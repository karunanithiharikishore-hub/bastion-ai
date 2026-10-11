# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Orchestrator — runs the full Blue-Team pipeline end to end, then hands the
result to the agent swarm.

Stages: ingest -> normalize -> ATT&CK map -> compress -> correlate -> intel RAG
-> RCA storyline -> IOC + threat-hunt checklist -> agent swarm (tiered SOC +
specialists that verify and reconcile).
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from .ingest import ingest_paths
from .pipeline import (
    normalize, compress, map_attack, correlate, extract_iocs,
)
from .pipeline.compress import token_estimate
from .pipeline.ioc import hunt_checklist
from .report.rca import (
    build_storyline, assess_incident, apply_tier2_verdict, reframe_benign,
)
from .intel import IntelStore
from .agents import run_swarm, ai_analyze
from .agents import budget, commander
from .agents.orchestrator import ORCHESTRATIONS
from .agents import injection
from . import provenance
from . import cache as run_cache
from . import tracing


_VERDICT_RANK = {"likely-malicious": 0, "needs-review": 1, "likely-benign": 2}


def analyze(paths, *, trace=None, **kwargs):
    """Run the pipeline (and, by default, the agent swarm). Returns a result dict.

    Every run is traced (spans, LLM usage, cost) into ``result["meta"]["trace"]``.
    ``trace=False`` skips persisting it under the runs dir (see tracing.py);
    tracing failures never affect the analysis. Other keyword arguments are
    those of ``_analyze``.
    """
    backbone = kwargs.get("backbone")
    tracer = tracing.start_run(
        paths, persist=trace,
        backbone=(backbone.resolved if backbone else "none"),
        model=getattr(backbone, "model", None),
        mode=kwargs.get("mode", "deep"),
        use_llm=kwargs.get("use_llm", True), run_agents=kwargs.get("run_agents", True),
        orchestration=kwargs.get("orchestration", "auto"))
    try:
        result = _analyze(paths, **kwargs)
    except BaseException as exc:
        tracing.end_run(tracer, error=f"{type(exc).__name__}: {exc}")
        raise
    tracing.end_run(tracer, result)
    return result


def _safe_ai(events, iocs, backbone, tier2_verdicts):
    try:
        return ai_analyze(events, iocs, backbone, want_review=True, tier2_verdicts=tier2_verdicts)
    except Exception as exc:  # never break the deterministic result
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}


def _analyst_finding(ai):
    """Tier-2-shaped finding from a grounded AI-analyst verdict, or None (needs-review,
    unavailable or ungrounded: the rule verdict stands)."""
    if not ai or not ai.get("available"):
        return None
    final, lead, review = ai.get("final_verdict"), ai.get("lead") or {}, ai.get("review") or {}
    if final not in ("likely-malicious", "likely-benign") or not (lead.get("_grounding") or {}).get("ok"):
        return None
    if review and not (review.get("_grounding") or {}).get("ok", True):
        return None
    try:
        conf = float(review.get("confidence", lead.get("confidence")))
    except (TypeError, ValueError):
        return None   # no real confidence: the rule verdict stands
    # The rationale comes from whichever agent produced the final verdict.
    pick = (review.get("notes") or lead.get("headline")) if review.get("corrected_verdict") \
        else (lead.get("headline") or review.get("notes"))
    rationale = str(pick or "").strip()
    if not math.isfinite(conf) or not rationale:
        return None
    return {"status": "escalated" if final == "likely-malicious" else "dismissed",
            "confidence": min(max(conf, 0.0), 1.0), "rationale": rationale}


def _analyze(paths, *, source_override=None, window_minutes=60,
             max_incidents=10, backbone=None, intel_store=None,
             max_digest_lines=400, run_agents=True, use_llm=True,
             cache=None, votes=1, tier1_model=None, skip_idle_tier1=True,
             orchestration="auto", max_agents=None, max_commander_turns=None,
             budget_seconds=None, mode="deep"):
    """mode: "deep" (commander + agent swarm + analyst) or "quick" (rules pipeline +
    one AI analyst pass whose grounded verdict sets the incident verdict; no swarm).
    cache: None/"off" (no cache), "use" (return a stored result for the same
    inputs + config, store complete new runs) or "refresh" (always run, then
    overwrite). Only LLM runs are cached; see cache.py.
    votes: Tier-2 self-consistency runs (majority vote per incident); with the
    Incident Commander it applies to every tier2-verifier it deploys.
    tier1_model: model for Tier-1 triage agents (None = the backbone's model).
    skip_idle_tier1: no Tier-1 model agent for sources with no incident events
    (fixed flow; the commander chooses its own Tier-1 deploys).
    orchestration: "auto" (Incident Commander when a model backbone is
    available, else fixed), "commander" or "fixed". max_agents /
    max_commander_turns / budget_seconds: the commander's guardrails (None =
    the defaults in agents/commander.py).
    """
    # Validate at the API boundary (the CLI already does this for its flags).
    if max_incidents < 1:
        raise ValueError(f"max_incidents must be >= 1, got {max_incidents!r}")
    for name, val in (("votes", votes), ("max_agents", max_agents),
                      ("max_commander_turns", max_commander_turns)):
        if val is not None and val < 1:
            raise ValueError(f"{name} must be >= 1, got {val!r}")
    # A worker needs MIN_WORKER_SECONDS and the commander needs time to plan.
    if budget_seconds is not None and budget_seconds <= commander.MIN_WORKER_SECONDS:
        raise ValueError(f"budget_seconds must be > {commander.MIN_WORKER_SECONDS}, "
                         f"got {budget_seconds!r}")
    if mode not in ("quick", "deep"):
        raise ValueError(f"mode must be 'quick' or 'deep', got {mode!r}")
    quick = mode == "quick"
    import time
    _t0 = time.perf_counter()
    tracing.stage("ingest")
    events = ingest_paths(paths, source_override)
    ingested = len(events)

    tracing.stage("normalize+attack")
    events = normalize(events)
    map_attack(events)
    # Log text that tries to instruct the AI analyst is itself a signal: tag it
    # (T1562, severity >= high) before scoring and correlation.
    injection.tag_events(events)

    tracing.stage("compress+correlate")
    digest = compress(events, max_lines=max_digest_lines)
    incidents = correlate(events, window_minutes=window_minutes)
    incidents_total = len(incidents)
    incidents = incidents[:max_incidents]

    tracing.stage("intel+iocs")
    if intel_store is None:
        try:
            intel_store = IntelStore()
        except Exception:
            intel_store = None
    intel_used = intel_store.context_for(incidents) if intel_store else []

    iocs = extract_iocs(events)
    checklist = hunt_checklist(incidents, iocs)

    llm_on = use_llm and backbone is not None
    if orchestration not in ORCHESTRATIONS:
        raise ValueError(f"orchestration must be one of {ORCHESTRATIONS}, got {orchestration!r}")
    commander_limits = {
        "max_agents": commander.DEFAULT_MAX_AGENTS if max_agents is None else int(max_agents),
        "max_commander_turns": (commander.DEFAULT_COMMANDER_TURNS if max_commander_turns is None
                                else int(max_commander_turns)),
        "budget_seconds": (commander.DEFAULT_BUDGET_SECONDS if budget_seconds is None
                           else float(budget_seconds)),
    }
    # Everything that shapes the swarm goes into the run-cache key below.
    swarm_options = {"votes": 1 if votes is None else int(votes), "tier1_model": tier1_model,
                     "skip_idle_tier1": skip_idle_tier1, "orchestration": orchestration,
                     **commander_limits}
    cache_mode = cache if cache in run_cache.MODES else "off"
    cache_key = material = None
    cache_note = "n/a (deterministic run)" if not llm_on else cache_mode
    if llm_on and cache_mode != "off":
        material = run_cache.key_material(events, backbone=backbone, intel_store=intel_store,
                                          settings=dict(
            swarm_options, source_override=source_override, window_minutes=window_minutes,
            max_incidents=max_incidents, max_digest_lines=max_digest_lines,
            run_agents=run_agents, mode=mode, tier_max_turns=budget.TIER_MAX_TURNS,
            max_tool_result_chars=budget.MAX_TOOL_RESULT_CHARS))
        cache_key = run_cache.cache_key(material)
        if cache_mode == "use":
            entry = run_cache.load(cache_key)
            if entry is not None:
                return run_cache.mark_hit(entry, cache_key,
                                          int((time.perf_counter() - _t0) * 1000),
                                          run_meta={"events_ingested": ingested})

    tracing.stage("storyline", incidents=len(incidents))
    incident_blocks = []
    for inc in incidents:
        # Per-incident digest keeps the LLM focused and token-lean.
        inc_digest = compress(inc.events, max_lines=200)
        inc_intel = intel_store.context_for([inc]) if intel_store else []
        story = build_storyline(inc, digest=inc_digest, intel=inc_intel,
                                backbone=None if quick else backbone)
        incident_blocks.append({
            "id": inc.id,
            "score": inc.score(),
            "verdict": assess_incident(inc),
            "storyline": story,
            "events": [e.to_dict() for e in inc.events],
        })

    _t_story = time.perf_counter()
    story_ms = int((_t_story - _t0) * 1000)

    tracing.stage("swarm")
    swarm = None
    _t_swarm0 = time.perf_counter()
    if run_agents and not quick:
        swarm = run_swarm(events, incidents, iocs, digest,
                          intel_store=intel_store, backbone=backbone,
                          use_llm=use_llm, **swarm_options)
    swarm_ms = int((time.perf_counter() - _t_swarm0) * 1000)

    # The headline follows the Tier-2 agent's confirm/dismiss decision when there
    # is one. Rule-only Tier-2 verdicts are a cruder heuristic than the scorer,
    # so without a model agent the scorer's verdict stands.
    tier2 = {}
    ai_analysis = None
    if quick and llm_on and run_agents:   # one grounded AI pass; its verdict is applied below like a Tier-2 one
        tracing.stage("ai_analysis")
        ai_analysis = _safe_ai(events, iocs, backbone, [])
        ai_f = _analyst_finding(ai_analysis)
        if ai_f and incident_blocks:
            # shortcut: analyst sees the whole case but returns one verdict; applied to the top incident only — scope per incident if ai_analyze ever returns per-incident verdicts
            inj = [e.event_id for e in events if injection.is_flagged(e)]
            top = incident_blocks[0]
            top["verdict"] = apply_tier2_verdict(
                top["verdict"], dict(ai_f, incident_id=top["id"]),
                injection_events=inj, who="AI analyst", decided_by="ai-analyst")
            v = top["verdict"]
            if ai_f["status"] == "dismissed" and ai_f["confidence"] < 0.8 \
                    and v["rule_verdict"]["level"] == "likely-malicious":
                # a weak dismissal may not overrule a malicious rule verdict
                top["verdict"] = dict(v, level="needs-review", overrides_rules=True,
                                      headline="AI analyst leaned benign with low confidence; a human must review.")
    if swarm:
        tier2 = {f["incident_id"]: f for f in swarm["findings"]
                 if f["tier"] == 2 and f.get("origin") == "agent"}
        # A split Tier-2 vote leaves the rule verdict in place; show the tally.
        split = {f["incident_id"]: f["votes"] for f in swarm["findings"]
                 if f["tier"] == 2 and f.get("origin") != "agent"
                 and (f.get("votes") or {}).get("needs_review")}
        # Case-wide: an injection in any event steers the analyst, so a dismissal of any
        # incident in this case is downgraded (BUG-INJ-1).
        inj = [e.event_id for e in events if injection.is_flagged(e)]
        for block in incident_blocks:
            if block["id"] in split:
                block["verdict"] = dict(block["verdict"], votes=split[block["id"]])
            if block["id"] in tier2:
                block["verdict"] = apply_tier2_verdict(block["verdict"], tier2[block["id"]],
                                                       injection_events=inj)

    # Benign incidents get a summary that does not presume an attacker.
    by_id = {inc.id: inc for inc in incidents}
    for block in incident_blocks:
        if block["verdict"].get("level") == "likely-benign":
            reframe_benign(by_id[block["id"]], block["storyline"]["structured"])

    # Most serious verdict first, then score. The report headline, executive
    # summary and dashboard all describe incidents[0], so a dismissed high-score
    # incident must not hide an open one behind it.
    incident_blocks.sort(key=lambda b: (_VERDICT_RANK.get(b["verdict"].get("level"), 1),
                                        -b["score"]))

    # Model-driven AI analyst — genuine LLM reasoning over the evidence, grounded.
    # Opt-in: only runs when an LLM backbone is available (use_llm and backbone).
    if run_agents and not quick and use_llm and backbone is not None:
        tracing.stage("ai_analysis")
        ai_analysis = _safe_ai(events, iocs, backbone, list(tier2.values()))

    tracing.stage("finalize")
    total_ms = int((time.perf_counter() - _t0) * 1000)

    result = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "events_ingested": ingested,
            "events_normalized": len(events),
            "incidents_total": incidents_total,
            "sources": sorted({e.source for e in events}),
            "backbone": (backbone.resolved if backbone else "none (deterministic)"),
            "digest_tokens": token_estimate(digest),
            "window_minutes": window_minutes,
            "author": provenance.AUTHOR,
            "watermark": provenance.WATERMARK,
            "timing_ms": {
                "storyline": story_ms,
                "swarm": swarm_ms,
                "total": total_ms,
            },
            # worker_count excludes the commander (BUG-CMD-11); fixed flow has none.
            "agents_deployed": (swarm.get("worker_count", swarm["agent_count"]) if swarm else 0),
            "orchestration": (swarm.get("orchestration") if swarm else None),
            "repeatability": {
                "sampling": getattr(backbone, "sampling", None) if llm_on else "n/a (no LLM)",
                "votes": swarm_options["votes"],
                "tier1_model": tier1_model,
                "skip_idle_tier1": skip_idle_tier1,
            },
            "cost_plan": (budget.plan_swarm(events, incidents,
                                            votes=swarm_options["votes"],
                                            skip_idle_tier1=skip_idle_tier1,
                                            orchestration=(swarm or {}).get("orchestration"),
                                            commander_limits=commander_limits)
                          if run_agents and llm_on and not quick else
                          ({"mode": "quick", "tier1_agents": 0, "tier2_runs": 0, "tier3_agents": 0,
                            "agent_runs": 0, "processes": 2 if events else 0, "mcp_servers": 0,
                            "max_turns": 0} if run_agents and llm_on else None)),
            "cache": cache_note,
            "mode": mode,
        },
        "incidents": incident_blocks,
        "iocs": iocs,
        "hunt_checklist": checklist,
        "intel_used": intel_used,
        "swarm": swarm,
        "ai_analysis": ai_analysis,
        "prompt_injection": injection.summarize(events),
    }
    if cache_key is not None:
        result["meta"]["cache_key"] = cache_key
        reason = run_cache.uncacheable_reason(result, backbone)
        if reason is None:
            tr = tracing.current()
            if run_cache.store(cache_key, material, result,
                               origin_run_id=getattr(tr, "run_id", None),
                               origin_persisted=getattr(tr, "persist", True)) is None:
                reason = result["meta"].get("cache_error")   # store() recorded it there
            else:
                result["meta"]["cache"] = "refreshed" if cache_mode == "refresh" else "miss (stored)"
        if reason is not None:
            note = f"miss (not stored: {reason}"
            # A refresh that cannot store must not leave the old entry to be served next time (BUG-FEAT-13).
            if cache_mode == "refresh" and run_cache.invalidate(cache_key):
                note += "; stale entry removed"
            result["meta"]["cache"] = note + ")"
    return result
