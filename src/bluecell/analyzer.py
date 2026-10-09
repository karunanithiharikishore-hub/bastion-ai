# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Orchestrator — runs the full Blue-Team pipeline end to end, then hands the
result to the agent swarm.

Stages: ingest -> normalize -> ATT&CK map -> compress -> correlate -> intel RAG
-> RCA storyline -> IOC + threat-hunt checklist -> agent swarm (tiered SOC +
specialists that verify and reconcile).
"""
from __future__ import annotations

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
from .agents import injection
from . import provenance


_VERDICT_RANK = {"likely-malicious": 0, "needs-review": 1, "likely-benign": 2}


def analyze(paths, *, source_override=None, window_minutes=60,
            max_incidents=10, backbone=None, intel_store=None,
            max_digest_lines=400, run_agents=True, use_llm=True):
    """Run the pipeline (and, by default, the agent swarm). Returns a result dict."""
    import time
    _t0 = time.perf_counter()
    events = ingest_paths(paths, source_override)
    ingested = len(events)

    events = normalize(events)
    map_attack(events)
    # Log text that tries to instruct the AI analyst is itself a signal: tag it
    # (T1562, severity >= high) before scoring and correlation.
    injection.tag_events(events)

    digest = compress(events, max_lines=max_digest_lines)
    incidents = correlate(events, window_minutes=window_minutes)[:max_incidents]

    if intel_store is None:
        try:
            intel_store = IntelStore()
        except Exception:
            intel_store = None
    intel_used = intel_store.context_for(incidents) if intel_store else []

    iocs = extract_iocs(events)
    checklist = hunt_checklist(incidents, iocs)

    incident_blocks = []
    for inc in incidents:
        # Per-incident digest keeps the LLM focused and token-lean.
        inc_digest = compress(inc.events, max_lines=200)
        inc_intel = intel_store.context_for([inc]) if intel_store else []
        story = build_storyline(inc, digest=inc_digest, intel=inc_intel,
                                backbone=backbone)
        incident_blocks.append({
            "id": inc.id,
            "score": inc.score(),
            "verdict": assess_incident(inc),
            "storyline": story,
            "events": [e.to_dict() for e in inc.events],
        })

    _t_story = time.perf_counter()
    story_ms = int((_t_story - _t0) * 1000)

    swarm = None
    _t_swarm0 = time.perf_counter()
    if run_agents:
        swarm = run_swarm(events, incidents, iocs, digest,
                          intel_store=intel_store, backbone=backbone,
                          use_llm=use_llm)
    swarm_ms = int((time.perf_counter() - _t_swarm0) * 1000)

    # The headline follows the Tier-2 agent's confirm/dismiss decision when there
    # is one. Rule-only Tier-2 verdicts are a cruder heuristic than the scorer,
    # so without a model agent the scorer's verdict stands.
    tier2 = {}
    if swarm:
        tier2 = {f["incident_id"]: f for f in swarm["findings"]
                 if f["tier"] == 2 and f.get("origin") == "agent"}
        for block in incident_blocks:
            if block["id"] in tier2:
                inj = [e["event_id"] for e in block["events"]
                       if injection.INJECTION_TAG in (e.get("tags") or [])]
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
    ai_analysis = None
    if run_agents and use_llm and backbone is not None:
        try:
            ai_analysis = ai_analyze(events, iocs, backbone, want_review=True,
                                     tier2_verdicts=list(tier2.values()))
        except Exception as exc:  # never break the deterministic result
            ai_analysis = {"available": False, "reason": f"{type(exc).__name__}: {exc}"}

    total_ms = int((time.perf_counter() - _t0) * 1000)

    return {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "events_ingested": ingested,
            "events_normalized": len(events),
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
            "agents_deployed": (swarm["agent_count"] if swarm else 0),
        },
        "incidents": incident_blocks,
        "iocs": iocs,
        "hunt_checklist": checklist,
        "intel_used": intel_used,
        "swarm": swarm,
        "ai_analysis": ai_analysis,
        "prompt_injection": injection.summarize(events),
    }
