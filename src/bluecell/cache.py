# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Run cache: same logs + same configuration -> the same result, instantly.

LLM output is not bit-identical across runs (the ``claude`` CLI has no
temperature/seed option, and even temperature 0 on the API is not a
determinism guarantee). The cache makes a *reviewed* result reproducible: the
first complete run is stored, and any later run over the same normalized
events with the same model, BlueCell version, prompts, tool schemas and
orchestration settings returns that stored result, marked
``meta.cache = "hit"``.

Key = sha256 over:
- every normalized event (its event_id and full normalized content),
- model, Tier-1 model, backbone path (cli/api) and sampling temperature,
- BlueCell version,
- the prompt/mission texts (including the prompt-injection boundary text and
  detector) and the tool schemas (separate hashes), plus a hash of the
  LLM-path source code so a code change never serves a stale result,
- the threat-intel store contents (agents and the narrative read it),
- orchestration settings (window, incident cap, votes, Tier-1 model,
  orchestration mode and the commander's agent/turn/time limits, budgets, ...).

Never stored: runs where an agent errored or fell back to rules, a run that
hit its turn budget, a failed analyst call or LLM narrative, an Incident
Commander run that errored or fell back to the fixed flow, and runs without
an LLM (those are already deterministic and fast, so caching them would only
add a way to serve stale output).

Location: ``$BLUECELL_CACHE_DIR`` or ``~/.bluecell/cache/<key>.json``.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from datetime import datetime, timezone

CACHE_ENV = "BLUECELL_CACHE_DIR"
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
# Source files whose code shapes an LLM-backed result.
_LLM_PATH_SOURCES = ("agents", "llm", os.path.join("report", "rca.py"), "analyzer.py")

MODES = ("use", "refresh", "off")


def cache_dir() -> str:
    return os.environ.get(CACHE_ENV) or os.path.join(
        os.path.expanduser("~"), ".bluecell", "cache")


def _sha(obj) -> str:
    data = obj if isinstance(obj, bytes) else json.dumps(
        obj, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------
def events_fingerprint(events) -> str:
    h = hashlib.sha256()
    for e in events:
        h.update(json.dumps(e.to_dict(), sort_keys=True, default=str).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def prompt_texts() -> dict:
    """Every system prompt / mission / prompt template a model sees."""
    from .agents import runtime, analyst, roles, injection, toolbox, commander, dispatch
    from .report import rca
    texts = {
        # Incident Commander: its protocol, the worker roles it is offered and
        # its dispatch tool schemas.
        "commander_protocol": commander.COMMANDER_PROTOCOL,
        "commander_roles": {k: d for k, (_, d) in commander.WORKER_ROLES.items()},
        "commander_tools": dispatch.COMMAND_TOOL_SPECS,
        "investigator": commander.Investigator.mission,
        # Prompt-injection defenses: the boundary instruction every prompt
        # carries, the tool-output warning, and the detector itself (its
        # patterns decide which events are flagged and how verdicts are guarded).
        "injection_boundary": injection.BOUNDARY_INSTRUCTION,
        "injection_warning": toolbox.INJECTION_WARNING,
        "injection_detector": _source_of(injection),
        "operating_protocol": runtime.OPERATING_PROTOCOL,
        "task_prompt": runtime.task_prompt("{agent}", "{role}"),
        "tier1": roles.JuniorSocAnalyst.mission,
        "tier2": roles.SeniorSocAnalyst.mission,
        "analyst_system": analyst._SYSTEM,
        "analyst_lead": analyst._LEAD_PROMPT,
        "analyst_review": analyst._REVIEW_PROMPT,
        "analyst_tier2": analyst._TIER2_HEADER,
    }
    try:
        texts["narrative"] = inspect.getsource(rca._llm_narrative)
    except (OSError, TypeError):   # no source available (e.g. zipped install)
        texts["narrative"] = repr(rca._llm_narrative.__code__.co_consts)
    for cls in roles.SPECIALISTS:
        texts["tier3:" + cls.role] = cls.mission
    return texts


def _source_of(obj) -> str:
    try:
        return inspect.getsource(obj)
    except (OSError, TypeError):   # no source available (e.g. zipped install)
        return repr(obj)


def prompt_fingerprint() -> str:
    return _sha(prompt_texts())


def tool_schema_fingerprint() -> str:
    from .agents.toolbox import TOOL_SPECS
    return _sha(TOOL_SPECS)


def code_fingerprint() -> str:
    h = hashlib.sha256()
    for rel in _LLM_PATH_SOURCES:
        path = os.path.join(_PKG_DIR, rel)
        files = ([path] if os.path.isfile(path) else
                 sorted(os.path.join(d, f) for d, _, fs in os.walk(path)
                        for f in fs if f.endswith(".py")))
        for f in files:
            h.update(os.path.relpath(f, _PKG_DIR).encode())
            with open(f, "rb") as fh:
                h.update(hashlib.sha256(fh.read()).digest())
    return h.hexdigest()


def intel_fingerprint(store) -> str:
    if store is None:
        return "none"
    return _sha(getattr(store, "entries", []))


def key_material(events, *, backbone, intel_store=None, settings: dict | None = None) -> dict:
    from . import __version__
    return {
        "events": events_fingerprint(events),
        "event_count": len(events),
        "model": getattr(backbone, "model", None),
        "backbone": getattr(backbone, "resolved", None),
        "temperature": getattr(backbone, "temperature", None),
        "bluecell_version": __version__,
        "prompts": prompt_fingerprint(),
        "tool_schemas": tool_schema_fingerprint(),
        "code": code_fingerprint(),
        "intel": intel_fingerprint(intel_store),
        "settings": dict(settings or {}),
    }


def cache_key(material: dict) -> str:
    return _sha(material)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def _path(key: str) -> str:
    return os.path.join(cache_dir(), f"{key}.json")


def load(key: str):
    """The stored entry for ``key``, or None (missing or unreadable)."""
    try:
        with open(_path(key), encoding="utf-8") as fh:
            entry = json.load(fh)
    except (OSError, ValueError):
        return None
    return entry if isinstance(entry, dict) and "result" in entry else None


def store(key: str, material: dict, result: dict, origin_run_id: str | None = None) -> str:
    os.makedirs(cache_dir(), exist_ok=True)
    path = _path(key)
    tmp = f"{path}.{os.getpid()}.tmp"
    entry = {"key": key, "material": material,
             "stored_at": datetime.now(timezone.utc).isoformat(),
             "origin_run_id": origin_run_id,   # trace of the run that produced it
             "result": result}
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(entry, fh, default=str)
    os.replace(tmp, path)
    return path


def uncacheable_reason(result: dict, backbone) -> str | None:
    """Why this result must not be cached, or None if it may be."""
    if backbone is None:
        return "no LLM (deterministic run)"
    swarm = result.get("swarm") or {}
    cmd = swarm.get("commander") or {}
    if cmd.get("fallback_reason"):
        # Not a run of the requested orchestration (and the commander's wasted
        # work is not in agent_runs, so the checks below would not see it).
        return f"Incident Commander fell back to the fixed flow ({cmd['fallback_reason']})"
    if cmd.get("error"):
        return f"Incident Commander errored ({cmd['error']})"
    for r in swarm.get("agent_runs") or []:
        if r.get("dispatch_warning"):
            return f"agent {r.get('agent')}: {r['dispatch_warning']}"
        name = r.get("agent")
        if r.get("error"):
            return f"agent {name} errored"
        if str(r.get("mode", "")).startswith("fallback"):
            return f"agent {name} fell back to rules"
        if r.get("truncated"):
            return f"agent {name} hit its turn budget"
    ai = result.get("ai_analysis")
    if ai is not None and not ai.get("available"):
        return "AI analyst call failed"
    if ai and isinstance(ai.get("review"), dict) and ai["review"].get("error"):
        return "AI reviewer call failed"
    for block in result.get("incidents") or []:
        if (block.get("storyline") or {}).get("narrative_source") != "llm":
            return f"LLM narrative for {block.get('id')} failed"
    return None


def mark_hit(entry: dict, key: str, elapsed_ms: int) -> dict:
    result = entry["result"]
    meta = result.setdefault("meta", {})
    meta["cache"] = "hit"
    meta["cache_key"] = key
    meta["cached_at"] = entry.get("stored_at")
    meta["original_generated"] = meta.get("generated")
    meta["original_timing_ms"] = meta.get("timing_ms")
    meta["original_run_id"] = entry.get("origin_run_id")   # `bluecell runs show <id>`
    meta["timing_ms"] = {"storyline": 0, "swarm": 0, "total": elapsed_ms}
    return result
