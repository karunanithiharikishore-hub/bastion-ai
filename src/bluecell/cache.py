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
  detector) and the tool schemas (separate hashes), plus a hash of all package
  source code so a code change never serves a stale result,
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
import sys
import tempfile
import time
from datetime import datetime, timezone

CACHE_ENV = "BLUECELL_CACHE_DIR"
KEEP_ENV = "BLUECELL_CACHE_KEEP"   # newest entries kept after each store
KEEP_DEFAULT = 200
TMP_MAX_AGE_S = 300                # interrupted stores leave *.tmp behind
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
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
        d = e.to_dict()
        if "ts-unparsed" in e.tags:   # ts is a now() guess; keep it out, as event_id does
            d.pop("ts", None)
        h.update(json.dumps(d, sort_keys=True, default=str).encode("utf-8"))
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
    # Every package source file: any module can shape a result (pipeline, intel,
    # ingest, models...), and a missed one would serve stale output.
    h = hashlib.sha256()
    rels = sorted(os.path.relpath(os.path.join(d, f), _PKG_DIR)
                  for d, _, fs in os.walk(_PKG_DIR) for f in fs if f.endswith(".py"))
    for rel in rels:
        h.update(rel.encode())
        with open(os.path.join(_PKG_DIR, rel), "rb") as fh:
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
    """The stored entry for ``key``, or None (missing, unreadable or malformed)."""
    try:
        with open(_path(key), encoding="utf-8") as fh:
            entry = json.load(fh)
    except (OSError, ValueError):
        return None
    ok = isinstance(entry, dict) and isinstance(entry.get("result"), dict)
    return entry if ok else None


def invalidate(key: str) -> bool:
    """Delete the stored entry for ``key``; True if one was removed. Never raises."""
    try:
        os.unlink(_path(key))
        return True
    except OSError:
        return False


def _prune(keep_path: str) -> None:
    """Bound the cache after a store: drop entries from other code, keep the
    newest KEEP_ENV entries, sweep stale temp files. Never raises; never
    removes ``keep_path`` (the entry just written)."""
    try:
        keep = max(1, int(os.environ.get(KEEP_ENV) or KEEP_DEFAULT))
    except ValueError:
        keep = KEEP_DEFAULT
    try:
        d = cache_dir()
        now = time.time()
        current = code_fingerprint()
        entries = []
        for name in os.listdir(d):
            path = os.path.join(d, name)
            try:
                if name.endswith(".tmp"):
                    if now - os.path.getmtime(path) > TMP_MAX_AGE_S:
                        os.unlink(path)
                elif name.endswith(".json") and path != keep_path:
                    with open(path, encoding="utf-8") as fh:
                        code = (json.load(fh).get("material") or {}).get("code")
                    if code is not None and code != current:   # orphaned by a code change
                        os.unlink(path)
                    else:
                        entries.append((os.path.getmtime(path), path))
                elif name.endswith(".json"):
                    entries.append((os.path.getmtime(path), path))
            except (OSError, ValueError, AttributeError):
                continue        # a file that vanished or is unreadable is not worth failing for
        entries.sort(reverse=True)
        for _, path in entries[keep:]:
            if path != keep_path:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    except Exception as exc:    # pruning is housekeeping; it must never break an analysis
        print(f"bluecell: run cache prune skipped ({exc})", file=sys.stderr)


def store(key: str, material: dict, result: dict, origin_run_id: str | None = None) -> str | None:
    """Store a finished result. Never raises: a failed write must not lose the analysis.

    On failure the reason is recorded in ``result["meta"]["cache_error"]`` and
    returned as None.
    """
    entry = {"key": key, "material": material,
             "stored_at": datetime.now(timezone.utc).isoformat(),
             "origin_run_id": origin_run_id,   # trace of the run that produced it
             "result": result}
    try:
        data = json.dumps(entry, default=str)
        os.makedirs(cache_dir(), exist_ok=True)
        path = _path(key)
        # mkstemp gives a unique name per call, so concurrent stores of one key
        # (threads or processes) never share a temp file.
        fd, tmp = tempfile.mkstemp(dir=cache_dir(), prefix=f"{key}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        _prune(path)
        return path
    except (OSError, TypeError, ValueError) as exc:
        print(f"bluecell: run cache not stored ({exc})", file=sys.stderr)
        result.setdefault("meta", {})
        if isinstance(result["meta"], dict):
            result["meta"]["cache_error"] = str(exc)
        return None


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
    gap = None   # reported last, so a clear error or fallback is named first
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
        note = str(r.get("note") or "")   # set by Tier-2 verify(): incidents left without a verdict
        if gap is None and ("no verdict" in note or "no agent verdict" in note):
            gap = f"agent {name} filed no verdict for some incidents"
    ai = result.get("ai_analysis")
    if ai is not None and not ai.get("available"):
        return "AI analyst call failed"
    if ai and isinstance(ai.get("review"), dict) and ai["review"].get("error"):
        return "AI reviewer call failed"
    if ai and ai.get("final_verdict") is None:
        return "AI analyst gave no usable verdict"
    if ai:   # a part that was not valid JSON is kept as {"raw": text}; not a usable answer
        for part in ("lead", "review"):
            if isinstance(ai.get(part), dict) and "raw" in ai[part]:
                return f"AI analyst {part} was not valid JSON"
    for block in result.get("incidents") or []:
        if (block.get("storyline") or {}).get("narrative_source") != "llm":
            return f"LLM narrative for {block.get('id')} failed"
    return gap


def mark_hit(entry: dict, key: str, elapsed_ms: int) -> dict:
    result = entry["result"]
    meta = result.get("meta")
    if not isinstance(meta, dict):   # a malformed entry must not crash the run
        meta = result["meta"] = {}
    meta["cache"] = "hit"
    meta["cache_key"] = key
    meta["cached_at"] = entry.get("stored_at")
    meta["original_generated"] = meta.get("generated")
    meta["original_timing_ms"] = meta.get("timing_ms")
    meta["original_run_id"] = entry.get("origin_run_id")   # `bluecell runs show <id>`
    meta["timing_ms"] = {"storyline": 0, "swarm": 0, "total": elapsed_ms}
    return result
