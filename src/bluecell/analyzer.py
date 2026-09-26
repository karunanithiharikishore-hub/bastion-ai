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
from .report.rca import build_storyline
from .intel import IntelStore
from .agents import run_swarm
from . import provenance


def analyze(paths, *, source_override=None, window_minutes=60,
            max_incidents=10, backbone=None, intel_store=None,
            max_digest_lines=400, run_agents=True, use_llm=True):
    """Run the pipeline (and, by default, the agent swarm). Returns a result dict."""
    events = ingest_paths(paths, source_override)
    ingested = len(events)

    events = normalize(events)
    map_attack(events)

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
            "storyline": story,
            "events": [e.to_dict() for e in inc.events],
        })

    swarm = None
    if run_agents:
        swarm = run_swarm(events, incidents, iocs, digest,
                          intel_store=intel_store, backbone=backbone,
                          use_llm=use_llm)

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
        },
        "incidents": incident_blocks,
        "iocs": iocs,
        "hunt_checklist": checklist,
        "intel_used": intel_used,
        "swarm": swarm,
    }
