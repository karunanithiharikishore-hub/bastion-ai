"""Orchestrator — runs the full Blue-Team pipeline end to end.

This is the "coordinator agent" that sequences the specialist stages:
ingest -> normalize -> ATT&CK map -> compress -> correlate -> intel RAG ->
RCA storyline -> IOC + threat-hunt checklist.
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


def analyze(paths, *, source_override=None, window_minutes=60,
            max_incidents=10, backbone=None, intel_store=None,
            max_digest_lines=400):
    """Run the pipeline and return a structured result dict."""
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

    return {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "events_ingested": ingested,
            "events_normalized": len(events),
            "sources": sorted({e.source for e in events}),
            "backbone": (backbone.resolved if backbone else "none (deterministic)"),
            "digest_tokens": token_estimate(digest),
            "window_minutes": window_minutes,
        },
        "incidents": incident_blocks,
        "iocs": iocs,
        "hunt_checklist": checklist,
        "intel_used": intel_used,
    }
