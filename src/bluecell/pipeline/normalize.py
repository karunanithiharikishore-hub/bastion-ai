"""Normalize a raw Event list: dedup and chronological sort."""
from __future__ import annotations


def normalize(events: list) -> list:
    """Deduplicate by stable event_id and sort ascending by timestamp."""
    seen = set()
    unique = []
    for ev in events:
        eid = ev.event_id
        if eid in seen:
            continue
        seen.add(eid)
        unique.append(ev)
    unique.sort(key=lambda e: e.ts)
    return unique
