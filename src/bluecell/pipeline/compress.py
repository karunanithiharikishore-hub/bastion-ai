# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Token-efficient compression for the LLM stage.

Raw logs are never sent to the model. Instead we:
1. Collapse repeated identical events into counts (e.g. 500 failed logins ->
   one line "x500").
2. Emit each event as a single compact line (Event.compact()).
3. Prefer events that carry ATT&CK tags or high severity when a budget cap is
   set, so the most decision-relevant signal survives truncation.

Returns a string designed to be dropped straight into a prompt.
"""
from __future__ import annotations

from collections import OrderedDict


def _dedup_with_counts(events: list) -> list:
    """Collapse consecutive/again-seen identical compact lines into (line, n)."""
    counts: "OrderedDict[str, int]" = OrderedDict()
    representative: dict = {}
    for ev in events:
        # Signature ignores the exact timestamp so bursts collapse, but keeps
        # the first occurrence's line (with its time) as representative. It
        # covers every field compact() prints, so a collapsed line never hides
        # a different IP/process/hash behind the representative's value.
        sig = (f"{ev.source}|{ev.action}|{ev.host}|{ev.user}|{ev.src_ip}|{ev.src_port}|{ev.dst_ip}|{ev.dst_port}|"
               f"{ev.domain}|{ev.process}|{ev.file_hash}|{','.join(ev.attack)}")
        counts[sig] = counts.get(sig, 0) + 1
        representative.setdefault(sig, ev)
    out = []
    for sig, n in counts.items():
        out.append((representative[sig], n))
    return out


def compress(events: list, max_lines: int = 400) -> str:
    """Produce a compact, deduplicated event digest for the LLM."""
    if not events:
        return "(no events)"

    collapsed = _dedup_with_counts(sorted(events, key=lambda e: e.ts))
    total_sigs = len(collapsed)

    # If over budget, keep the most relevant lines: ATT&CK-tagged and high
    # severity first, but preserve chronological order in the output.
    if len(collapsed) > max_lines:
        scored = sorted(
            collapsed,
            key=lambda pair: (bool(pair[0].attack), pair[0].severity, pair[1]),
            reverse=True,
        )[:max_lines]
        keep_ids = {id(p[0]) for p in scored}
        collapsed = [p for p in collapsed if id(p[0]) in keep_ids]

    lines = []
    for ev, n in collapsed:
        line = ev.compact()
        if n > 1:
            line += f"  x{n}"
        lines.append(line)

    header = f"# {len(events)} raw events -> {total_sigs} distinct signatures"
    if total_sigs > len(lines):
        header += f", {total_sigs - len(lines)} omitted (budget)"
    header += "\n"
    return header + "\n".join(lines)


def token_estimate(text: str) -> int:
    """Rough token estimate (~4 chars/token) for cost visibility."""
    return max(1, len(text) // 4)