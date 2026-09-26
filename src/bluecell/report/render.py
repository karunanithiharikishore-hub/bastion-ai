"""Render analysis results to Markdown or JSON."""
from __future__ import annotations

import json


def render_json(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


def _sev_badge(label: str) -> str:
    return {"critical": "🔴 CRITICAL", "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM", "low": "🟢 LOW"}.get(label, label.upper())


def render_markdown(result: dict) -> str:
    meta = result["meta"]
    lines = [
        "# BlueCell — Incident Analysis Report",
        "",
        f"- Generated: {meta['generated']}",
        f"- Events ingested: **{meta['events_ingested']}** "
        f"(distinct after normalize: {meta['events_normalized']})",
        f"- Sources: {', '.join(meta['sources']) or 'n/a'}",
        f"- Incidents found: **{len(result['incidents'])}**",
        f"- LLM backbone: {meta['backbone']}  |  digest ≈ {meta['digest_tokens']} tokens",
        "",
    ]

    if not result["incidents"]:
        lines.append("_No correlated incidents crossed the reporting threshold._")
        return "\n".join(lines)

    lines.append("## Incidents (highest risk first)\n")
    for i, inc in enumerate(result["incidents"], 1):
        s = inc["storyline"]["structured"]
        lines += [
            f"### {i}. {s['incident_id']} — {_sev_badge(s['severity'])} "
            f"(score {s['score']}/100)",
            "",
            f"- Window: {s['window']['start']} → {s['window']['end']}",
            f"- Hosts: {', '.join(s['affected_hosts']) or 'n/a'}",
            f"- Users: {', '.join(s['affected_users']) or 'n/a'}",
            f"- Sources: {', '.join(s['sources_involved'])}",
            f"- Likely objective: **{s['likely_objective']}**",
            "",
            "**RCA / Storyline** "
            f"_(source: {inc['storyline']['narrative_source']})_",
            "",
            inc["storyline"]["narrative"],
            "",
            "**ATT&CK phases:**",
        ]
        for p in s["phases"]:
            techs = ", ".join(f"`{t['id']}` {t['name']}" for t in p["techniques"])
            lines.append(f"- {p['tactic']}: {techs}")
        lines.append("")

    # IOCs
    lines.append("## Indicators of Compromise (IOCs)\n")
    iocs = result["iocs"]
    for kind in ("hash", "domain", "ip", "process", "user"):
        items = [x for x in iocs.get(kind, []) if x["suspicious"]] or iocs.get(kind, [])[:5]
        if not items:
            continue
        lines.append(f"**{kind.upper()}**")
        for x in items[:15]:
            flag = " ⚠️" if x["suspicious"] else ""
            hosts = f" — hosts: {', '.join(x['hosts'])}" if x["hosts"] else ""
            lines.append(f"- `{x['value']}` (x{x['count']}){flag}{hosts}")
        lines.append("")

    # Threat-hunt checklist
    lines.append("## Threat-Hunt Checklist (prioritized)\n")
    for c in result["hunt_checklist"]:
        lines.append(f"- [{c['priority'].upper()}] **{c['action']}**")
        if c.get("targets"):
            lines.append(f"    - targets: {', '.join(str(t) for t in c['targets'][:20])}")
        lines.append(f"    - why: {c['why']}")
    lines.append("")

    # Threat intel used
    if result.get("intel_used"):
        lines.append("## Threat Intel Referenced\n")
        for e in result["intel_used"]:
            lines.append(f"- {e.get('id')}: {e.get('title')} (sev {e.get('severity','?')}, src {e.get('source','?')})")
        lines.append("")

    lines.append("---")
    lines.append("_BlueCell is a read-only analysis aid. Validate all findings "
                 "before acting. IOCs and RCA are hypotheses, not proof._")
    return "\n".join(lines)
