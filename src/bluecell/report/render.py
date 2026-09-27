# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Render analysis results to Markdown or JSON."""
from __future__ import annotations

import json

from .. import provenance


def render_json(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


def _sev_badge(label: str) -> str:
    return {"critical": "🔴 CRITICAL", "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM", "low": "🟢 LOW"}.get(label, label.upper())


def _verdict_badge(level: str) -> str:
    return {
        "likely-malicious": "🔴 LIKELY REAL ATTACK",
        "likely-benign": "🟢 LIKELY BENIGN / NOISE",
        "needs-review": "🟡 NEEDS REVIEW",
    }.get(level, (level or "unknown").upper())


def render_markdown(result: dict) -> str:
    meta = result["meta"]
    lines = [
        "# BlueCell — Incident Analysis Report",
        "",
        f"> Built by **{meta.get('author', provenance.AUTHOR)}** · "
        f"{provenance.COPYRIGHT}",
        "",
        f"- Generated: {meta['generated']}",
        f"- Events ingested: **{meta['events_ingested']}** "
        f"(distinct after normalize: {meta['events_normalized']})",
        f"- Sources: {', '.join(meta['sources']) or 'n/a'}",
        f"- Incidents found: **{len(result['incidents'])}**",
        f"- LLM backbone: {meta['backbone']}  |  digest ≈ {meta['digest_tokens']} tokens",
        "",
    ]

    # Agent swarm summary (if the swarm ran).
    swarm = result.get("swarm")
    if swarm:
        c = swarm["counts"]
        lines += [
            f"- Agent swarm: **{swarm['agent_count']} agents** "
            f"(T1:{c['tier1_findings']} findings, T2:{c['tier2_findings']} verifications, "
            f"T3:{c['tier3_findings']} specialist findings, "
            f"{c['confirmed_incidents']} confirmed)",
            "",
        ]

    if not result["incidents"]:
        lines.append("_No correlated incidents crossed the reporting threshold._")
        if swarm:
            lines += ["", _render_swarm(swarm)]
        lines += ["", "---", _footer()]
        return "\n".join(lines)

    # ---- Executive summary (IR-report style) --------------------------------
    top = result["incidents"][0]
    tv = top.get("verdict") or {}
    ts = top["storyline"]["structured"]
    asum = ts.get("attack_summary") or {}
    lines += [
        "## Executive Summary",
        "",
        f"**Overall verdict:** {_verdict_badge(tv.get('level'))} "
        f"(confidence {round(tv.get('confidence', 0) * 100)}%) — {tv.get('headline', '')}",
        "",
        f"**How they got in:** {asum.get('how_they_got_in', 'n/a')}",
        "",
        f"**Objective:** {asum.get('objective', ts.get('likely_objective', 'unknown'))}",
        "",
        "**What they did:**",
    ]
    for step in asum.get("what_they_did", []):
        lines.append(f"- {step}")
    if not asum.get("what_they_did"):
        lines.append("- No discrete actions reconstructed.")
    lines += [
        "",
        f"**Scope:** hosts: {', '.join(ts.get('affected_hosts') or []) or 'n/a'} · "
        f"users: {', '.join(ts.get('affected_users') or []) or 'n/a'} · "
        f"window: {ts['window']['start']} → {ts['window']['end']}",
        "",
    ]

    lines.append("## Incidents (highest risk first)\n")
    for i, inc in enumerate(result["incidents"], 1):
        s = inc["storyline"]["structured"]
        lines += [
            f"### {i}. {s['incident_id']} — {_sev_badge(s['severity'])} "
            f"(score {s['score']}/100)",
            "",
        ]
        # Analyst verdict — the real-vs-noise call, up top where it matters.
        v = inc.get("verdict")
        if v:
            lines += [
                f"> **VERDICT: {_verdict_badge(v['level'])}** "
                f"(confidence {round(v.get('confidence', 0) * 100)}%)  ",
                f"> {v['headline']}  ",
                f"> {v['why']}",
                "",
                "**What to do next:**",
            ]
            for chk in v.get("recommended_checks", []):
                lines.append(f"- [ ] {chk}")
            lines.append("")
        lines += [
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

    # Agent swarm detail.
    if swarm:
        lines.append(_render_swarm(swarm))

    lines.append("---")
    lines.append("_BlueCell is a read-only analysis aid. Validate all findings "
                 "before acting. IOCs and RCA are hypotheses, not proof._")
    lines.append(_footer())
    return "\n".join(lines)


def _footer() -> str:
    return (f"\n<!-- {provenance.WATERMARK} -->\n"
            f"_BlueCell — built by {provenance.AUTHOR}. "
            f"{provenance.COPYRIGHT}_")


def _render_swarm(swarm: dict) -> str:
    out = ["## Agent Swarm — findings & consensus\n"]
    out.append(f"**Roster ({swarm['agent_count']} agents):**")
    for a in swarm["roster"]:
        out.append(f"- T{a['tier']} `{a['name']}` — {a['role']}")
    out.append("")
    out.append("**Per-incident consensus:**")
    for con in swarm["consensus"]:
        out.append(
            f"- {con['incident_id']} — {con['severity'].upper()} "
            f"(score {con['score']}/100) · "
            f"{'✅ CONFIRMED by Tier-2' if con['confirmed_by_tier2'] else '⏳ not corroborated'} · "
            f"{con['agents_involved']} agents, tiers {con['tiers_involved']}, "
            f"consensus confidence {con['consensus_confidence']}")
    out.append("")
    # Tier-3 specialist recommendations are the actionable output.
    t3 = [f for f in swarm["findings"] if f["tier"] == 3]
    if t3:
        out.append("**Specialist findings (Tier-3):**")
        for f in t3:
            out.append(f"- [{f['severity'].upper()}] _{f['role']}_: **{f['title']}**")
            if f.get("recommended_action"):
                out.append(f"    - action: {f['recommended_action']}")
        out.append("")
    return "\n".join(out)
