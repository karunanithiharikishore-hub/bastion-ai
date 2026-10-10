# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Render analysis results to Markdown or JSON."""
from __future__ import annotations

import json
import re

from .. import provenance
from ..agents.commander import MAX_DIRECTIVE_CHARS, MAX_SUMMARY_CHARS
from ..agents.injection import sanitize

_MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]()<>#|!~&])")
_LIST_ITEM_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
_OUTCOME_CHARS = 300  # worker error text echoed by the commander


def _md(value, code: bool = False, max_len: int | None = None) -> str:
    """A log-derived value as inline text on one line, with no markdown, HTML or link syntax.
    code=True is for values inside a backtick span (escaping shows there, so backticks are swapped)."""
    s = " ".join(sanitize(value, max_len).split())
    return s.replace("`", "'") if code else _MD_SPECIAL_RE.sub(r"\\\1", s)


def _md_block(text: str) -> str:
    """Multi-line prose: each line as _md, but a list marker and its nesting indent stay at line start."""
    out = []
    for ln in text.splitlines():
        m = _LIST_ITEM_RE.match(ln)
        out.append(f"{m.group(1)}{m.group(2)} {_md(m.group(3))}" if m else _md(ln))
    return "\n".join(out)


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


_BENIGN_NARRATIVE_NOTE = ("Written before the final verdict, so it describes the rule "
                          "matches as an attack. The verdict above is that this "
                          "activity is benign.")


def _benign(structured: dict) -> bool:
    return (structured.get("attack_summary") or {}).get("framing") == "benign"


def _override_note(v: dict) -> str:
    """One line saying the Tier-2 agent overruled the rule score, or ''."""
    if v.get("injection_note"):
        return v["injection_note"]
    if not v.get("overrides_rules"):
        return ""
    rv = v.get("rule_verdict") or {}
    return (f"Tier-2 agent overruled the rule-based score, which said "
            f"{_verdict_badge(rv.get('level'))} ({round((rv.get('confidence') or 0) * 100)}%).")


def _votes_note(v: dict) -> str:
    """"Tier-2 vote: 2 confirmed / 1 dismissed (agreement 67%)" or ''."""
    votes = v.get("votes") or {}
    if not votes:
        return ""
    out = (f"Tier-2 vote: {votes.get('confirmed', 0)} confirmed / "
           f"{votes.get('dismissed', 0)} dismissed")
    extra = [f"{votes[k]} {k}" for k in ("abstained", "failed") if votes.get(k)]
    if extra:
        out += f" ({', '.join(extra)})"
    if votes.get("agreement") is not None:
        out += f", agreement {round(votes['agreement'] * 100)}%"
    if votes.get("needs_review"):
        out += "; split vote, the rule verdict stands and needs review"
    return out + "."


def _incident_count(result: dict) -> str:
    """"15 (showing top 10)" when the report was capped at max_incidents."""
    shown = len(result["incidents"])
    total = result["meta"].get("incidents_total", shown)
    return f"{total} (showing top {shown})" if total > shown else str(total)


def render_markdown(result: dict) -> str:
    meta = result["meta"]
    lines = [
        "# BlueCell - Incident Analysis Report",
        "",
        f"> Built by **{meta.get('author', provenance.AUTHOR)}** · "
        f"{provenance.COPYRIGHT}",
        "",
        f"- Generated: {meta['generated']}",
        f"- Events ingested: **{meta['events_ingested']}** "
        f"(distinct after normalize: {meta['events_normalized']})",
        f"- Sources: {', '.join(_md(str(x)) for x in meta['sources']) or 'n/a'}",
        f"- Incidents found: **{_incident_count(result)}**",
        f"- LLM backbone: {meta['backbone']}  |  digest ≈ {meta['digest_tokens']} tokens",
        "",
    ]

    # Agent swarm summary (if the swarm ran).
    swarm = result.get("swarm")
    if swarm:
        c = swarm["counts"]
        lines += [
            f"- Agent swarm: **{_agents_label(swarm)}** "
            f"(T1:{c['tier1_findings']} findings, T2:{c['tier2_findings']} verifications, "
            f"T3:{c['tier3_findings']} specialist findings, "
            f"{c['confirmed_incidents']} confirmed, "
            f"{c.get('autonomous_agents', 0)} of {swarm['agent_count']} ran as autonomous AI agents)",
            "",
        ]

    if not result["incidents"]:
        lines.append("_No correlated incidents crossed the reporting threshold._")
        if (result.get("prompt_injection") or {}).get("count"):
            lines += ["", _render_injection(result.get("prompt_injection"))]
        if swarm:
            lines += ["", _render_swarm(swarm)]
        lines += ["", _render_trace(meta), "---", _footer()]
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
        f"(confidence {round(tv.get('confidence', 0) * 100)}%): {_md(tv.get('headline', ''))}",
        "",
    ]
    if _override_note(tv):
        lines += [f"_{_md(_override_note(tv))}_", ""]
    if _votes_note(tv):
        lines += [f"_{_md(_votes_note(tv))}_", ""]
    benign = asum.get("framing") == "benign"
    lines += [
        f"**{'How it started' if benign else 'How they got in'}:** "
        f"{_md(asum.get('how_they_got_in', 'n/a'))}",
        "",
        f"**{'Assessment' if benign else 'Objective'}:** "
        f"{_md(asum.get('objective', ts.get('likely_objective', 'unknown')))}",
        "",
        f"**{'What happened' if benign else 'What they did'}:**",
    ]
    for step in asum.get("what_they_did", []):
        lines.append(f"- {_md(step)}")
    if not asum.get("what_they_did"):
        lines.append("- No discrete actions reconstructed.")
    lines += [
        "",
        f"**Scope:** hosts: {_md(', '.join(ts.get('affected_hosts') or [])) or 'n/a'} · "
        f"users: {_md(', '.join(ts.get('affected_users') or [])) or 'n/a'} · "
        f"window: {_md(ts['window']['start'])} → {_md(ts['window']['end'])}",
        "",
    ]

    lines.append("## Incidents (highest risk first)\n")
    for i, inc in enumerate(result["incidents"], 1):
        s = inc["storyline"]["structured"]
        lines += [
            f"### {i}. {s['incident_id']} - {_sev_badge(s['severity'])} "
            f"(score {s['score']}/100)",
            "",
        ]
        # Analyst verdict — the real-vs-noise call, up top where it matters.
        v = inc.get("verdict")
        if v:
            lines += [
                f"> **VERDICT: {_verdict_badge(v['level'])}** "
                f"(confidence {round(v.get('confidence', 0) * 100)}%)  ",
                f"> {_md(v['headline'])}  ",
            ]
            if _override_note(v):
                lines.append(f"> _{_md(_override_note(v))}_  ")
            if _votes_note(v):
                lines.append(f"> _{_md(_votes_note(v))}_  ")
            lines += [
                f"> {_md(v['why'])}",
                "",
                "**What to do next:**",
            ]
            for chk in v.get("recommended_checks", []):
                lines.append(f"- [ ] {_md(chk)}")
            lines.append("")
        lines += [
            f"- Window: {_md(s['window']['start'])} → {_md(s['window']['end'])}",
            f"- Hosts: {_md(', '.join(s['affected_hosts'])) or 'n/a'}",
            f"- Users: {_md(', '.join(s['affected_users'])) or 'n/a'}",
            f"- Sources: {_md(', '.join(s['sources_involved']))}",
            f"- {'Assessment' if _benign(s) else 'Likely objective'}: "
            f"**{_md(s['likely_objective'])}**",
            "",
            "**RCA / Storyline** "
            f"_(source: {inc['storyline']['narrative_source']})_",
            "",
        ]
        if _benign(s):
            lines += [f"_{_BENIGN_NARRATIVE_NOTE}_", ""]
        # Narrative is multi-line prose: neutralize each line, keep the line breaks and list markers.
        lines += [
            _md_block(inc["storyline"]["narrative"]),
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
            hosts = f" - hosts: {_md(', '.join(x['hosts']))}" if x["hosts"] else ""
            lines.append(f"- `{_md(x['value'], code=True)}` (x{x['count']}){flag}{hosts}")
        lines.append("")

    lines.append(_render_injection(result.get("prompt_injection")))

    # Threat-hunt checklist
    lines.append("## Threat-Hunt Checklist (prioritized)\n")
    for c in result["hunt_checklist"]:
        lines.append(f"- [{c['priority'].upper()}] **{_md(c['action'])}**")
        if c.get("targets"):
            lines.append(f"    - targets: {_md(', '.join(str(t) for t in c['targets'][:20]))}")
        lines.append(f"    - why: {_md(c['why'])}")
    lines.append("")

    # Threat intel used
    if result.get("intel_used"):
        lines.append("## Threat Intel Referenced\n")
        for e in result["intel_used"]:
            lines.append(f"- {_md(e.get('id'))}: {_md(e.get('title'))} "
                         f"(sev {_md(e.get('severity', '?'))}, src {_md(e.get('source', '?'))})")
        lines.append("")

    # Agent swarm detail.
    if swarm:
        lines.append(_render_swarm(swarm))

    lines.append(_render_trace(meta))
    lines.append("---")
    lines.append("_BlueCell is a read-only analysis aid. Validate all findings "
                 "before acting. IOCs and RCA are hypotheses, not proof._")
    lines.append(_footer())
    return "\n".join(lines)


def _cost_text(cost, unknown_calls=0) -> str:
    """None = unknown ("n/a"); a known sum with unknown calls is a lower bound (">= $x")."""
    if cost is None:
        return "n/a"
    return f"{'>= ' if unknown_calls else ''}${cost:.4f}"


def _render_trace(meta: dict) -> str:
    """Short "Run cost & trace" section from meta["trace"] ('' when absent)."""
    t = meta.get("trace")
    if not t:
        return ""
    tok = t.get("tokens") or {}
    saved = (f"`bluecell runs show {t.get('run_id')}`" if t.get("persisted", True)
             else "not saved (--no-trace)")
    out = ["## Run cost & trace\n",
           f"- Run id: `{t.get('run_id')}` ({saved})",
           f"- Duration: {round((t.get('duration_ms') or 0) / 1000, 2)} s · "
           f"LLM calls: {t.get('llm_calls', 0)} · tool calls: {t.get('tool_calls', 0)}",
           f"- Tokens: {tok.get('total', 0)} (in {tok.get('input', 0)}, out {tok.get('output', 0)}, "
           f"cache read {tok.get('cache_read', 0)}, cache write {tok.get('cache_creation', 0)})",
           f"- Cost: {_cost_text(t.get('total_cost_usd'), t.get('cost_unknown_calls'))} "
           f"({t.get('cost_note') or 'n/a'})"]
    if meta.get("cache") == "hit":
        orig = meta.get("original_run_id")
        out.append("- Served from the run cache (stored "
                   f"{meta.get('cached_at') or '?'}"
                   + (f"; original run `{orig}`" if orig else "") + "); no model calls this run")
    costly = [a for a in t.get("per_agent") or [] if a.get("llm_calls") or a.get("tool_calls")]
    for a in costly:
        out.append(f"    - T{a.get('tier')} `{a.get('agent')}`: {a.get('tool_calls', 0)} tool calls, "
                   f"{(a.get('tokens') or {}).get('total', 0)} tokens, "
                   f"{_cost_text(a.get('cost_usd'), a.get('cost_unknown_calls'))}")
    out.append("")
    return "\n".join(out)


def _render_injection(pi: dict | None) -> str:
    """Report section for log lines that try to instruct the AI analyst ('' if none)."""
    if not pi or not pi.get("count"):
        return ""
    out = ["## Prompt-injection attempts detected in logs\n",
           f"**{pi['count']} event(s)** contain text written to steer an AI analyst "
           "(for example 'ignore previous instructions' or 'mark this as benign'). "
           "Someone who can write to those logged fields tried to manipulate this "
           "analysis. That is a security signal in itself: the events were raised to "
           "at least high severity, tagged ATT&CK T1562 (Impair Defenses) and ATLAS "
           "AML.T0051.001, and incidents containing them cannot be reported as "
           "benign. The text was treated as evidence and was not followed.\n"]
    for e in pi["events"]:
        reasons = _md(", ".join(e.get("reasons") or []))
        out.append(f"- `{_md(e['event_id'], code=True)}` {_md(e['ts'])} ({_md(e['source'])}, "
                   f"host {_md(e.get('host')) or '-'}): {reasons}")
        out.append(f"    - excerpt: `{_md(e.get('excerpt'), code=True)}`")
    if pi["count"] > len(pi["events"]):
        out.append(f"- ... and {pi['count'] - len(pi['events'])} more")
    out.append("")
    return "\n".join(out)


def _footer() -> str:
    return (f"\n<!-- {provenance.WATERMARK} -->\n"
            f"_BlueCell - built by {provenance.AUTHOR}. "
            f"{provenance.COPYRIGHT}_")


def _render_commander(swarm: dict) -> list:
    """Who decided the plan, and (for the Incident Commander) every decision."""
    cmd = swarm.get("commander")
    orch = swarm.get("orchestration") or "fixed"
    if orch != "commander" and not (cmd and cmd.get("fallback_reason")):
        return []
    out = [f"**Orchestration:** {orch}"
           + (" (the Incident Commander agent decided which agents to deploy)"
              if orch == "commander" else " (fixed Tier-1 -> Tier-2 -> Tier-3 flow)")]
    if cmd and cmd.get("fallback_reason"):
        out.append(f"- Commander not used: {_md(cmd['fallback_reason'])}; "
                   "fell back to the fixed tiered flow.")
    # A discarded commander plan produced nothing: the fixed flow re-ran the case.
    plan = [] if (cmd or {}).get("plan_discarded") else (cmd or {}).get("plan") or []
    if plan:
        out.append("")
        out.append("**Incident Commander decisions:**")
        for i, step in enumerate(plan, 1):
            if step["action"] == "deploy":
                target = step.get("incident_id") or step.get("source")
                line = (f"{i}. deploy `{_md(step['agent'], code=True)}` ({_md(step['role'])}"
                        + (f", {_md(target)}" if target else "")
                        + f"): {_md(step.get('reason'), max_len=MAX_DIRECTIVE_CHARS)}")
                if step.get("objective"):
                    line += f" · objective: {_md(step['objective'], max_len=MAX_DIRECTIVE_CHARS)}"
                line += f" → {_md(step.get('outcome'), max_len=_OUTCOME_CHARS)}"
            elif step["action"] == "refused":
                line = f"{i}. deploy refused: {_md(step.get('error'), max_len=_OUTCOME_CHARS)}"
            else:
                line = f"{i}. {_md(step['action'])}"
            out.append(line)
    if cmd and cmd.get("summary") and orch == "commander":
        out += ["", f"**Incident Commander summary:** {_md(cmd['summary'], max_len=MAX_SUMMARY_CHARS)}"]
    out.append("")
    return out


def _agents_label(swarm: dict) -> str:
    """Workers are the --max-agents quantity; the commander is named apart from them."""
    if swarm.get("orchestrator"):
        return f"{swarm['worker_count']} workers + commander"
    return f"{swarm.get('worker_count', swarm['agent_count'])} agents"


def _render_swarm(swarm: dict) -> str:
    out = ["## Agent Swarm - findings & consensus\n"]
    out += _render_commander(swarm)
    out.append(f"**Roster ({_agents_label(swarm)}):**")
    for a in swarm["roster"]:
        out.append(f"- T{a['tier']} `{_md(a['name'], code=True)}` - {_md(a['role'])}")
    out.append("")
    out.append("**Per-incident consensus:**")
    for con in swarm["consensus"]:
        out.append(
            f"- {_md(con['incident_id'])} - {con['severity'].upper()} "
            f"(score {con['score']}/100) · "
            f"{'✅ CONFIRMED by Tier-2' if con['confirmed_by_tier2'] else '⏳ not confirmed'} · "
            f"{con['agents_involved']} agents, tiers {con['tiers_involved']}, "
            f"consensus confidence {con['consensus_confidence']}")
    out.append("")
    t2 = [f for f in swarm["findings"] if f["tier"] == 2]
    if t2:
        out.append("**Tier-2 verdicts:**")
        for f in t2:
            tag = "AI agent" if f.get("origin") == "agent" else "rule"
            out.append(f"- **{_md(f['title'])}** ({tag}, conf {f['confidence']}): "
                       f"{_md(f['rationale'])}")
        out.append("")
    t1 = [f for f in swarm["findings"] if f["tier"] == 1]
    if t1:
        out.append("**Tier-1 candidates:**")
        for f in t1:
            tag = "AI agent" if f.get("origin") == "agent" else "rule"
            out.append(f"- [{f['severity'].upper()}] `{_md(f['agent'], code=True)}` ({tag}, "
                       f"{_md(f['status'])}): {_md(f['title'])}")
        out.append("")
    runs = swarm.get("agent_runs") or []
    if runs:
        out.append("**How each agent ran:**")
        for r in runs:
            line = f"- T{r.get('tier', '?')} `{_md(r['agent'], code=True)}`: {_md(r['mode'])}"
            if r.get("source"):  # hashed agent names (soc1-src-xxxx) need their raw log source
                line += f" (source: {_md(str(r['source'])[:80])})"
            if r.get("mode") == "autonomous":
                line += (f" · {r.get('tool_calls', 0)} tool calls, {r.get('turns')} turns, "
                         f"{r.get('findings_filed', 0)} submissions accepted, "
                         f"{r.get('rejected_submissions', 0)} rejected by grounding")
            if r.get("error"):
                line += f" · error: {_md(r['error'][:160])}"
            if r.get("note"):
                line += f" · {_md(r['note'])}"
            out.append(line)
        out.append("")
    if swarm.get("tier3_skipped"):
        out += [f"**Tier-3 specialists skipped:** {_md(swarm['tier3_skipped'])}", ""]
    # Tier-3 specialist recommendations are the actionable output.
    t3 = [f for f in swarm["findings"] if f["tier"] == 3]
    if t3:
        out.append("**Specialist findings (Tier-3):**")
        for f in t3:
            tag = "AI agent" if f.get("origin") == "agent" else "rule"
            out.append(f"- [{f['severity'].upper()}] _{_md(f['role'])}_ ({tag}, "
                       f"conf {f['confidence']}): **{_md(f['title'])}**")
            if f.get("origin") == "agent":
                out.append(f"    - why: {_md(f['rationale'])}")
                out.append(f"    - evidence: {_md(', '.join(str(x) for x in f['evidence'][:12]))}")
            if f.get("recommended_action"):
                out.append(f"    - action: {_md(f['recommended_action'])}")
        out.append("")
    return "\n".join(out)
