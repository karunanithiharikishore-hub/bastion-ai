# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Root-cause / attack storyline reconstruction.

Two layers:
1. A deterministic storyline built from the correlated incident: patient-zero,
   ordered phases mapped to ATT&CK tactics, and the likely objective. Always
   available, no LLM required.
2. Optional LLM narrative: given the compact event digest + deterministic
   skeleton + relevant threat intel, Claude writes a readable RCA. Falls back
   silently to the deterministic text if the backbone is unavailable.
"""
from __future__ import annotations

from ..pipeline.attack import ATTACK_TECHNIQUES

# Rough kill-chain ordering so phases read in attack order, not just clock order.
_TACTIC_ORDER = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def _tactic_rank(tactic: str) -> int:
    for i, t in enumerate(_TACTIC_ORDER):
        if t in tactic:
            return i
    return len(_TACTIC_ORDER)


def deterministic_storyline(inc) -> dict:
    """Build a structured, LLM-free storyline for one incident."""
    events = inc.events
    patient_zero = events[0] if events else None

    # Group ATT&CK-tagged events into phases by tactic.
    phases = {}
    for ev in events:
        for tid in ev.attack:
            meta = ATTACK_TECHNIQUES.get(tid)
            tactic = meta[1] if meta else "other"
            phases.setdefault(tactic, []).append((ev, tid))

    ordered_phases = []
    for tactic in sorted(phases, key=_tactic_rank):
        evs = phases[tactic]
        tids = sorted({tid for _e, tid in evs})
        # De-duplicated example event lines for the clickable phase drawer.
        seen, samples = set(), []
        for e, _t in evs:
            line = e.compact()
            if line not in seen:
                seen.add(line); samples.append(line)
            if len(samples) >= 8:
                break
        ordered_phases.append({
            "tactic": tactic,
            "techniques": [{"id": t, "name": ATTACK_TECHNIQUES.get(t, ("?",))[0]} for t in tids],
            "first_seen": min(e.ts for e, _t in evs).isoformat(),
            "last_seen": max(e.ts for e, _t in evs).isoformat(),
            "count": len(evs),
            "example": evs[0][0].compact(),
            "events": samples,
            "hosts": sorted({e.host for e, _t in evs if e.host}),
            "users": sorted({e.user for e, _t in evs if e.user}),
        })

    objective = "unknown"
    tset = inc.tactics
    if "impact" in tset:
        objective = "impact (destruction/ransomware) — highest urgency"
    elif "exfiltration" in tset:
        objective = "data exfiltration"
    elif "command-and-control" in tset:
        objective = "establishing C2 / remote control"
    elif "persistence" in tset:
        objective = "establishing persistence / foothold"
    elif "credential-access" in tset:
        objective = "credential theft / account takeover"

    return {
        "incident_id": inc.id,
        "score": inc.score(),
        "severity": inc.severity_label(),
        "window": {"start": inc.start.isoformat(), "end": inc.end.isoformat()},
        "affected_hosts": sorted(inc.hosts),
        "affected_users": sorted(inc.users),
        "sources_involved": sorted(inc.sources),
        "patient_zero": patient_zero.compact() if patient_zero else None,
        "phases": ordered_phases,
        "likely_objective": objective,
        "event_count": len(events),
        "attack_summary": _attack_summary(inc, patient_zero, ordered_phases, objective),
    }


# Human-readable label per ATT&CK tactic for the plain-English summary.
_TACTIC_VERB = {
    "reconnaissance": "scouted the environment",
    "initial-access": "gained an initial foothold",
    "execution": "ran malicious code",
    "persistence": "established persistence to survive reboots/log-offs",
    "privilege-escalation": "escalated privileges",
    "defense-evasion": "disabled or evaded defenses",
    "credential-access": "harvested credentials",
    "discovery": "mapped internal systems",
    "lateral-movement": "moved to other machines",
    "collection": "collected data of interest",
    "command-and-control": "set up remote command-and-control",
    "exfiltration": "exfiltrated data out of the network",
    "impact": "caused impact (encryption/destruction)",
}


def _attack_summary(inc, patient_zero, ordered_phases, objective) -> dict:
    """Plain-English 'how they got in and what they did' for non-experts."""
    # Entry vector: earliest phase in kill-chain order, plus patient zero.
    entry_phase = ordered_phases[0] if ordered_phases else None
    entry_bits = []
    if patient_zero is not None:
        pz = patient_zero.compact() if hasattr(patient_zero, "compact") else str(patient_zero)
        entry_bits.append(f"Earliest suspicious activity: {pz}.")
    if entry_phase:
        techs = ", ".join(f"{t['id']} ({t['name']})" for t in entry_phase["techniques"])
        entry_bits.append(
            f"First observed tactic was {entry_phase['tactic']} via {techs}"
            f" at {entry_phase['first_seen'][:19].replace('T', ' ')}.")
    if inc.users:
        entry_bits.append(f"Accounts involved: {', '.join(sorted(inc.users))}.")

    steps = []
    for i, p in enumerate(ordered_phases, 1):
        verb = _TACTIC_VERB.get(p["tactic"], p["tactic"])
        techs = ", ".join(t["id"] for t in p["techniques"])
        where = (" on " + ", ".join(p["hosts"])) if p["hosts"] else ""
        steps.append(f"{i}. The attacker {verb}{where} "
                     f"[{techs}] — first seen {p['first_seen'][11:19]}, {p['count']} event(s).")

    return {
        "how_they_got_in": " ".join(entry_bits) or "Entry vector could not be determined from the evidence.",
        "what_they_did": steps,
        "objective": objective,
        "span": {"start": inc.start.isoformat(), "end": inc.end.isoformat()},
        "affected_hosts": sorted(inc.hosts),
        "affected_users": sorted(inc.users),
    }


def _llm_narrative(inc, story: dict, digest: str, intel: list, backbone) -> str | None:
    if backbone is None:
        return None
    intel_txt = "\n".join(
        f"- {e.get('id')}: {e.get('title')} (sev {e.get('severity','?')})"
        for e in intel
    ) or "(no matching intel)"
    phase_txt = "\n".join(
        f"  {p['tactic']}: {', '.join(t['id'] for t in p['techniques'])} (first {p['first_seen']})"
        for p in story["phases"]
    ) or "  (no ATT&CK phases)"
    system = (
        "You are a senior blue-team incident analyst. Write a factual, concise "
        "root-cause analysis from the provided normalized evidence only. Do not "
        "invent hosts, IPs, times, or techniques not present in the evidence. "
        "If evidence is insufficient for a claim, say so explicitly."
    )
    prompt = f"""Reconstruct the attack storyline and root cause for this incident.

INCIDENT: {inc.id}  score={story['score']}/100 severity={story['severity']}
Window: {story['window']['start']} .. {story['window']['end']}
Affected hosts: {story['affected_hosts']}
Affected users: {story['affected_users']}
Sources: {story['sources_involved']}
Deterministic likely objective: {story['likely_objective']}

ATT&CK PHASES (deterministic skeleton):
{phase_txt}

RELEVANT THREAT INTEL (retrieved):
{intel_txt}

NORMALIZED EVENT DIGEST (compact, deduplicated):
{digest}

Write:
1. Summary (2-3 sentences).
2. Attack storyline in order (how it started -> what happened -> objective).
3. Root cause (the initial weakness/entry that made this possible).
4. Confidence and any evidence gaps.
Keep it under 350 words. Reference technique IDs where relevant."""
    try:
        return backbone.complete(prompt, system=system, max_tokens=1200)
    except Exception:
        return None


def build_storyline(inc, digest: str = "", intel: list | None = None,
                    backbone=None) -> dict:
    """Return {structured, narrative, narrative_source}."""
    structured = deterministic_storyline(inc)
    narrative = _llm_narrative(inc, structured, digest, intel or [], backbone)
    if narrative:
        source = "llm"
    else:
        narrative = _fallback_narrative(structured)
        source = "deterministic"
    return {"structured": structured, "narrative": narrative,
            "narrative_source": source}


def _fallback_narrative(story: dict) -> str:
    lines = [
        f"Incident {story['incident_id']} — {story['severity'].upper()} "
        f"(score {story['score']}/100).",
        f"Observed between {story['window']['start']} and {story['window']['end']} "
        f"across sources: {', '.join(story['sources_involved'])}.",
    ]
    if story["affected_hosts"]:
        lines.append(f"Affected hosts: {', '.join(story['affected_hosts'])}.")
    if story["patient_zero"]:
        lines.append(f"Earliest related activity: {story['patient_zero']}.")
    if story["phases"]:
        lines.append("Progression by ATT&CK tactic:")
        for p in story["phases"]:
            techs = ", ".join(f"{t['id']} ({t['name']})" for t in p["techniques"])
            lines.append(f"  - {p['tactic']}: {techs} — first seen {p['first_seen']} ({p['count']} events).")
    lines.append(f"Likely objective: {story['likely_objective']}.")
    lines.append("(Deterministic storyline — LLM backbone unavailable; enable "
                 "`claude` CLI or ANTHROPIC_API_KEY for a narrative RCA.)")
    return "\n".join(lines)