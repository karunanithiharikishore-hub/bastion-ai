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


_ATTACK_CHECKS = (
    "Isolate/scope the affected hosts and accounts immediately.",
    "Confirm the successful/impact events are not the legitimate user.",
    "Pull EDR + network for the same hosts around the window.",
    "Preserve logs; begin incident response.",
)


def assess_incident(inc) -> dict:
    """Produce a plain-English analyst VERDICT: is this real, noise, or unclear —
    and what to do next. This is the judgment a Tier-2 analyst gives, surfaced so
    users don't have to interpret raw findings themselves.
    """
    tactics = set(inc.tactics)
    sources = set(inc.sources)
    events = inc.events

    def _is_success(e):
        a = (e.action or "").lower(); m = (e.message or "").lower()
        return "success" in a or a == "login_success" or "accepted" in m
    def _is_fail(e):
        return "fail" in (e.action or "").lower() or "login_failed" == (e.action or "").lower()

    has_success = any(_is_success(e) for e in events)
    fail_ct = sum(1 for e in events if _is_fail(e))
    single_source = len(sources) <= 1
    # Valid Accounts (T1078) on a sign-in is the credential story itself, not
    # separate defense-evasion/persistence activity.
    cred_tactics = set()
    for e in events:
        for tid in e.attack:
            if tid == "T1078" and e.category == "authentication":
                cred_tactics.add("credential-access")
            elif tid in ATTACK_TECHNIQUES:
                cred_tactics.update(_split_tactic(ATTACK_TECHNIQUES[tid][1]))
    only_cred = bool(cred_tactics) and cred_tactics.issubset({"credential-access", "authentication"})
    serious = bool(tactics & {"impact", "exfiltration", "command-and-control", "lateral-movement"})

    # Distinct external IPs seen (rough breadth signal).
    ips = set()
    for e in events:
        for ip in (e.src_ip, e.dst_ip):
            if ip:
                ips.add(ip)

    if serious and inc.score() >= 50:
        return {
            "level": "likely-malicious",
            "confidence": 0.8,
            "headline": "Likely a real attack. Investigate now.",
            "why": (f"Multiple kill-chain stages ({', '.join(sorted(tactics))}) "
                    f"across {len(sources)} log source(s) at high severity "
                    f"({inc.score()}/100). That progression is not normal noise."),
            "recommended_checks": list(_ATTACK_CHECKS),
        }
    if only_cred and not has_success and single_source:
        return {
            "level": "likely-benign",
            "confidence": 0.7,
            "headline": "Likely benign failed-login noise, not a confirmed breach.",
            "why": (f"{fail_ct} failed sign-in(s) with NO successful compromise, "
                    f"a single source ({', '.join(sorted(sources)) or 'n/a'}), and no "
                    f"follow-on activity (no lateral movement, C2, or impact). "
                    f"Most common cause: an expired password or a stale cached "
                    f"credential on a device (e.g. a mail client) retrying and "
                    f"racking up failures."),
            "recommended_checks": [
                "Confirm NONE of the failed attempts later SUCCEEDED from the same IP.",
                "Check whether the IPs are the user's known home/office/mobile network.",
                "Reset the password / re-auth the mail client to stop the retry spam.",
                "Confirm MFA is enforced on the account(s).",
            ],
        }
    if only_cred and has_success:
        return {
            "level": "needs-review",
            "confidence": 0.55,
            "headline": "Failed sign-ins followed by a success. Verify it was the real user.",
            "why": (f"{fail_ct} failed sign-in(s) and at least one SUCCESS. This is "
                    f"either the user finally entering the right password, or an "
                    f"account takeover. It needs a human check."),
            "recommended_checks": [
                "Was the successful sign-in from a known device / IP / location?",
                "Any impossible-travel or new-device sign-in around that time?",
                "Check for new mailbox rules, MFA changes, or app consents right after the success.",
            ],
        }
    return {
        "level": "needs-review",
        "confidence": 0.5,
        "headline": "Needs analyst review: not enough to call automatically.",
        "why": (f"Observed tactics {', '.join(sorted(tactics)) or 'none'} across "
                f"{len(sources)} source(s), but not enough corroboration for a firm "
                f"verdict."),
        "recommended_checks": [
            "Correlate with EDR / network logs for the same hosts and users.",
            "Confirm whether any action actually succeeded or had impact.",
            "Widen the correlation window if the activity looks spread out.",
        ],
    }

# Rough kill-chain ordering so phases read in attack order, not just clock order.
_TACTIC_ORDER = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


def apply_tier2_verdict(rule_verdict: dict, tier2: dict) -> dict:
    """Replace the rule-based verdict with the Tier-2 agent's decision.

    ``tier2`` is the Tier-2 finding dict (status escalated|dismissed). The rule
    verdict is kept under ``rule_verdict`` so an override stays visible.
    """
    confirmed = tier2.get("status") == "escalated"
    if confirmed:
        level = "likely-malicious"
        headline = "Tier-2 analyst confirmed a real attack. Investigate now."
        checks = (rule_verdict.get("recommended_checks")
                  if rule_verdict.get("level") == "likely-malicious" else list(_ATTACK_CHECKS))
    else:
        level = "likely-benign"
        headline = "Tier-2 analyst dismissed this as benign after reviewing the evidence."
        checks = [
            "Close the incident without escalation.",
            "Review the detection rules that flagged it; they over-scored this activity.",
            "Watch the same hosts and accounts for similar activity outside expected work.",
        ]
    return {
        "level": level,
        "confidence": tier2.get("confidence", 0.0),
        "headline": headline,
        "why": tier2.get("rationale", ""),
        "recommended_checks": checks,
        "decided_by": "tier2-agent",
        **({"votes": tier2["votes"]} if tier2.get("votes") else {}),
        "overrides_rules": level != rule_verdict.get("level"),
        "rule_verdict": {k: rule_verdict.get(k) for k in ("level", "confidence", "headline")},
    }


def reframe_benign(inc, structured: dict) -> None:
    """Rewrite an incident's attack-framed summary in neutral terms, in place,
    once its final verdict is likely-benign. The rule-derived objective is kept
    as ``rule_objective``."""
    rule_objective = structured.get("likely_objective", "unknown")
    objective = "none: assessed as benign"
    if rule_objective and rule_objective != "unknown":
        objective += f" (the rules matched patterns of {rule_objective})"
    structured["rule_objective"] = rule_objective
    structured["likely_objective"] = objective
    structured["attack_summary"] = _attack_summary(
        inc, structured.get("patient_zero"), structured.get("phases") or [],
        objective, framing="benign", tagged=structured.get("patient_zero_tagged", True))


def _split_tactic(tactic: str) -> list:
    """Compound catalog tactics ("defense-evasion/persistence") -> parts."""
    return [t for t in tactic.split("/") if t] or ["other"]


def _patient_zero(events):
    """First ATT&CK-tagged event, else None (no suspicious starting point)."""
    return next((e for e in events if e.attack), None)


def _tactic_rank(tactic: str) -> int:
    for i, t in enumerate(_TACTIC_ORDER):
        if t in tactic:
            return i
    return len(_TACTIC_ORDER)


def deterministic_storyline(inc) -> dict:
    """Build a structured, LLM-free storyline for one incident."""
    events = inc.events
    patient_zero = _patient_zero(events)
    earliest = patient_zero or (events[0] if events else None)

    # Group ATT&CK-tagged events into phases by tactic.
    phases = {}
    for ev in events:
        for tid in ev.attack:
            meta = ATTACK_TECHNIQUES.get(tid)
            for tactic in _split_tactic(meta[1] if meta else "other"):
                phases.setdefault(tactic, []).append((ev, tid))

    ordered_phases = []
    # Chronological: the storyline must start with what happened first (the
    # brute force at 09:01, not the execution at 09:06). Kill-chain rank only
    # breaks ties between phases that start at the same moment.
    first = {t: min(e.ts for e, _t in evs) for t, evs in phases.items()}
    for tactic in sorted(phases, key=lambda t: (first[t], _tactic_rank(t))):
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
            "count": len({id(e) for e, _t in evs}),   # events, not (event, technique) pairs
            "example": evs[0][0].compact(),
            "events": samples,
            "hosts": sorted({e.host for e, _t in evs if e.host}),
            "users": sorted({e.user for e, _t in evs if e.user}),
        })

    objective = "unknown"
    tset = inc.tactics
    if "impact" in tset:
        objective = "impact (destruction/ransomware), highest urgency"
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
        "patient_zero": earliest.compact() if earliest else None,
        "patient_zero_tagged": patient_zero is not None,
        "phases": ordered_phases,
        "likely_objective": objective,
        "event_count": len(events),
        "attack_summary": _attack_summary(inc, earliest, ordered_phases, objective,
                                          tagged=patient_zero is not None),
    }


# Human-readable label per ATT&CK tactic for the plain-English summary.
_TACTIC_VERB = {
    "reconnaissance": "scouted the environment",
    "initial-access": "gained an initial foothold",
    "execution": "ran malicious code",
    "persistence": "established persistence to survive reboots/log-offs",
    "privilege-escalation": "escalated privileges",
    "defense-evasion": "disabled or evaded defenses",
    "credential-access": "went after credentials (e.g. brute force or theft)",
    "discovery": "mapped internal systems",
    "lateral-movement": "moved to other machines",
    "collection": "collected data of interest",
    "command-and-control": "set up remote command-and-control",
    "exfiltration": "exfiltrated data out of the network",
    "impact": "caused impact (encryption/destruction)",
}


def _attack_summary(inc, patient_zero, ordered_phases, objective,
                    framing: str = "attack", tagged: bool = True) -> dict:
    """Plain-English 'how they got in and what they did' for non-experts.

    ``framing="benign"`` describes the same facts without presuming an attacker,
    for incidents whose final verdict is likely-benign.
    """
    benign = framing == "benign"
    # Entry vector: earliest phase in kill-chain order, plus patient zero.
    entry_phase = ordered_phases[0] if ordered_phases else None   # earliest phase
    entry_bits = []
    if patient_zero is not None:
        pz = patient_zero.compact() if hasattr(patient_zero, "compact") else str(patient_zero)
        # Only an ATT&CK-tagged event is called "suspicious".
        label = ("Earliest activity" if benign else
                 "Earliest suspicious activity" if tagged else "Earliest related activity")
        entry_bits.append(f"{label}: {pz}.")
    if entry_phase:
        techs = ", ".join(f"{t['id']} ({t['name']})" for t in entry_phase["techniques"])
        entry_bits.append(
            f"{'First rule match was' if benign else 'First observed tactic was'} "
            f"{entry_phase['tactic']} via {techs}"
            f" at {entry_phase['first_seen'][:19].replace('T', ' ')}.")
    if inc.users:
        entry_bits.append(f"Accounts involved: {', '.join(sorted(inc.users))}.")

    steps = []
    for i, p in enumerate(ordered_phases, 1):
        verb = _TACTIC_VERB.get(p["tactic"], p["tactic"])
        techs = ", ".join(t["id"] for t in p["techniques"])
        where = (" on " + ", ".join(p["hosts"])) if p["hosts"] else ""
        if benign:
            steps.append(f"{i}. Activity the rules matched to {p['tactic']}{where} "
                         f"[{techs}] - first seen {p['first_seen'][11:19]}, {p['count']} event(s).")
        else:
            steps.append(f"{i}. The attacker {verb}{where} "
                         f"[{techs}] - first seen {p['first_seen'][11:19]}, {p['count']} event(s).")

    return {
        "framing": framing,
        "how_they_got_in": " ".join(entry_bits) or (
            "Starting point could not be determined from the evidence." if benign
            else "Entry vector could not be determined from the evidence."),
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
        "You are a senior blue-team incident analyst. Every analysis and "
        "deduction you make MUST be evidence-based and precise; no hallucinations "
        "should be introduced into the analysis. Write the root-cause analysis "
        "from the provided normalized evidence ONLY. Never invent or infer hosts, "
        "IPs, domains, file hashes, users, timestamps, or ATT&CK techniques that "
        "are not literally present in the evidence. Where the evidence does not "
        "establish something, write 'not proven by the available logs' rather "
        "than guessing."
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
        text = backbone.complete(prompt, system=system, max_tokens=1200)
    except Exception:
        return None
    if not text:
        return None
    # ENFORCE grounding: flag any indicator not present in the real evidence.
    try:
        from ..agents.grounding import evidence_index, annotate
        idx = evidence_index(inc.events, inc.techniques)
        text = annotate(text.strip(), idx)
    except Exception:
        pass
    return text


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
        f"Incident {story['incident_id']} - {story['severity'].upper()} "
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
            lines.append(f"  - {p['tactic']}: {techs} - first seen {p['first_seen']} ({p['count']} events).")
    lines.append(f"Likely objective: {story['likely_objective']}.")
    lines.append("(Deterministic storyline: LLM backbone unavailable; enable "
                 "`claude` CLI or ANTHROPIC_API_KEY for a narrative RCA.)")
    return "\n".join(lines)