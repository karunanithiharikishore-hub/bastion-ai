# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Concrete blue-team agent roles.

Tier 1  : Junior SOC analysts — triage, one per log source, raise candidates.
Tier 2  : Senior SOC analyst — confirm or dismiss incidents from the candidates.
Tier 3  : Specialists — IR, forensics, hunt, malware, intel, security
          engineering, vulnerability analysis.

Every agent here is an autonomous, tool-using model agent (see runtime.py). The
``analyze`` / rule-verdict code on each is the fallback used only when no model
backbone is available or the agent fails.
"""
from __future__ import annotations

from .base import Agent, Finding, AgentContext, _sev_from_score
from ..pipeline.attack import ATTACK_TECHNIQUES
from ..pipeline.ioc import hunt_checklist
from .runtime import AutonomousAgent
from .toolbox import BASE_TOOLS


# ---------------------------------------------------------------------------
# TIER 1 — Junior SOC Analysts (triage)
# ---------------------------------------------------------------------------
class JuniorSocAnalyst(AutonomousAgent):
    """Triages one log source and raises candidates for Tier-2."""
    role = "Tier-1 SOC Analyst"
    tier = 1
    default_max_turns = 16
    mission = """Mission: you are the Tier-1 analyst who owns the {source!r} log source.
    Triage it: go through the {source} events (search_events with source={source!r},
    aggregate by action/host/user/process), separate the malicious or suspicious
    from routine noise, and raise each real candidate with submit_finding. Each
    candidate must cite at least one {source} event; cite events from other
    sources too when they corroborate it, and set incident_id when the activity
    belongs to a correlated incident. Rate severity and confidence honestly: a
    noisy-but-benign pattern should not be raised. Tier-2 will verify your
    candidates, so make the rationale precise enough to check."""

    def __init__(self, source: str, **kw):
        super().__init__(name=f"soc1-{source}", **kw)
        self.source = source
        self.source_scope = source

    def brief(self) -> str:
        return self.mission.format(source=self.source)

    def analyze(self, ctx: AgentContext) -> list:
        findings = []
        for inc in ctx.incidents:
            src_events = [e for e in inc.events if e.source == self.source]
            if not src_events:
                continue
            techs = sorted({t for e in src_events for t in e.attack})
            if not techs and inc.max_severity < 3:
                continue  # nothing notable from this source in this incident
            sev = _sev_from_score(inc.score()) if techs else "low"
            conf = 0.5 + 0.1 * min(3, len(techs))
            findings.append(Finding(
                agent=self.name, role=self.role, tier=1,
                title=f"Suspicious {self.source} activity in {inc.id}",
                severity=sev, confidence=round(min(conf, 0.85), 2),
                rationale=(f"{len(src_events)} {self.source} events tied to incident "
                           f"{inc.id}; techniques: {techs or 'none tagged'}."),
                incident_id=inc.id, attack=techs,
                evidence=[e.event_id for e in src_events[:20]],
                recommended_action="Escalate to Tier-2 for verification.",
                status="proposed",
            ))
        return findings


# ---------------------------------------------------------------------------
# TIER 2 — Senior SOC Analysts (verification / confirmation)
# ---------------------------------------------------------------------------
class SeniorSocAnalyst(AutonomousAgent):
    """Confirms or dismisses incidents from the Tier-1 candidates."""
    role = "Tier-2 SOC Analyst"
    tier = 2
    tools = tuple(t for t in BASE_TOOLS if t != "submit_finding") + ("submit_verdict",)
    mission = """Mission: you are the Tier-2 analyst. The Tier-1 analysts' candidates are
    in case_overview under earlier_tiers (with their ids, rationale and evidence).
    Do not take them on trust: for every correlated incident, re-examine the
    events yourself, check whether independent sources corroborate each other,
    look for benign explanations (admin activity, scanners, misconfiguration),
    and look for anything Tier-1 missed. Then record exactly one decision per
    incident with submit_verdict: 'confirmed' if the evidence shows real
    malicious activity that the specialists must work, 'dismissed' if it does
    not. List the candidate ids you reviewed. Confirmed incidents go to the
    Tier-3 specialists, so be decisive and explain the deciding evidence."""

    def verify(self, ctx: AgentContext, tier1: list, use_llm: bool = False,
               session=None) -> list:
        """Return Tier-2 verdict findings, and mark the Tier-1 candidates."""
        by_incident = {}
        for f in tier1:
            by_incident.setdefault(f.incident_id, []).append(f)
        agent_verdicts = {}
        if use_llm and ctx.backbone is not None and session is not None:
            try:
                self.investigate(ctx, session)
                agent_verdicts = {v["incident_id"]: v for v in self.verdicts}
            except Exception as exc:
                self.last_run = dict(self.last_run or {}, agent=self.name, role=self.role,
                                     tier=self.tier, mode="fallback (rules)", error=str(exc))
        else:
            self.last_run = {"agent": self.name, "role": self.role, "tier": self.tier,
                             "mode": "rules", "error": None}
        by_id = {f.id: f for f in tier1}

        verified = []
        for inc in ctx.incidents:
            cands = by_incident.get(inc.id, [])
            v = agent_verdicts.get(inc.id)
            if v is not None:
                verified.append(self._apply_verdict(inc, v, cands, by_id))
            elif cands:
                verified.append(self._rule_verdict(inc, cands))
        if self.last_run.get("mode") == "autonomous":
            notes = []
            by_rules = [f.incident_id for f in verified if f.origin == "rules"]
            if by_rules:
                notes.append(f"no agent verdict for {by_rules}; rules decided those")
            decided = {f.incident_id for f in verified}
            undecided = [i.id for i in ctx.incidents if i.id not in decided]
            if undecided:
                notes.append(f"{undecided} got no verdict and no Tier-1 candidates")
            if notes:
                self.last_run["note"] = "; ".join(notes)
        self.last_run["findings_filed"] = len(verified)
        return verified

    def _apply_verdict(self, inc, v: dict, cands: list, by_id: dict) -> Finding:
        confirmed = v["decision"] == "confirmed"
        status = "confirmed" if confirmed else "dismissed"
        reviewed = {by_id[i].id for i in v["reviewed_candidates"] if i in by_id}
        for c in cands + [by_id[i] for i in reviewed]:
            if self.name not in c.verified_by:
                c.status = status
                c.verified_by.append(self.name)
        return Finding(
            agent=self.name, role=self.role, tier=2,
            title=f"Incident {inc.id} {'CONFIRMED' if confirmed else 'dismissed'}",
            severity=v["severity"], confidence=v["confidence"],
            rationale=v["rationale"], incident_id=inc.id,
            attack=sorted({t for e in inc.events if e.event_id in set(v["evidence"])
                           for t in e.attack}),
            evidence=v["evidence"],
            recommended_action=("Escalate to Incident Responder + specialists."
                                if confirmed else "Close; monitor for recurrence."),
            status="escalated" if confirmed else "dismissed",
            verified_by=[self.name], origin="agent",
        )

    def _rule_verdict(self, inc, cands: list) -> Finding:
        sources = {c.agent.replace("soc1-", "") for c in cands}
        techs = sorted({t for c in cands for t in c.attack})
        multi_source = len(sources) >= 2
        has_attack = bool(techs)
        # Confirmation rule: corroborated by >=2 sources OR high incident score.
        confirmed = multi_source or inc.score() >= 50
        status = "confirmed" if confirmed else "dismissed"
        conf = 0.9 if (multi_source and has_attack) else 0.7 if confirmed else 0.3
        for c in cands:
            c.status = status
            c.verified_by.append(self.name)
        return Finding(
            agent=self.name, role=self.role, tier=2,
            title=f"Incident {inc.id} {'CONFIRMED' if confirmed else 'not corroborated'}",
            severity=_sev_from_score(inc.score()),
            confidence=round(conf, 2),
            rationale=(f"Reviewed {len(cands)} Tier-1 candidates across sources "
                       f"{sorted(sources)}. Cross-source corroboration="
                       f"{multi_source}, incident score={inc.score()}/100."),
            incident_id=inc.id, attack=techs,
            evidence=[eid for c in cands for eid in c.evidence][:30],
            recommended_action=("Escalate to Incident Responder + specialists."
                                if confirmed else "Close as low-priority; monitor."),
            status="escalated" if confirmed else "dismissed",
            verified_by=[self.name],
        )

    def analyze(self, ctx: AgentContext) -> list:  # not used directly
        return []


# ---------------------------------------------------------------------------
# TIER 3 — Specialists
# ---------------------------------------------------------------------------
class IncidentResponder(AutonomousAgent):
    mission = """Mission: own the response. Decide whether this is a real intrusion, how far it
    has spread, and what must be contained first. Work the scope: every affected
    host, account, source IP and the attacker's current foothold. Distinguish what
    is confirmed from what is suspected. Produce a prioritized containment and
    eradication plan (isolate, revoke, block, reset) where each action is tied to
    the specific events that justify it, and flag what must be preserved for
    forensics before anyone acts."""
    role = "Incident Responder"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        out = []
        for inc in ctx.incidents:
            if inc.score() < 50:
                continue
            actions = []
            if "impact" in inc.tactics:
                actions.append("Isolate affected hosts immediately; do NOT power off "
                               "(preserve volatile evidence).")
            if "lateral-movement" in inc.tactics:
                actions.append("Block lateral protocols (SMB/RDP/WinRM) between segments.")
            if "credential-access" in inc.tactics:
                actions.append("Force password reset + revoke sessions for affected accounts; enable MFA.")
            if "command-and-control" in inc.tactics:
                actions.append("Block C2 domains/IPs at proxy and firewall; sinkhole if possible.")
            if not actions:
                actions.append("Contain affected hosts and begin scoping.")
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=f"Containment plan for {inc.id}",
                severity=_sev_from_score(inc.score()), confidence=0.8,
                rationale="Containment derived from confirmed tactics: "
                          f"{sorted(inc.tactics)}.",
                incident_id=inc.id, attack=inc.techniques,
                evidence=sorted(inc.hosts),
                recommended_action=" | ".join(actions),
                status="escalated",
            ))
        return out


class DigitalForensicsAnalyst(AutonomousAgent):
    mission = """Mission: reconstruct exactly what happened, in order. Identify patient zero
    and the initial access vector, then build a precise timeline from first
    attacker activity to the last observed action, across every log source.
    Establish the process lineage and the sequence of attacker actions on each
    host, call out gaps in the timeline where logs are missing, and state which
    artifacts (disk, memory, specific logs) should be acquired to prove it."""
    role = "Digital Forensics Analyst"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        out = []
        for inc in ctx.incidents:
            if inc.score() < 50:
                continue
            timeline = [f"{e.ts.strftime('%H:%M:%S')} {e.source}:{e.action} "
                        f"{'/'.join(filter(None,[e.host,e.user]))}"
                        for e in inc.events[:15]]
            pz = inc.events[0]
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=f"Forensic timeline + patient-zero for {inc.id}",
                severity=_sev_from_score(inc.score()), confidence=0.75,
                rationale=("Patient-zero (earliest related event): "
                           f"{pz.compact()}.\nTimeline:\n  " + "\n  ".join(timeline)),
                incident_id=inc.id,
                evidence=[e.event_id for e in inc.events[:15]],
                recommended_action="Acquire disk/memory images of affected hosts; "
                                   "preserve logs for chain of custody.",
                status="escalated",
            ))
        return out


class ThreatHunter(AutonomousAgent):
    mission = """Mission: find what the detections missed. Assume the correlated incidents are
    only part of the story. Form hunt hypotheses from the attacker's observed
    behaviour and test them against ALL events: the same IPs, hashes, accounts or
    tooling on other hosts, rare processes and destinations, activity outside the
    incident windows, and quieter precursor or follow-on activity. Report every
    confirmed hit, and also report hypotheses you tested that came back clean."""
    role = "Threat Hunter"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        checks = hunt_checklist(ctx.incidents, ctx.iocs)
        out = []
        for c in checks:
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=c["action"], severity=c["priority"], confidence=0.7,
                rationale=c["why"],
                evidence=[str(t) for t in c.get("targets", [])][:30],
                recommended_action="Run this hunt across all relevant telemetry.",
                status="proposed",
            ))
        return out


class MalwareAnalyst(AutonomousAgent):
    mission = """Mission: characterize the attacker's tooling. Examine every process execution,
    command line, binary hash, script interpreter and living-off-the-land binary
    in the evidence. Work out what each executed artifact did (download, execute,
    persist, encrypt, beacon), how it was delivered, and which hosts it touched.
    Separate malicious tooling from legitimate admin activity, and say what a
    sandbox or reverse-engineering pass should confirm."""
    role = "Malware Analyst"
    tier = 3

    _LOLBINS = ("powershell", "certutil", "mshta", "rundll32", "regsvr32",
                "bitsadmin", "wmic", "psexec", "cmd.exe", "wscript", "cscript")

    def analyze(self, ctx: AgentContext) -> list:
        out = []
        # Suspicious hashes.
        for h in [i for i in ctx.iocs.get("hash", []) if i["suspicious"]]:
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=f"Suspect binary {h['value'][:16]}...",
                severity="critical", confidence=0.7,
                rationale=f"Hash seen x{h['count']} on hosts {h['hosts']}; tied to "
                          f"ATT&CK-flagged activity.",
                evidence=[h["value"]] + h["hosts"],
                recommended_action="Detonate in sandbox; extract C2 + capabilities; "
                                   "sweep fleet for this hash.",
                status="proposed",
            ))
        # LOLBin / scripting abuse.
        procs = [i for i in ctx.iocs.get("process", [])
                 if any(l in i["value"].lower() for l in self._LOLBINS)]
        for p in procs:
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=f"Living-off-the-land binary: {p['value']}",
                severity="high", confidence=0.65,
                rationale=f"{p['value']} used in a way associated with execution / "
                          f"ingress tool transfer.",
                evidence=[p["value"]],
                recommended_action="Review command lines; hunt for the same pattern "
                                   "elsewhere; consider AppLocker/WDAC rules.",
                status="proposed",
            ))
        return out


class ThreatIntelAnalyst(AutonomousAgent):
    mission = """Mission: put the activity in context. Map the observed behaviour to ATT&CK and
    to the intel store (CVEs, advisories, known TTPs). Assess the attacker's
    likely objective and sophistication from the evidence, judge whether the
    infrastructure (IPs, domains) looks like commodity or targeted tooling, and
    say which intel entries genuinely match versus merely share a keyword. Never
    attribute to a named actor unless the evidence directly supports it."""
    role = "Threat Intelligence Analyst"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        if ctx.intel_store is None:
            return []
        out = []
        for inc in ctx.incidents:
            hits = ctx.intel_store.context_for([inc])
            if not hits:
                continue
            out.append(Finding(
                agent=self.name, role=self.role, tier=3,
                title=f"Threat intel matches for {inc.id}",
                severity=_sev_from_score(inc.score()), confidence=0.7,
                rationale="Relevant intel: " + "; ".join(
                    f"{h.get('id')} ({h.get('title')})" for h in hits),
                incident_id=inc.id,
                intel_refs=[h.get("id") for h in hits],
                recommended_action="Apply intel-derived detections and IOCs; brief the team.",
                status="proposed",
            ))
        return out


class SecurityEngineer(AutonomousAgent):
    mission = """Mission: turn this incident into control improvements. For each stage of the
    attack you can prove from the logs, identify the control that failed or was
    missing (authentication, egress filtering, application control, segmentation,
    backups, logging coverage) and recommend the specific, practical fix. Also
    identify detection gaps: what should have alerted earlier and on which events."""
    role = "Security Engineer / Architect"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        tactics = {t for inc in ctx.incidents for t in inc.tactics}
        recs = []
        if "credential-access" in tactics:
            recs.append("Enforce MFA everywhere; add SSH rate-limiting / fail2ban; disable password auth.")
        if "command-and-control" in tactics:
            recs.append("Deploy DNS filtering + egress allowlisting; alert on newly-seen domains.")
        if "impact" in tactics:
            recs.append("Immutable/offline backups; restrict vssadmin; test restore runbooks.")
        if "lateral-movement" in tactics:
            recs.append("Network segmentation; disable SMBv1; restrict admin shares + local admin reuse.")
        if not recs:
            recs.append("Baseline hardening: least privilege, logging coverage, patch cadence.")
        return [Finding(
            agent=self.name, role=self.role, tier=3,
            title="Hardening recommendations from observed gaps",
            severity="medium", confidence=0.7,
            rationale=f"Derived from tactics observed across incidents: {sorted(tactics)}.",
            recommended_action=" | ".join(recs), status="proposed",
        )]


class VulnerabilityAnalyst(AutonomousAgent):
    mission = """Mission: determine whether a vulnerability or misconfiguration enabled the
    attack. Examine the initial access path and the exploited services, accounts
    and software in the evidence, check the intel store for relevant CVEs, and
    state for each candidate whether the logs show actual exploitation, merely
    exposure, or nothing. Prioritize remediation by what the evidence proves."""
    role = "Vulnerability Analyst"
    tier = 3

    def analyze(self, ctx: AgentContext) -> list:
        if ctx.intel_store is None:
            return []
        # Match observed processes/techniques against CVE-type intel entries.
        terms = set()
        for inc in ctx.incidents:
            terms.update(inc.techniques)
            for e in inc.events:
                if e.process:
                    terms.add(e.process.lower())
        cves = [h for h in ctx.intel_store.search(terms, limit=10)
                if str(h.get("id", "")).upper().startswith("CVE")]
        if not cves:
            return []
        return [Finding(
            agent=self.name, role=self.role, tier=3,
            title="Potentially relevant known vulnerabilities",
            severity="high", confidence=0.55,
            rationale="Observed activity overlaps with: " + "; ".join(
                f"{c['id']} (cvss {c.get('severity','?')})" for c in cves),
            intel_refs=[c["id"] for c in cves],
            recommended_action="Confirm affected versions are present; prioritize patching.",
            status="proposed",
        )]


# Registry of Tier-3 specialists in run order.
SPECIALISTS = (
    IncidentResponder, DigitalForensicsAnalyst, ThreatHunter,
    MalwareAnalyst, ThreatIntelAnalyst, SecurityEngineer, VulnerabilityAnalyst,
)
