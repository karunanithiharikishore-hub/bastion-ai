# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Concrete blue-team agent roles.

Tier 1  : Junior SOC analysts — triage, one per log source, raise candidates.
Tier 2  : Senior SOC analysts — verify/confirm or dismiss Tier-1 candidates.
Tier 3  : Specialists & command — IR, forensics, hunt, malware, intel, security
          engineering, vulnerability analysis.
"""
from __future__ import annotations

from .base import Agent, Finding, AgentContext, _sev_from_score
from ..pipeline.attack import ATTACK_TECHNIQUES
from ..pipeline.ioc import hunt_checklist


# ---------------------------------------------------------------------------
# TIER 1 — Junior SOC Analysts (triage)
# ---------------------------------------------------------------------------
class JuniorSocAnalyst(Agent):
    """Triages one log source's contribution to each incident."""
    role = "Tier-1 SOC Analyst"
    tier = 1

    def __init__(self, source: str, **kw):
        super().__init__(name=f"soc1-{source}", **kw)
        self.source = source

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
class SeniorSocAnalyst(Agent):
    """Verifies Tier-1 candidates: corroboration across sources raises confidence."""
    role = "Tier-2 SOC Analyst"
    tier = 2

    def verify(self, ctx: AgentContext, tier1: list) -> list:
        by_incident = {}
        for f in tier1:
            by_incident.setdefault(f.incident_id, []).append(f)

        verified = []
        for inc in ctx.incidents:
            cands = by_incident.get(inc.id, [])
            if not cands:
                continue
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
            verified.append(Finding(
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
            ))
        return verified

    def analyze(self, ctx: AgentContext) -> list:  # not used directly
        return []


# ---------------------------------------------------------------------------
# TIER 3 — Specialists
# ---------------------------------------------------------------------------
class IncidentResponder(Agent):
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


class DigitalForensicsAnalyst(Agent):
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


class ThreatHunter(Agent):
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


class MalwareAnalyst(Agent):
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


class ThreatIntelAnalyst(Agent):
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


class SecurityEngineer(Agent):
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


class VulnerabilityAnalyst(Agent):
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
