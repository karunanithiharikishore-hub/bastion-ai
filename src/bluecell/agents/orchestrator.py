# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Swarm orchestrator — the SOC manager agent.

Flow (true multi-agent):
  1. Spawn one Tier-1 Junior SOC analyst per log source; each triages.
  2. Tier-2 Senior SOC analysts verify/confirm or dismiss Tier-1 candidates
     (cross-source corroboration = confirmation).
  3. Tier-3 specialists (IR, forensics, hunt, malware, intel, security eng,
     vuln) run on the confirmed picture.
  4. Reconcile into a consensus report with per-incident confidence.

Each agent's deterministic brain always runs; the LLM backbone (local `claude`
CLI keyless, or API) enriches when available. If ruflo is importable, agents
are also registered in its swarm for tracking, but execution does not depend
on it.
"""
from __future__ import annotations

from .base import AgentContext, Finding
from .roles import JuniorSocAnalyst, SeniorSocAnalyst, SPECIALISTS


class SwarmOrchestrator:
    def __init__(self, ctx: AgentContext, use_llm: bool = True):
        self.ctx = ctx
        self.use_llm = use_llm
        self.roster = []          # [{name, role, tier}]
        self.tier1 = []
        self.tier2 = []
        self.tier3 = []

    def _register(self, agent) -> None:
        self.roster.append({"name": agent.name, "role": agent.role, "tier": agent.tier})

    def run(self) -> dict:
        ctx = self.ctx

        # ---- Tier 1: one junior analyst per source present in incidents ----
        sources = sorted({e.source for inc in ctx.incidents for e in inc.events})
        if not sources:
            sources = sorted({e.source for e in ctx.events})
        for src in sources:
            agent = JuniorSocAnalyst(src)
            self._register(agent)
            self.tier1.extend(agent.run(ctx, use_llm=self.use_llm))

        # ---- Tier 2: senior analysts verify ----
        senior = SeniorSocAnalyst(name="soc2-lead")
        self._register(senior)
        self.tier2 = senior.verify(ctx, self.tier1)
        if self.use_llm:
            self.tier2 = senior.enrich(ctx, self.tier2)

        # Which incidents did Tier-2 confirm?
        confirmed_ids = {f.incident_id for f in self.tier2
                         if f.status == "escalated"}

        # ---- Tier 3: specialists (scoped to confirmed incidents) ----
        confirmed_ctx = AgentContext(
            events=ctx.events,
            incidents=[i for i in ctx.incidents if i.id in confirmed_ids] or ctx.incidents,
            iocs=ctx.iocs, digest=ctx.digest,
            intel_store=ctx.intel_store, backbone=ctx.backbone,
        )
        for cls in SPECIALISTS:
            agent = cls()
            self._register(agent)
            self.tier3.extend(agent.run(confirmed_ctx, use_llm=self.use_llm))

        return self._reconcile(confirmed_ids)

    def _reconcile(self, confirmed_ids: set) -> dict:
        all_findings = self.tier1 + self.tier2 + self.tier3

        # Per-incident consensus: how many agents/tiers weighed in + confirmation.
        per_incident = {}
        for inc in self.ctx.incidents:
            related = [f for f in all_findings if f.incident_id == inc.id]
            tiers = sorted({f.tier for f in related})
            confirmed = inc.id in confirmed_ids
            confs = [f.confidence for f in related] or [0.0]
            per_incident[inc.id] = {
                "incident_id": inc.id,
                "score": inc.score(),
                "severity": inc.severity_label(),
                "confirmed_by_tier2": confirmed,
                "agents_involved": len({f.agent for f in related}),
                "tiers_involved": tiers,
                "consensus_confidence": round(sum(confs) / len(confs), 2),
                "techniques": inc.techniques,
            }

        return {
            "roster": self.roster,
            "agent_count": len(self.roster),
            "counts": {
                "tier1_findings": len(self.tier1),
                "tier2_findings": len(self.tier2),
                "tier3_findings": len(self.tier3),
                "confirmed_incidents": len(confirmed_ids),
            },
            "findings": [f.to_dict() for f in all_findings],
            "consensus": list(per_incident.values()),
        }


def run_swarm(events, incidents, iocs, digest, intel_store=None,
              backbone=None, use_llm: bool = True) -> dict:
    ctx = AgentContext(events=events, incidents=incidents, iocs=iocs,
                       digest=digest, intel_store=intel_store, backbone=backbone)
    return SwarmOrchestrator(ctx, use_llm=use_llm).run()
