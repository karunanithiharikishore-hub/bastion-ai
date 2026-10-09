# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Swarm orchestrator — the SOC manager agent.

Flow:
  1. Tier-1: one Junior SOC analyst agent per log source triages its source and
     raises candidates (in parallel).
  2. Tier-2: the Senior SOC analyst agent re-examines the evidence behind the
     candidates and confirms or dismisses each incident.
  3. Tier-3: specialists (IR, forensics, hunt, malware, intel, security eng,
     vuln) investigate the confirmed incidents (in parallel).
  4. Reconcile into a consensus report with per-incident confidence.

Every agent is an autonomous, tool-using model agent whenever a backbone (local
`claude` CLI keyless, or API) is available; all tiers share one board, so later
tiers read earlier tiers' notes. Without a backbone each agent falls back to its
rules. ``agent_runs`` in the result records which mode every agent ran in.
"""
from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor

from .. import tracing
from .base import AgentContext, Finding
from .roles import JuniorSocAnalyst, SeniorSocAnalyst, SPECIALISTS
from .runtime import SwarmSession
from .budget import active_tier1_sources

MAX_PARALLEL_AGENTS = 4


class SwarmOrchestrator:
    def __init__(self, ctx: AgentContext, use_llm: bool = True,
                 max_parallel: int = MAX_PARALLEL_AGENTS, votes: int = 1,
                 tier1_model: str | None = None, skip_idle_tier1: bool = True):
        self.ctx = ctx
        self.use_llm = use_llm
        self.max_parallel = max_parallel
        self.votes = max(1, int(votes or 1))   # Tier-2 self-consistency runs
        self.tier1_model = tier1_model         # cheaper model for triage (None = main)
        self.skip_idle_tier1 = skip_idle_tier1
        self.roster = []          # [{name, role, tier}]
        self.tier1 = []
        self.tier2 = []
        self.tier3 = []
        self.agent_runs = []      # per-agent run record (mode, tools, errors)
        self.tier3_skipped = None  # reason string when Tier-3 did not run

    def _register(self, agent) -> None:
        self.roster.append({"name": agent.name, "role": agent.role, "tier": agent.tier})

    def run(self) -> dict:
        ctx = self.ctx
        autonomous = self.use_llm and ctx.backbone is not None
        session = SwarmSession(ctx, seed=[]) if autonomous else None
        try:
            return self._run_tiers(ctx, session)
        finally:
            if session is not None:
                session.close()

    def _run_all(self, agents: list, ctx: AgentContext, session) -> list:
        """Run one tier's agents (in parallel when they are model agents)."""
        for agent in agents:
            self._register(agent)
        if session is None:
            results = [a.run(ctx, use_llm=False) for a in agents]
        else:
            with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
                # Pool threads don't inherit contextvars; carry the active
                # trace run into each agent thread.
                results = list(pool.map(
                    lambda a: contextvars.copy_context().run(
                        a.run, ctx, use_llm=True, session=session), agents))
        self.agent_runs.extend(a.last_run for a in agents)
        return [f for findings in results for f in findings]

    def _run_tiers(self, ctx: AgentContext, session) -> dict:
        # ---- Tier 1: one junior analyst per log source ----
        # Sources with no event in any incident are left to the rules (whose
        # Tier-1 logic only looks at incident events), saving a model agent each.
        run, idle = active_tier1_sources(ctx.events, ctx.incidents,
                                         self.skip_idle_tier1 and session is not None)
        self.tier1 = self._run_all([JuniorSocAnalyst(src, llm_model=self.tier1_model)
                                    for src in run], ctx, session)
        for src in idle:
            agent = JuniorSocAnalyst(src, llm_model=self.tier1_model)
            self._register(agent)
            self.tier1 += agent.skip(ctx, "no incident events")
            self.agent_runs.append(agent.last_run)

        # ---- Tier 2: senior analyst confirms or dismisses incidents ----
        senior = SeniorSocAnalyst(name="soc2-lead", votes=self.votes)
        if ctx.incidents:
            self._register(senior)
        if session is not None:
            session.stage(ctx, seed=self._seed(self.tier1))
        with tracing.span(f"agent:{senior.name}", "agent", agent=senior.name,
                          role=senior.role, tier=senior.tier) as sp:
            self.tier2 = senior.verify(ctx, self.tier1, use_llm=session is not None,
                                       session=session)
            sp.set(mode=(senior.last_run or {}).get("mode"), findings=len(self.tier2))
        if ctx.incidents:
            self.agent_runs.append(senior.last_run)

        # Which incidents did Tier-2 confirm?
        confirmed_ids = {f.incident_id for f in self.tier2
                         if f.status == "escalated"}

        # ---- Tier 3: specialists ----
        # Scope: the confirmed incidents; if none, everything a Tier-2 *agent*
        # did not dismiss (rule-only dismissals are advisory, like the headline).
        # If the agent dismissed every incident there is nothing left to work.
        agent_dismissed = {f.incident_id for f in self.tier2
                           if f.status == "dismissed" and f.origin == "agent"}
        scope = [i for i in ctx.incidents if i.id in confirmed_ids] or \
                [i for i in ctx.incidents if i.id not in agent_dismissed]
        if not ctx.events:
            self.tier3_skipped = "No events were ingested; specialists not deployed."
            return self._reconcile(confirmed_ids)
        if ctx.incidents and not scope:
            self.tier3_skipped = (f"Tier-2 agent dismissed all {len(ctx.incidents)} "
                                  f"incident(s); specialists not deployed.")
            return self._reconcile(confirmed_ids)

        confirmed_ctx = AgentContext(
            events=ctx.events, incidents=scope,
            iocs=ctx.iocs, digest=ctx.digest,
            intel_store=ctx.intel_store, backbone=ctx.backbone,
        )
        if session is not None:
            session.stage(confirmed_ctx, seed=self._seed(self.tier1 + self.tier2))
        self.tier3 = self._run_all([cls() for cls in SPECIALISTS], confirmed_ctx, session)

        return self._reconcile(confirmed_ids)

    @staticmethod
    def _seed(findings: list) -> list:
        """Earlier tiers' conclusions, handed to the next tier as context."""
        return [{"id": f.id, "agent": f.agent, "tier": f.tier, "title": f.title,
                 "status": f.status, "severity": f.severity,
                 "confidence": f.confidence, "incident_id": f.incident_id,
                 "attack": f.attack, "evidence": f.evidence[:15],
                 "rationale": f.rationale[:600]}
                for f in findings]

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
                "autonomous_agents": sum(
                    1 for r in self.agent_runs if r.get("mode") == "autonomous"),
            },
            "agent_runs": self.agent_runs,
            "tier3_skipped": self.tier3_skipped,
            "settings": {"votes": self.votes, "tier1_model": self.tier1_model,
                         "skip_idle_tier1": self.skip_idle_tier1},
            "findings": [f.to_dict() for f in all_findings],
            "consensus": list(per_incident.values()),
        }


def run_swarm(events, incidents, iocs, digest, intel_store=None,
              backbone=None, use_llm: bool = True, **options) -> dict:
    """``options``: votes, tier1_model, skip_idle_tier1 (see SwarmOrchestrator)."""
    ctx = AgentContext(events=events, incidents=incidents, iocs=iocs,
                       digest=digest, intel_store=intel_store, backbone=backbone)
    return SwarmOrchestrator(ctx, use_llm=use_llm, **options).run()
