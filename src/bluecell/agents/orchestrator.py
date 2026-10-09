# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Swarm orchestrator.

Two ways to run the swarm (``orchestration``):

commander - an LLM "SOC Lead / Incident Commander" agent decides the plan
  (orchestrator-workers pattern, see commander.py): which worker agents to
  deploy, in what order, which follow-ups to send after reading their results,
  and when the case is done. Python enforces the guardrails (agents per run,
  commander turns, parallelism, wall-clock budget) and keeps the contract that
  incidents are confirmed/dismissed only by a Tier-2 verifier agent.

fixed - the deterministic tiered flow:
  1. Tier-1: one Junior SOC analyst agent per log source triages its source and
     raises candidates (in parallel).
  2. Tier-2: the Senior SOC analyst agent re-examines the evidence behind the
     candidates and confirms or dismisses each incident.
  3. Tier-3: specialists (IR, forensics, hunt, malware, intel, security eng,
     vuln) investigate the confirmed incidents (in parallel).

``auto`` uses the commander when a model backbone is available and the fixed
flow otherwise. If the commander deploys nothing, or ends without a Tier-2
agent verdict on a case that has incidents (including when it crashes), the run
falls back to the fixed flow and ``commander.fallback_reason`` says why.

Either way the result is reconciled into a consensus report with per-incident
confidence. Every agent is an autonomous, tool-using model agent whenever a
backbone (local `claude` CLI keyless, or API) is available; all agents share
one board, so later agents read earlier agents' notes. Without a backbone each
agent falls back to its rules. ``agent_runs`` records which mode every agent
ran in.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .base import AgentContext, Finding
from .commander import (
    Dispatcher, IncidentCommander, DEFAULT_MAX_AGENTS, DEFAULT_COMMANDER_TURNS,
    DEFAULT_BUDGET_SECONDS,
)
from .roles import JuniorSocAnalyst, SeniorSocAnalyst, SPECIALISTS
from .runtime import SwarmSession

MAX_PARALLEL_AGENTS = 4
ORCHESTRATIONS = ("auto", "commander", "fixed")


class SwarmOrchestrator:
    def __init__(self, ctx: AgentContext, use_llm: bool = True,
                 max_parallel: int = MAX_PARALLEL_AGENTS,
                 orchestration: str = "fixed",
                 max_agents: int = DEFAULT_MAX_AGENTS,
                 max_commander_turns: int = DEFAULT_COMMANDER_TURNS,
                 budget_seconds: float = DEFAULT_BUDGET_SECONDS):
        if orchestration not in ORCHESTRATIONS:
            raise ValueError(f"orchestration must be one of {ORCHESTRATIONS}")
        self.ctx = ctx
        self.use_llm = use_llm
        self.max_parallel = max_parallel
        self.orchestration = orchestration
        self.max_agents = max_agents
        self.max_commander_turns = max_commander_turns
        self.budget_seconds = budget_seconds
        self.commander = None     # commander record (plan, summary, fallback reason)
        self._reset()

    def _reset(self) -> None:
        self.roster = []          # [{name, role, tier}]
        self.tier1 = []
        self.tier2 = []
        self.tier3 = []
        self.agent_runs = []      # per-agent run record (mode, tools, errors)
        self.tier3_skipped = None  # reason string when Tier-3 did not run
        self.used = "fixed"       # orchestration that produced the result

    def _register(self, agent) -> None:
        self.roster.append({"name": agent.name, "role": agent.role, "tier": agent.tier})

    def confirmed_ids(self) -> set:
        return {f.incident_id for f in self.tier2 if f.status == "escalated"}

    def merge_tier2(self, verdicts: list) -> None:
        """Fold a verifier's output into Tier-2: one verdict per incident; a
        later agent verdict replaces an earlier one, rule verdicts only fill gaps."""
        by_inc = {f.incident_id: f for f in self.tier2}
        for f in verdicts:
            old = by_inc.get(f.incident_id)
            if old is None or f.origin == "agent" or old.origin != "agent":
                by_inc[f.incident_id] = f
        self.tier2 = list(by_inc.values())

    def run(self) -> dict:
        ctx = self.ctx
        autonomous = self.use_llm and ctx.backbone is not None
        if self.orchestration in ("auto", "commander"):
            if autonomous and ctx.events:
                out = self._run_commander()
                if out is not None:
                    return out
            elif self.orchestration == "commander":
                self.commander = {
                    "requested": "commander", "plan": [], "summary": None,
                    "fallback_reason": ("no model backbone available" if not autonomous
                                        else "no events were ingested")}
        return self._run_fixed()

    # ---- commander-led ------------------------------------------------------
    def _run_commander(self):
        """Run the Incident Commander. Returns the swarm result, or None (with
        ``commander['fallback_reason']`` set) to fall back to the fixed flow."""
        ctx = self.ctx
        session = SwarmSession(ctx, seed=[])
        try:
            dispatcher = Dispatcher(self, ctx, session, max_agents=self.max_agents,
                                    max_parallel=self.max_parallel,
                                    budget_seconds=self.budget_seconds)
            lead = IncidentCommander(dispatcher, max_turns=self.max_commander_turns)
            error = lead.command(ctx, session)
        finally:
            session.close()
        run = dict(lead.last_run or {})
        summary = dispatcher.summary
        if summary is None:   # never called finish: keep its closing text
            summary = run.get("summary") or None
        self.commander = {
            "requested": self.orchestration, "plan": dispatcher.plan,
            "summary": summary, "finished": dispatcher.finished,
            "limits": dict(dispatcher.limits(), max_turns=lead.max_turns),
            "agents_deployed": dispatcher.deployed,
            "elapsed_seconds": round(dispatcher.elapsed(), 1),
            "error": error, "fallback_reason": None,
        }

        reason = None
        if dispatcher.deployed == 0:
            reason = "the commander deployed no agents"
        elif ctx.incidents and not any(f.origin == "agent" for f in self.tier2):
            reason = "the commander ended without a Tier-2 agent verdict on any incident"
        if reason:
            if error:
                reason += f" (commander error: {error})"
            self.commander["fallback_reason"] = reason
            self.commander["run"] = {k: v for k, v in run.items() if k != "trace"}
            self._reset()
            return None

        self.used = "commander"
        self.roster.insert(0, {"name": lead.name, "role": lead.role, "tier": lead.tier})
        self.agent_runs.insert(0, run)
        if not any(r.get("tier") == 3 for r in self.agent_runs):
            self.tier3_skipped = "The Incident Commander deployed no Tier-3 specialists."
        return self._reconcile(self.confirmed_ids())

    # ---- fixed tiered flow --------------------------------------------------
    def _run_fixed(self) -> dict:
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
                results = list(pool.map(
                    lambda a: a.run(ctx, use_llm=True, session=session), agents))
        self.agent_runs.extend(a.last_run for a in agents)
        return [f for findings in results for f in findings]

    def _run_tiers(self, ctx: AgentContext, session) -> dict:
        # ---- Tier 1: one junior analyst per log source ----
        sources = sorted({e.source for e in ctx.events})
        self.tier1 = self._run_all([JuniorSocAnalyst(src) for src in sources], ctx, session)

        # ---- Tier 2: senior analyst confirms or dismisses incidents ----
        senior = SeniorSocAnalyst(name="soc2-lead")
        if ctx.incidents:
            self._register(senior)
        if session is not None:
            session.stage(ctx, seed=self._seed(self.tier1))
        self.tier2 = senior.verify(ctx, self.tier1, use_llm=session is not None,
                                   session=session)
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
            "findings": [f.to_dict() for f in all_findings],
            "consensus": list(per_incident.values()),
            "orchestration": self.used,
            "commander": self.commander,
        }


def run_swarm(events, incidents, iocs, digest, intel_store=None,
              backbone=None, use_llm: bool = True, orchestration: str = "auto",
              **limits) -> dict:
    ctx = AgentContext(events=events, incidents=incidents, iocs=iocs,
                       digest=digest, intel_store=intel_store, backbone=backbone)
    return SwarmOrchestrator(ctx, use_llm=use_llm, orchestration=orchestration,
                             **limits).run()
