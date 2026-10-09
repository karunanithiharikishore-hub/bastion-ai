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

import contextvars
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .. import tracing
from .base import AgentContext, Finding
from .commander import (
    Dispatcher, IncidentCommander, DEFAULT_MAX_AGENTS, DEFAULT_COMMANDER_TURNS,
    DEFAULT_BUDGET_SECONDS, MIN_WORKER_SECONDS,
)
from .roles import JuniorSocAnalyst, SeniorSocAnalyst, SPECIALISTS
from .runtime import SwarmSession
from .budget import active_tier1_sources
from .injection import is_flagged

MAX_PARALLEL_AGENTS = 4
ORCHESTRATIONS = ("auto", "commander", "fixed")


class SwarmOrchestrator:
    def __init__(self, ctx: AgentContext, use_llm: bool = True,
                 max_parallel: int = MAX_PARALLEL_AGENTS, votes: int = 1,
                 tier1_model: str | None = None, skip_idle_tier1: bool = True,
                 orchestration: str = "fixed",
                 max_agents: int = DEFAULT_MAX_AGENTS,
                 max_commander_turns: int = DEFAULT_COMMANDER_TURNS,
                 budget_seconds: float = DEFAULT_BUDGET_SECONDS):
        if orchestration not in ORCHESTRATIONS:
            raise ValueError(f"orchestration must be one of {ORCHESTRATIONS}")
        self.ctx = ctx
        self.use_llm = use_llm
        self.max_parallel = max_parallel
        self.votes = max(1, int(votes or 1))   # Tier-2 self-consistency runs
        self.tier1_model = tier1_model         # cheaper model for triage (None = main)
        self.skip_idle_tier1 = skip_idle_tier1
        self.orchestration = orchestration
        self.max_agents = max_agents
        self.max_commander_turns = max_commander_turns
        self.budget_seconds = budget_seconds
        self.commander = None     # commander record (plan, summary, fallback reason)
        self._fallback_llm = True  # False when a failed commander left no budget
        self._cap = None          # fallback only: {"agents": left, "deadline": monotonic}
        self._cap_lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self.roster = []          # [{name, role, tier}]
        self.tier1 = []
        self.tier2 = []
        self.tier3 = []
        self.agent_runs = []      # per-agent run record (mode, tools, errors)
        self.tier3_skipped = None  # reason string when Tier-3 did not run
        self.tier3_note = None     # why Tier-3 ran despite an all-dismissal
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
        return self._run_fixed(llm=self._fallback_llm)

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
            # The fixed flow re-runs the case, so `plan` did not produce the result.
            self.commander["plan_discarded"] = True
            self._reset()
            # The fallback gets what the commander left: with no wall clock for a
            # worker, or no agents left, it runs on the rules and spends nothing more.
            # The fallback may use only the agents and wall clock the commander left.
            self._cap = {"agents": self.max_agents - dispatcher.deployed,
                         "deadline": time.monotonic() + dispatcher.remaining_seconds()}
            self._fallback_llm = (dispatcher.remaining_seconds() >= MIN_WORKER_SECONDS
                                  and dispatcher.deployed < self.max_agents)
            return None

        self.used = "commander"
        self.roster.insert(0, {"name": lead.name, "role": lead.role, "tier": lead.tier})
        self.agent_runs.insert(0, run)
        if not any(r.get("tier") == 3 for r in self.agent_runs):
            self.tier3_skipped = "The Incident Commander deployed no Tier-3 specialists."
        return self._reconcile(self.confirmed_ids())

    def tier3_scope(self, confirmed_ids) -> list:
        """Incidents Tier-3 works; shared by the fixed flow and the commander."""
        ctx = self.ctx
        agent_dismissed = {f.incident_id for f in self.tier2
                           if f.status == "dismissed" and f.origin == "agent"}
        scope = [i for i in ctx.incidents if i.id in confirmed_ids] or \
                [i for i in ctx.incidents if i.id not in agent_dismissed]
        if ctx.incidents and not scope and any(is_flagged(e) for e in ctx.events):
            # An all-dismissal is exactly what an injection aims for: keep Tier-3.
            scope = list(ctx.incidents)
            self.tier3_note = ("Tier-2 agent dismissed every incident, but the case has "
                               "injection-flagged events; Tier-3 ran anyway and needs review.")
        return scope

    # ---- fixed tiered flow --------------------------------------------------
    def _run_fixed(self, llm: bool = True) -> dict:
        ctx = self.ctx
        autonomous = self.use_llm and ctx.backbone is not None and llm
        session = SwarmSession(ctx, seed=[]) if autonomous else None
        try:
            return self._run_tiers(ctx, session)
        finally:
            if session is not None:
                session.close()

    def _admit(self, agent) -> bool:
        """Fallback cap: may this agent make model calls? Takes one of the
        agents left and bounds its timeout by the wall clock left."""
        if self._cap is None:
            return True
        with self._cap_lock:
            left = self._cap["deadline"] - time.monotonic()
            if self._cap["agents"] <= 0 or left < MIN_WORKER_SECONDS:
                return False
            self._cap["agents"] -= 1
        agent.timeout = min(agent.timeout, left)
        return True

    def _run_one(self, agent, ctx: AgentContext, session) -> list:
        if session is not None and not self._admit(agent):
            if agent.tier == 3:   # specialists are skipped, other tiers run on rules
                self.tier3_note = ("Fallback ran out of agents or wall-clock budget; "
                                   "some specialists were skipped.")
                return agent.skip(ctx, "agent or wall-clock budget exhausted")
            session = None
        return agent.run(ctx, use_llm=session is not None, session=session)

    def _run_all(self, agents: list, ctx: AgentContext, session) -> list:
        """Run one tier's agents (in parallel when they are model agents)."""
        for agent in agents:
            self._register(agent)
        if session is None:
            results = [a.run(ctx, use_llm=False) for a in agents]
        else:
            with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
                # Pool threads don't inherit contextvars; copy the caller's
                # context here (one per agent: a Context can't be entered twice)
                # so each agent's spans and usage land in this run's trace.
                ctxs = [contextvars.copy_context() for _ in agents]
                results = list(pool.map(
                    lambda cx: cx[0].run(self._run_one, cx[1], ctx, session),
                    zip(ctxs, agents)))
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
        sess2 = session if session is not None and self._admit(senior) else None
        self.tier2 = self.traced_verify(senior, ctx, self.tier1, session=sess2)
        if ctx.incidents:
            self.agent_runs.append(senior.last_run)

        # Which incidents did Tier-2 confirm?
        confirmed_ids = {f.incident_id for f in self.tier2
                         if f.status == "escalated"}

        # ---- Tier 3: specialists ----
        # Scope: the confirmed incidents; if none, everything a Tier-2 *agent*
        # did not dismiss (rule-only dismissals are advisory, like the headline).
        # If the agent dismissed every incident there is nothing left to work.
        scope = self.tier3_scope(confirmed_ids)
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
    def traced_verify(senior, ctx: AgentContext, tier1: list, session=None) -> list:
        """Tier-2 verification (all K votes) as one agent span in the run trace.
        Used by the fixed flow and by the Incident Commander's verifier deploys."""
        with tracing.span(f"agent:{senior.name}", "agent", agent=senior.name,
                          role=senior.role, tier=senior.tier, votes=senior.votes) as sp:
            out = senior.verify(ctx, tier1, use_llm=session is not None, session=session)
            sp.set(mode=(senior.last_run or {}).get("mode"), findings=len(out))
            return out

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
            # agent_count includes the commander; worker_count is the --max-agents
            # quantity (deployed workers) and orchestrator is the commander's entry.
            "agent_count": len(self.roster),
            "worker_count": len(self.roster) - (self.used == "commander"),
            "orchestrator": self.roster[0] if self.used == "commander" else None,
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
            "tier3_note": self.tier3_note,
            "settings": {"votes": self.votes, "tier1_model": self.tier1_model,
                         "skip_idle_tier1": self.skip_idle_tier1,
                         "orchestration": self.orchestration,
                         "max_agents": self.max_agents,
                         "max_commander_turns": self.max_commander_turns,
                         "budget_seconds": self.budget_seconds},
            "findings": [f.to_dict() for f in all_findings],
            "consensus": list(per_incident.values()),
            "orchestration": self.used,
            "commander": self.commander,
        }


def run_swarm(events, incidents, iocs, digest, intel_store=None,
              backbone=None, use_llm: bool = True, orchestration: str = "auto",
              **options) -> dict:
    """``options``: votes, tier1_model, skip_idle_tier1, max_agents,
    max_commander_turns, budget_seconds (see SwarmOrchestrator)."""
    ctx = AgentContext(events=events, incidents=incidents, iocs=iocs,
                       digest=digest, intel_store=intel_store, backbone=backbone)
    return SwarmOrchestrator(ctx, use_llm=use_llm, orchestration=orchestration,
                             **options).run()
