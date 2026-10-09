# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""The SOC Lead / Incident Commander: a model agent that runs the swarm.

Anthropic's "orchestrator-workers" pattern. Instead of Python fixing the flow
(Tier-1 -> Tier-2 -> Tier-3), the commander reads the case and decides which
worker agents to deploy, in what order, and when the case is done. It deploys
workers with ``deploy_agent`` / ``deploy_agents`` and gets each worker's summary
and filed findings/verdicts back as the tool result, so it can send follow-ups
(e.g. a Threat Hunter after a Tier-1 finding names an IP).

Workers are the existing roles, unchanged: same missions, read-only toolbox,
grounding of every submission, Tier-1 source scope, Tier-2-only
``submit_verdict``. The commander adds direction (objective, focus incident) to
a worker's brief; it cannot widen a worker's tools.

Python keeps the guardrails (``Dispatcher``): a cap on agents per run, the
commander's turn cap, MAX_PARALLEL_AGENTS per batch, and a wall-clock budget.
Deploys beyond budget are refused with a tool error the commander sees. The
orchestrator falls back to the fixed tiered flow when the commander fails or
ends without a Tier-2 agent verdict (see orchestrator.py).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .base import AgentContext
from .dispatch import COMMAND_TOOLS, CommanderToolbox, FileDispatchServer
from .roles import (
    JuniorSocAnalyst, SeniorSocAnalyst, IncidentResponder, DigitalForensicsAnalyst,
    ThreatHunter, MalwareAnalyst, ThreatIntelAnalyst, SecurityEngineer,
    VulnerabilityAnalyst,
)
from .runtime import AutonomousAgent, SwarmSession

DEFAULT_MAX_AGENTS = 15
DEFAULT_COMMANDER_TURNS = 30
DEFAULT_BUDGET_SECONDS = 3600
MIN_WORKER_SECONDS = 60      # never start a worker with less time than this

# The commander may look at the evidence itself, but files nothing.
COMMANDER_READ_TOOLS = ("case_overview", "get_incident", "search_events", "get_event",
                        "pivot", "aggregate", "list_iocs", "attack_lookup",
                        "intel_search", "read_board", "post_note")


class Investigator(AutonomousAgent):
    """General-purpose worker the commander points at one specific question."""
    role = "Investigator"
    tier = 3
    mission = """Mission: you are a general blue-team investigator. The Incident Commander
    has given you one specific objective (below). Work exactly that question with
    your tools, file what the evidence proves with submit_finding, and say clearly
    in your summary what you could not establish."""

    def analyze(self, ctx: AgentContext) -> list:
        return []   # no rule-based fallback: without a model it has nothing to add


# role key -> (class, one-line description shown to the commander)
WORKER_ROLES = {
    "tier1-analyst": (JuniorSocAnalyst,
                      "Tier-1 SOC analyst that triages ONE log source (needs 'source') "
                      "and raises candidates."),
    "tier2-verifier": (SeniorSocAnalyst,
                       "Tier-2 SOC analyst: re-examines the evidence and records a "
                       "confirmed/dismissed verdict per incident. The ONLY role whose "
                       "verdicts decide the case; deploy it after triage."),
    "incident-responder": (IncidentResponder, IncidentResponder.role +
                           ": scope, foothold and a containment plan."),
    "forensics": (DigitalForensicsAnalyst, DigitalForensicsAnalyst.role +
                  ": patient zero, initial access and the precise timeline."),
    "threat-hunter": (ThreatHunter, ThreatHunter.role +
                      ": hunts the attacker's IPs/accounts/tooling beyond the incidents."),
    "malware-analyst": (MalwareAnalyst, MalwareAnalyst.role +
                        ": executed tooling, LOLBins, hashes, what each artifact did."),
    "threat-intel": (ThreatIntelAnalyst, ThreatIntelAnalyst.role +
                     ": ATT&CK/intel context, objective and infrastructure."),
    "security-engineer": (SecurityEngineer, SecurityEngineer.role +
                          ": failed controls and detection gaps."),
    "vulnerability-analyst": (VulnerabilityAnalyst, VulnerabilityAnalyst.role +
                              ": whether a vulnerability/misconfiguration enabled it."),
    "investigator": (Investigator, "Generic investigator for a question no role covers "
                                   "(needs a precise 'objective')."),
}

COMMANDER_PROTOCOL = """\
You are the SOC Lead / Incident Commander on a blue team, running a live case
inside BlueCell. You do not file findings yourself: you run the investigation by
deploying worker agents and deciding, from what they report back, what to do
next. You can only see the evidence through your tools.

How to work:
1. Call case_overview and list_roles. Look at the evidence yourself as much as
   you need to plan (search_events, get_incident, pivot, ...); delegate the
   analysis to workers.
2. Triage: deploy Tier-1 analysts for the log sources that matter
   (deploy_agents runs a batch in parallel).
3. Verification is mandatory whenever the case has correlated incidents: after
   triage, deploy a 'tier2-verifier'. Only its verdicts confirm or dismiss an
   incident, and the report's headline depends on them. Deploy it again if
   later work changes the picture.
4. Send specialists where the verdicts and findings point: e.g. an
   incident-responder and forensics on confirmed incidents, a threat-hunter when
   a finding names an IP, account or hash that may appear elsewhere, an
   'investigator' with a precise objective for a question no role covers. Do not
   work incidents the verifier dismissed without a specific reason.
5. Read every result before deciding the next step, and give every deploy a
   concrete reason (it is recorded in the case's decision log).
6. When the case is answered, or the budget is spent, call finish with your
   summary: per incident, the verdict and the deciding evidence, what the
   specialists established, and what remains open.

Budget: agents per case and wall-clock time are limited (list_roles shows what
is left); deploys beyond budget are refused. Ground rules: never invent hosts,
IPs, domains, hashes, users, timestamps or ATT&CK techniques; you are read-only:
you analyze and direct, you never act on systems.
"""


class Dispatcher:
    """Runs the commander's deploy requests against an orchestrator's state.

    ``orch`` is the SwarmOrchestrator: workers are registered in its roster,
    their run records go to ``agent_runs`` and their findings to its tier lists,
    so the swarm result keeps the same shape as the fixed flow.
    """

    def __init__(self, orch, ctx: AgentContext, session: SwarmSession, *,
                 max_agents: int = DEFAULT_MAX_AGENTS,
                 max_parallel: int = 4,
                 budget_seconds: float = DEFAULT_BUDGET_SECONDS):
        self.orch = orch
        self.ctx = ctx
        self.session = session
        self.max_agents = max_agents
        self.max_parallel = max(1, max_parallel)
        self.budget_seconds = budget_seconds
        self.started = time.monotonic()
        self.deployed = 0
        self.batches = 0
        self.finished = False
        self.summary = None
        self.plan: list = []        # decision log: deploys (with reason), refusals, finish
        self.workers: list = []     # every worker agent deployed
        self._names: dict = {}
        self.closed = False          # set once the commander has stopped
        self._lock = threading.Lock()        # one deploy/finish at a time
        self._state_lock = threading.Lock()  # guards merging into the orchestrator
        self.sources = sorted({e.source for e in ctx.events})
        self.incident_ids = [i.id for i in ctx.incidents]

    # ---- budget -------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining_seconds(self) -> float:
        return self.budget_seconds - self.elapsed()

    def budget(self) -> dict:
        return {"agents_deployed": self.deployed, "max_agents": self.max_agents,
                "agents_remaining": max(0, self.max_agents - self.deployed),
                "seconds_remaining": max(0, int(self.remaining_seconds())),
                "max_parallel": self.max_parallel}

    def limits(self) -> dict:
        return {"max_agents": self.max_agents, "max_parallel": self.max_parallel,
                "budget_seconds": self.budget_seconds}

    def close(self) -> None:
        """Stop accepting work. Results of a deploy still running (CLI mode, if
        the commander process ended mid-deploy) are discarded, not merged, so
        the orchestrator's state cannot change after the commander stopped."""
        with self._state_lock:
            self.closed = True

    # ---- entry point (in-process for api, via FileDispatchServer for cli) ----
    def handle(self, op: str, args: dict) -> dict:
        if self.closed and op in ("deploy", "finish"):
            return {"error": "the case is closed; no further dispatch calls"}
        if op == "list_roles":
            return {"roles": [{"role": k, "description": d}
                              for k, (_, d) in WORKER_ROLES.items()],
                    "sources": self.sources, "incidents": self.incident_ids,
                    "budget": self.budget()}
        if op == "deploy":
            with self._lock:
                return self._deploy(list(args.get("agents") or []))
        if op == "finish":
            with self._lock:
                self.finished = True
                self.summary = str(args.get("summary") or "").strip()
                self.plan.append({"action": "finish", "t": round(self.elapsed(), 1)})
            return {"closed": True, "budget": self.budget()}
        return {"error": f"unknown dispatch op {op!r}"}

    # ---- deploys ------------------------------------------------------------
    def _refuse(self, items: list, error: str, **extra) -> dict:
        with self._state_lock:
            if not self.closed:
                self.plan.append({"action": "refused", "t": round(self.elapsed(), 1),
                                  "request": items, "error": error})
        return dict({"error": error, "budget": self.budget()}, **extra)

    def _validate(self, item) -> list:
        if not isinstance(item, dict):
            return ["each agent must be an object {role, reason, ...}"]
        problems = []
        role = item.get("role")
        if role not in WORKER_ROLES:
            problems.append(f"unknown role {role!r}; use one of {list(WORKER_ROLES)}")
        if not str(item.get("reason") or "").strip():
            problems.append(f"{role}: give a reason for the deploy")
        if role == "tier1-analyst" and item.get("source") not in self.sources:
            problems.append(f"tier1-analyst needs 'source', one of {self.sources}")
        if role == "investigator" and not str(item.get("objective") or "").strip():
            problems.append("investigator needs an 'objective'")
        inc = item.get("incident_id")
        if inc and inc not in self.incident_ids:
            problems.append(f"unknown incident_id {inc!r}; known: {self.incident_ids}")
        return problems

    def _validate_batch(self, items: list) -> list:
        problems = [p for it in items for p in self._validate(it)]
        if sum(1 for it in items if isinstance(it, dict)
               and it.get("role") == "tier2-verifier") > 1:
            problems.append("deploy at most one tier2-verifier per batch (verdicts "
                            "from parallel verifiers would race)")
        return problems

    def _name(self, base: str) -> str:
        n = self._names.get(base, 0) + 1
        self._names[base] = n
        return base if n == 1 else f"{base}-{n}"

    def _build(self, item: dict):
        role = item["role"]
        cls = WORKER_ROLES[role][0]
        if role == "tier1-analyst":
            agent = cls(item["source"])
            agent.name = self._name(agent.name)
        elif role == "tier2-verifier":
            agent = cls(name=self._name("soc2-lead"))
        elif role == "investigator":
            agent = cls(name=self._name("investigator"))
        else:
            agent = cls(name=self._name(cls.role))
        lines = []
        if item.get("objective"):
            lines.append(f"Direction from the Incident Commander: {item['objective']}")
        if item.get("incident_id"):
            lines.append(f"Focus on incident {item['incident_id']}.")
        agent.directive = "\n".join(lines)
        return agent

    def _scope(self, item: dict) -> list:
        """Incidents a Tier-3 worker's rule fallback works (mirrors the fixed flow)."""
        if item.get("incident_id"):
            return [i for i in self.ctx.incidents if i.id == item["incident_id"]]
        confirmed = self.orch.confirmed_ids()
        dismissed = {f.incident_id for f in self.orch.tier2
                     if f.status == "dismissed" and f.origin == "agent"}
        return [i for i in self.ctx.incidents if i.id in confirmed] or \
               [i for i in self.ctx.incidents if i.id not in dismissed]

    def _run_worker(self, agent, item: dict) -> list:
        # Workers queued behind the parallel cap start later: size each one's
        # timeout from the budget left when it actually starts, and skip it if
        # the wall clock ran out while it waited.
        left = self.remaining_seconds()
        if left < MIN_WORKER_SECONDS or self.closed:
            why = ("the case was closed" if self.closed else
                   "wall-clock budget exhausted before it could start")
            agent.last_run = {"agent": agent.name, "role": agent.role,
                              "tier": agent.tier, "mode": "skipped", "error": why,
                              "findings_filed": 0}
            return []
        agent.timeout = int(max(MIN_WORKER_SECONDS, min(agent.timeout, left)))
        ctx = self.ctx
        if isinstance(agent, SeniorSocAnalyst):
            return agent.verify(ctx, list(self.orch.tier1), use_llm=True,
                                session=self.session)
        if agent.tier == 3:
            ctx = AgentContext(events=ctx.events, incidents=self._scope(item),
                               iocs=ctx.iocs, digest=ctx.digest,
                               intel_store=ctx.intel_store, backbone=ctx.backbone)
        return agent.run(ctx, use_llm=True, session=self.session)

    def _deploy(self, items: list) -> dict:
        if not items:
            return {"error": "nothing to deploy"}
        if self.finished:
            return self._refuse(items, "the case is closed (finish was called); "
                                       "no further deploys")
        if self.remaining_seconds() < MIN_WORKER_SECONDS:
            return self._refuse(items, "wall-clock budget exhausted "
                                       f"({int(self.budget_seconds)}s); call finish")
        problems = self._validate_batch(items)
        if problems:
            return self._refuse(items, "deploy rejected", problems=problems)
        left = self.max_agents - self.deployed
        if len(items) > left:
            return self._refuse(items, f"agent budget exceeded: {self.deployed}/"
                                       f"{self.max_agents} deployed, {left} left, "
                                       f"{len(items)} requested"
                                       + ("; call finish" if left == 0 else ""))
        self.batches += 1
        batch = self.batches
        agents = [self._build(it) for it in items]
        self.deployed += len(agents)
        # Every worker in the batch sees all conclusions filed so far.
        orch = self.orch
        self.session.stage(self.ctx, seed=orch._seed(orch.tier1 + orch.tier2 + orch.tier3))
        with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(agents))) as pool:
            outputs = list(pool.map(lambda pair: self._run_worker(*pair),
                                    zip(agents, items)))

        with self._state_lock:
            if self.closed:
                return {"error": "the case was closed while these agents ran; "
                                 "their results were discarded"}
            return self._merge(batch, agents, items, outputs)

    def _merge(self, batch: int, agents: list, items: list, outputs: list) -> dict:
        orch = self.orch
        results = []
        for agent, item, findings in zip(agents, items, outputs):
            self.workers.append(agent)
            orch._register(agent)
            orch.agent_runs.append(agent.last_run)
            if agent.tier == 1:
                orch.tier1.extend(findings)
            elif agent.tier == 2:
                orch.merge_tier2(findings)
            else:
                orch.tier3.extend(findings)
            results.append(self._result(agent, findings))
            self.plan.append({
                "action": "deploy", "batch": batch, "t": round(self.elapsed(), 1),
                "role": item["role"], "agent": agent.name, "reason": item.get("reason"),
                "objective": item.get("objective"), "incident_id": item.get("incident_id"),
                "source": item.get("source"), "outcome": self._outcome(agent, findings)})
        return {"results": results, "budget": self.budget()}

    @staticmethod
    def _outcome(agent, findings: list) -> str:
        run = agent.last_run or {}
        if agent.tier == 2:
            decided = [f"{f.incident_id} {'confirmed' if f.status == 'escalated' else 'dismissed'}"
                       f" ({f.origin})" for f in findings]
            what = "; ".join(decided) or "no verdicts"
        else:
            what = f"{len(findings)} finding(s)"
        out = f"{run.get('mode', '?')}: {what}"
        if run.get("error"):
            out += f" · error: {run['error'][:120]}"
        return out

    @staticmethod
    def _result(agent, findings: list) -> dict:
        run = agent.last_run or {}
        out = {"agent": agent.name, "role": agent.role, "mode": run.get("mode"),
               "summary": (run.get("summary") or "")[:1500], "error": run.get("error")}
        if agent.tier == 2:
            out["verdicts"] = [{
                "incident_id": f.incident_id,
                "decision": "confirmed" if f.status == "escalated" else "dismissed",
                "decided_by": "agent" if f.origin == "agent" else "rules (agent gave no verdict)",
                "confidence": f.confidence, "rationale": f.rationale[:500],
                "evidence": f.evidence[:10]} for f in findings]
        else:
            out["findings"] = [{
                "id": f.id, "title": f.title, "severity": f.severity,
                "confidence": f.confidence, "incident_id": f.incident_id,
                "origin": f.origin, "attack": f.attack, "evidence": f.evidence[:10],
                "rationale": f.rationale[:500],
                "recommended_action": f.recommended_action} for f in findings]
        return out


class IncidentCommander(AutonomousAgent):
    """Plans and runs the case by deploying worker agents (see module doc)."""
    role = "SOC Lead / Incident Commander"
    tier = 0
    tools = COMMANDER_READ_TOOLS + COMMAND_TOOLS
    default_max_turns = DEFAULT_COMMANDER_TURNS
    mission = "Run the case: decide which agents to deploy, in what order, and when it is done."

    def __init__(self, dispatcher: Dispatcher, **kw):
        super().__init__(name="soc-lead", **kw)
        self.dispatcher = dispatcher
        # The commander's own process must outlive every worker it waits for.
        self.timeout = int(dispatcher.budget_seconds) + 300

    # ---- prompts / tools ----------------------------------------------------
    def system_prompt(self) -> str:
        return COMMANDER_PROTOCOL

    def task(self) -> str:
        return ("A new case has been opened. Plan the investigation, deploy the "
                "agents it needs, follow up on what they report, and finish with "
                "your summary.")

    def make_toolbox(self, session: SwarmSession) -> CommanderToolbox:
        return CommanderToolbox(session.ctx, self.name, self.role, session.board,
                                board_seed=session.seed, tools=self.tools,
                                dispatch=self.dispatcher.handle)

    @property
    def mcp_args(self):
        return ("--commander", "--dispatch-timeout", str(self.timeout))

    @property
    def cli_env(self):
        # Claude Code's MCP client must keep a deploy call open while workers run.
        return {"MCP_TOOL_TIMEOUT": str(self.timeout * 1000)}

    def analyze(self, ctx: AgentContext) -> list:
        return []

    # ---- run ----------------------------------------------------------------
    def command(self, ctx: AgentContext, session: SwarmSession):
        """Run the commander. Returns an error string, or None on a clean run.

        On return the dispatcher is closed: nothing a late worker produces can
        change the orchestrator's state any more."""
        relay = (FileDispatchServer(session.dir, self.dispatcher.handle)
                 if ctx.backbone.resolved == "cli" else None)
        err = None
        try:
            if relay is not None:
                relay.start()
            self.investigate(ctx, session)
        except Exception as exc:
            err = str(exc) if isinstance(exc, RuntimeError) else f"{type(exc).__name__}: {exc}"
            self.last_run = dict(self.last_run or {}, agent=self.name, role=self.role,
                                 tier=self.tier, mode="failed", error=err)
        finally:
            self.dispatcher.close()
            if relay is not None and not relay.stop():
                note = ("a dispatch request was still running when the commander "
                        "stopped; its results were discarded")
                self.last_run = dict(self.last_run or {}, dispatch_warning=note)
        return err or (self.last_run or {}).get("error")
