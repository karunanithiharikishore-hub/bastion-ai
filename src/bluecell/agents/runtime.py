# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Autonomous agent runtime for every tier of the swarm.

Each agent (Tier-1 triage, Tier-2 verification, Tier-3 specialists) is a real
tool-using agent: the model is given a mission, a
persona and the investigation toolbox, and it runs its own loop — decide what
to look at, call a tool, read the result, follow the lead, coordinate with the
other agents on the shared board, and file evidence-checked findings. Python
does not decide what the agent concludes; it only executes tool calls and
rejects findings that are not backed by the logs.

Two drivers, matching the backbone:
- cli : each agent is its own ``claude -p`` process with BlueCell's tools served
        over MCP (``mcp_server.py``) and every built-in tool disabled. Keyless.
- api : native Anthropic tool use, looped in-process.

If no backbone is available, or the agent process fails, the agent falls back
to its rule-based logic and the run record says so.
"""
from __future__ import annotations

import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile

from .base import Agent, AgentContext, Finding
from .toolbox import Blackboard, SecurityToolbox, BASE_TOOLS, file_slug

MCP_SERVER = "bluecell"
DEFAULT_MAX_TURNS = 24
DEFAULT_TIMEOUT = 900   # seconds per agent

_SRC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OPERATING_PROTOCOL = """\
You are working a live case inside BlueCell, alongside other blue-team agents.
You can only see the evidence through your tools; you have no other access.

How to work:
1. Call case_overview, then read_board to see what the other agents have found.
2. Investigate like a practitioner: form a hypothesis, pull the events that would
   prove or disprove it (search_events, get_incident, pivot, get_event,
   aggregate, attack_lookup, list_iocs, intel_search), and follow the leads you
   find. Look beyond the correlated incidents when your role calls for it.
3. When you find something another agent should chase, post_note it.
4. File each conclusion with your submit tool (submit_finding, or submit_verdict
   if you have it), citing the event_ids that prove it. If it is rejected, read
   the problems, fix them, and resubmit. File only what the evidence supports;
   one strong finding beats five weak ones. If you find nothing worth filing in
   your area, file nothing and say so.
5. Finish with a short plain-text summary of what you concluded and why.

Ground rules: every claim must be backed by events you actually retrieved.
Never invent hosts, IPs, domains, hashes, users, timestamps or ATT&CK techniques.
Where the logs do not establish something, say "not proven by the available
logs". You are read-only: you analyze and recommend; you never act on systems.
"""


def build_system_prompt(role: str, mission: str) -> str:
    return f"You are the {role} on a blue team.\n\n{mission.strip()}\n\n{OPERATING_PROTOCOL}"


def task_prompt(agent_name: str, role: str) -> str:
    return (f"You are agent '{agent_name}' ({role}). A new case has been opened. "
            "Investigate it within your specialty using your tools, file your "
            "findings, then give your summary.")


# ---------------------------------------------------------------------------
# Session: shared state for one swarm run (pickled context + shared board)
# ---------------------------------------------------------------------------
class SwarmSession:
    """One swarm run. The board persists across tiers; ``stage`` swaps in the
    context and seed for the next tier (tiers run one after another)."""

    def __init__(self, ctx: AgentContext, seed: list):
        self.dir = tempfile.mkdtemp(prefix="bluecell-swarm-")
        self.board = Blackboard(os.path.join(self.dir, "board.jsonl"))
        self.stage(ctx, seed)

    def stage(self, ctx: AgentContext, seed: list) -> None:
        self.seed = seed
        self.ctx = ctx
        shared = AgentContext(events=ctx.events, incidents=ctx.incidents,
                              iocs=ctx.iocs, digest=ctx.digest,
                              intel_store=ctx.intel_store, backbone=None)
        # Atomic: an MCP server starting right now reads the old or the new
        # context, never a half-written pickle.
        path = os.path.join(self.dir, "ctx.pkl")
        with open(path + ".tmp", "wb") as fh:
            pickle.dump({"ctx": shared, "seed": seed}, fh)
        os.replace(path + ".tmp", path)

    def close(self) -> None:
        if not os.environ.get("BLUECELL_KEEP_SESSION"):
            shutil.rmtree(self.dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
def _run_cli(agent, session: SwarmSession, backbone, max_turns: int,
             timeout: int) -> dict:
    cfg = {"mcpServers": {MCP_SERVER: {
        "command": sys.executable,
        "args": ["-m", "bluecell.agents.mcp_server", "--session", session.dir,
                 "--agent", agent.name, "--role", agent.role,
                 "--tools", ",".join(agent.tools)]
                + (["--source-scope", agent.source_scope] if agent.source_scope else [])
                + list(agent.mcp_args),
        "env": {"PYTHONPATH": _SRC_ROOT},
    }}}
    cfg_path = os.path.join(session.dir, f"{file_slug(agent.name)}.mcp.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)

    allowed = ",".join(f"mcp__{MCP_SERVER}__{n}" for n in agent.tools)
    cmd = ["claude", "-p",
           "--model", backbone.model,
           "--system-prompt", agent.system_prompt(),
           "--mcp-config", cfg_path, "--strict-mcp-config",
           "--tools", "",
           "--allowedTools", allowed,
           "--setting-sources", "project",
           "--max-turns", str(max_turns),
           "--no-session-persistence",
           "--output-format", "stream-json", "--verbose"]
    out_path = os.path.join(session.dir, f"{file_slug(agent.name)}.out.json")
    error = None
    summary, turns, cost = "", None, None
    try:
        # cwd = session dir: no project settings/hooks/CLAUDE.md leak into the agent.
        proc = subprocess.run(cmd, input=agent.task(),
                              capture_output=True, text=True, timeout=timeout,
                              cwd=session.dir,
                              env=dict(os.environ, **agent.cli_env) if agent.cli_env else None)
        for line in proc.stdout.splitlines():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("type") == "result":
                summary = msg.get("result") or ""
                turns = msg.get("num_turns")
                cost = msg.get("total_cost_usd")
                if msg.get("is_error") and msg.get("subtype") != "error_max_turns":
                    error = f"agent ended with {msg.get('subtype')}: {summary[:200]}"
        if proc.returncode != 0 and not summary:
            error = f"claude exited {proc.returncode}: {proc.stderr.strip()[:300]}"
    except (subprocess.TimeoutExpired, OSError) as exc:
        error = f"{type(exc).__name__}: {exc}"

    result = {"findings": [], "verdicts": [], "calls": []}
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8") as fh:
            result = json.load(fh)
    if not result["calls"] and error is None:
        error = "agent made no tool calls (MCP server may have failed to start)"
    return {"findings": result["findings"], "verdicts": result.get("verdicts", []),
            "calls": result["calls"],
            "summary": summary.strip(), "turns": turns, "cost_usd": cost,
            "error": error}


def _run_api(agent, session: SwarmSession, backbone, max_turns: int,
             timeout: int) -> dict:
    box = agent.make_toolbox(session)
    tools = [{"name": t["name"], "description": t["description"],
              "input_schema": t["input_schema"]} for t in box.specs()]
    system = agent.system_prompt()
    messages = [{"role": "user", "content": agent.task()}]
    summary, error, turns = "", None, 0
    try:
        while turns < max_turns:
            turns += 1
            payload = backbone.messages({
                "model": backbone.model, "max_tokens": 4000, "system": system,
                "tools": tools, "messages": messages,
            })
            content = payload.get("content", [])
            messages.append({"role": "assistant", "content": content})
            uses = [c for c in content if c.get("type") == "tool_use"]
            if not uses:
                summary = "".join(c.get("text", "") for c in content
                                  if c.get("type") == "text")
                break
            results = []
            for u in uses:
                text = box.call(u["name"], u.get("input") or {})
                results.append({"type": "tool_result", "tool_use_id": u["id"],
                                "content": text,
                                "is_error": text.startswith('{"error"')})
            messages.append({"role": "user", "content": results})
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return {"findings": box.findings, "verdicts": list(box.verdicts.values()),
            "calls": box.calls, "summary": summary.strip(),
            "turns": turns, "cost_usd": None, "error": error}


# ---------------------------------------------------------------------------
# Agent base class
# ---------------------------------------------------------------------------
class AutonomousAgent(Agent):
    """An agent that investigates autonomously when a model is available, and
    falls back to its rule-based ``analyze`` when not."""

    mission = ""
    tools = BASE_TOOLS
    source_scope = None
    default_max_turns = DEFAULT_MAX_TURNS
    directive = ""          # extra instructions (e.g. from the Incident Commander)
    mcp_args = ()           # extra mcp_server arguments (CLI driver)
    cli_env = None          # extra environment for the `claude` process (CLI driver)

    def __init__(self, *a, max_turns: int | None = None,
                 timeout: int = DEFAULT_TIMEOUT, **kw):
        super().__init__(*a, **kw)
        self.max_turns = max_turns or self.default_max_turns
        self.timeout = timeout
        self.last_run: dict = {}
        self.verdicts: list = []          # Tier-2 submit_verdict results

    def brief(self) -> str:
        return self.mission

    def system_prompt(self) -> str:
        mission = self.brief()
        if self.directive:
            mission = f"{mission.rstrip()}\n\n{self.directive.strip()}"
        return build_system_prompt(self.role, mission)

    def task(self) -> str:
        return task_prompt(self.name, self.role)

    def make_toolbox(self, session: SwarmSession) -> SecurityToolbox:
        """The in-process toolbox the API driver executes this agent's calls on."""
        return SecurityToolbox(session.ctx, self.name, self.role, session.board,
                               board_seed=session.seed, tools=self.tools,
                               source_scope=self.source_scope)

    def investigate(self, ctx: AgentContext, session: SwarmSession) -> list:
        backbone = ctx.backbone
        driver = _run_cli if backbone.resolved == "cli" else _run_api
        run = driver(self, session, backbone, self.max_turns, self.timeout)
        findings = [Finding(agent=self.name, role=self.role, tier=self.tier,
                            title=f["title"], severity=f["severity"],
                            confidence=f["confidence"], rationale=f["rationale"],
                            incident_id=f.get("incident_id"), attack=f.get("attack") or [],
                            evidence=f["evidence"],
                            recommended_action=f.get("recommended_action"),
                            status="proposed", origin="agent")
                    for f in run["findings"]]
        self.verdicts = run["verdicts"]
        self.last_run = {
            "agent": self.name, "role": self.role, "tier": self.tier,
            "mode": "autonomous", "backbone": backbone.resolved, "model": backbone.model,
            "turns": run["turns"], "tool_calls": len(run["calls"]),
            "tools_used": sorted({c["tool"] for c in run["calls"]}),
            "rejected_submissions": sum(1 for c in run["calls"]
                                        if c["tool"].startswith("submit_") and not c["ok"]),
            "findings_filed": len(findings) + len(self.verdicts),
            "summary": run["summary"],
            "cost_usd": run["cost_usd"], "error": run["error"],
            "trace": run["calls"],
        }
        if run["error"] and not findings and not self.verdicts:
            raise RuntimeError(run["error"])
        return findings

    def _rules(self, ctx: AgentContext, mode: str, error=None) -> list:
        findings = self.analyze(ctx) or []
        self.last_run = dict(self.last_run or {}, agent=self.name, role=self.role,
                             tier=self.tier, mode=mode, error=error,
                             findings_filed=len(findings))
        return findings

    def run(self, ctx: AgentContext, use_llm: bool = True,
            session: SwarmSession | None = None) -> list:
        if use_llm and ctx.backbone is not None and session is not None and self.mission:
            try:
                return self.investigate(ctx, session)
            except Exception as exc:
                reason = str(exc) if isinstance(exc, RuntimeError) else f"{type(exc).__name__}: {exc}"
                return self._rules(ctx, "fallback (rules)", reason)
        return self._rules(ctx, "rules")
