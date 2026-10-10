# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Per-tier budgets and an offline cost plan for one swarm run.

Turn caps are per agent run (one model turn may carry several tool calls).
Tier-1 triage is a narrow job over one source, so it gets the smallest cap;
Tier-2 must record a verdict for every incident; Tier-3 specialists dig deep.

``plan_swarm`` counts, without calling any model, how many ``claude`` processes
a run would start and the maximum number of model turns it may spend, so the
cost of a configuration can be compared before running it.
"""
from __future__ import annotations

# Caps used before the repeatability/cost work, kept for the before/after plan.
LEGACY_TIER_MAX_TURNS = {1: 16, 2: 24, 3: 24}
TIER_MAX_TURNS = {1: 10, 2: 20, 3: 18}

# Cap on the text of one tool result handed back to a model (characters).
MAX_TOOL_RESULT_CHARS = 12000
# read_board returns at most this many of the newest board entries.
MAX_BOARD_ENTRIES = 60


def active_tier1_sources(events, incidents, skip_idle: bool = True):
    """Split log sources into (run, skipped) for Tier-1.

    A source with no event inside any correlated incident is left to the rules
    (``JuniorSocAnalyst.analyze`` only raises candidates from incident events,
    so the rule result for such a source is empty anyway). With no incidents at
    all, Tier-1 is the only first look at every source, so nothing is skipped.
    """
    sources = sorted({e.source for e in events})
    if not skip_idle or not incidents:
        return sources, []
    hot = {e.source for inc in incidents for e in inc.events}
    return [s for s in sources if s in hot], [s for s in sources if s not in hot]


def plan_swarm(events, incidents, *, votes: int = 1, skip_idle_tier1: bool = True,
               tier_turns: dict | None = None, n_specialists: int = 7,
               analyst_calls: int = 2, orchestration: str | None = None,
               commander_limits: dict | None = None) -> dict:
    """Offline estimate for one LLM run (CLI driver).

    processes  : ``claude`` processes started (agents + narrative + analyst calls)
    mcp_servers: Bastion AI MCP server processes (one per CLI agent run)
    max_turns  : upper bound on model turns across all agent runs
    In API mode the same turns run in-process: processes and mcp_servers are 0.

    ``orchestration="commander"``: the Incident Commander decides the workers, so
    the plan is a ceiling from its guardrails (``commander_limits``: max_agents,
    max_commander_turns), assuming every deploy is the most expensive worker and
    every Tier-2 verifier deploy runs ``votes`` times. The fixed-flow estimate is
    included for comparison under ``fixed_flow``.
    """
    if orchestration == "commander":
        return plan_commander(events, incidents, votes=votes, tier_turns=tier_turns,
                              analyst_calls=analyst_calls, **(commander_limits or {}))
    turns = {**TIER_MAX_TURNS, **(tier_turns or {})}
    run, skipped = active_tier1_sources(events, incidents, skip_idle_tier1)
    t2_runs = max(1, votes) if incidents else 0
    t3_runs = n_specialists if events else 0
    agent_runs = len(run) + t2_runs + t3_runs
    narrative = len(incidents)
    return {
        "tier1_agents": len(run), "tier1_skipped": skipped,
        "tier2_runs": t2_runs, "tier3_agents": t3_runs,
        "agent_runs": agent_runs,
        "processes": agent_runs + narrative + (analyst_calls if events else 0),
        "mcp_servers": agent_runs,
        "max_turns": len(run) * turns[1] + t2_runs * turns[2] + t3_runs * turns[3],
        "turn_caps": turns,
    }


def plan_commander(events, incidents, *, votes: int = 1, tier_turns: dict | None = None,
                   analyst_calls: int = 2, max_agents: int = 15,
                   max_commander_turns: int = 30, budget_seconds: float = 3600) -> dict:
    """Ceiling for a commander-led run (see ``plan_swarm``)."""
    turns = {**TIER_MAX_TURNS, **(tier_turns or {})}
    votes = max(1, votes)
    # Worst case per deploy: a Tier-2 verifier voting K times, else a Tier-3 run.
    per_deploy = max(turns[2] * votes, turns[3], turns[1])
    runs_per_deploy = votes if incidents else 1
    agent_runs = 1 + max_agents * runs_per_deploy
    narrative = len(incidents)
    return {
        "orchestration": "commander",
        "commander_turns": max_commander_turns,
        "max_agents": max_agents, "budget_seconds": budget_seconds,
        "agent_runs_max": agent_runs,
        "processes_max": agent_runs + narrative + (analyst_calls if events else 0),
        "mcp_servers_max": agent_runs,
        "max_turns": max_commander_turns + max_agents * per_deploy,
        "turn_caps": dict(turns, commander=max_commander_turns),
        "fixed_flow": plan_swarm(events, incidents, votes=votes, tier_turns=tier_turns,
                                 analyst_calls=analyst_calls),
    }


def plan_before_after(events, incidents, votes: int = 1, commander_limits: dict | None = None) -> dict:
    """The plan for the legacy configuration next to the current one, plus the
    Incident Commander's ceiling (``--orchestration commander``/``auto``)."""
    return {
        "before": plan_swarm(events, incidents, votes=1, skip_idle_tier1=False,
                             tier_turns=LEGACY_TIER_MAX_TURNS),
        "after": plan_swarm(events, incidents, votes=votes),
        "commander_ceiling": plan_commander(events, incidents, votes=votes,
                                            **(commander_limits or {})),
    }
