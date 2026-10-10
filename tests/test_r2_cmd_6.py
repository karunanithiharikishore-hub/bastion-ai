# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-6: a wall-clock budget too small to start one worker is refused
(CLI and commander), and a fallback caused by the budget says it ran unbounded.
"""
import pytest

from bastion.agents import AgentContext
from bastion.agents.commander import Dispatcher
from bastion.agents.runtime import SwarmSession
from bastion.cli import build_parser

from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _text, _use


@pytest.mark.parametrize("value", ["30", "60"])
def test_cli_rejects_budget_that_cannot_start_a_worker(value, capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["analyze", "x", "--budget-seconds", value])
    assert "must be more than 60" in capsys.readouterr().err


def test_cli_accepts_budget_above_worker_minimum():
    args = build_parser().parse_args(["analyze", "x", "--budget-seconds", "61"])
    assert args.budget_seconds == 61


def test_commander_refuses_budget_too_small_at_construction():
    ctx = _ctx()
    session = SwarmSession(ctx, seed=[])
    try:
        from bastion.agents import SwarmOrchestrator
        orch = SwarmOrchestrator(ctx, orchestration="commander")
        with pytest.raises(ValueError, match="too small"):
            Dispatcher(orch, ctx, session, budget_seconds=30)
        Dispatcher(orch, ctx, session, budget_seconds=0)   # no time at all is still allowed
    finally:
        session.close()


def test_budget_starved_fallback_says_it_ran_without_a_budget():
    ctx = _ctx()
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify"}),
        lambda b: _text("gave up")])
    out = _orch(ctx, model, budget_seconds=0).run()
    assert out["orchestration"] == "fixed"
    reason = out["commander"]["fallback_reason"]
    assert "deployed no agents" in reason
    assert "fixed fallback ran on the rules only, with no model agents" in reason


def test_other_fallbacks_do_not_claim_missing_budget():
    ctx = _ctx()
    model = SwarmModel(ctx, [lambda b: _use("list_roles", {})] * 10)
    out = _orch(ctx, model, max_commander_turns=3).run()
    assert out["orchestration"] == "fixed"
    assert "rules only" not in out["commander"]["fallback_reason"]
