# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-6 follow-up: when the commander used up the wall-clock budget, the
fixed fallback must not start a fresh model-agent run."""
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _text, _use


def test_budget_starved_fallback_runs_rules_only():
    ctx = _ctx()
    model = SwarmModel(ctx, [
        lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "verify"}),
        lambda b: _text("gave up")])
    out = _orch(ctx, model, budget_seconds=0).run()
    assert out["orchestration"] == "fixed"
    assert "deployed no agents" in out["commander"]["fallback_reason"]
    assert model.roles_called == []                       # no worker made a model call
    assert all(r.get("mode") != "autonomous" for r in out["agent_runs"])
