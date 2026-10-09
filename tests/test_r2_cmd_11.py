"""BUG-CMD-11: the commander is counted apart from its workers, and a fallback
to the fixed flow does not present the discarded commander decisions as the
plan that ran. No real model calls: scripted fake model only."""
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use, _text, COMMANDER


def test_commander_run_counts_workers_apart_from_commander():
    ctx = _ctx()
    script = [lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "v"}),
              lambda b: _use("deploy_agent", {"role": "threat-hunter", "reason": "h"}),
              lambda b: _use("finish", {"summary": "s"}),
              lambda b: _text("x")]
    out = _orch(ctx, SwarmModel(ctx, script), max_agents=2).run()

    assert out["orchestration"] == "commander"
    assert out["commander"]["agents_deployed"] == 2
    assert out["worker_count"] == 2
    assert out["orchestrator"] == {"name": "soc-lead", "role": COMMANDER, "tier": 0}
    assert out["agent_count"] == out["worker_count"] + 1


def test_fallback_discards_commander_decisions_from_plan():
    ctx = _ctx()
    script = [lambda b: _use("deploy_agent", {"role": "threat-hunter", "reason": "hunt"}),
              lambda b: _use("finish", {"summary": "s"}),
              lambda b: _text("x")]
    out = _orch(ctx, SwarmModel(ctx, script)).run()

    assert out["orchestration"] == "fixed"
    assert out["orchestrator"] is None
    assert out["worker_count"] == len(out["roster"])
    cmd = out["commander"]
    assert cmd["fallback_reason"]
    assert cmd["plan_discarded"] is True
    assert [p["action"] for p in cmd["plan"]] == ["deploy", "finish"]
