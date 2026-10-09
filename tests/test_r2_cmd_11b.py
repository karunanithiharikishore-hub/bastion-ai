"""BUG-CMD-11 follow-up: the report counts workers apart from the commander, a
discarded commander plan is not shown as the plan that ran, and deploy/refused
plan lines print their own text. No real model calls: scripted fake model only."""
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use, _text
from bluecell.report.render import _render_commander, _render_swarm


def test_report_counts_workers_and_commander_separately():
    ctx = _ctx()
    script = [lambda b: _use("deploy_agent", {"role": "tier2-verifier", "reason": "v"}),
              lambda b: _use("deploy_agent", {"role": "threat-hunter", "reason": "h"}),
              lambda b: _use("finish", {"summary": "s"}),
              lambda b: _text("x")]
    out = _orch(ctx, SwarmModel(ctx, script), max_agents=2).run()
    md = _render_swarm(out)

    assert out["orchestration"] == "commander"
    assert "2 workers + commander" in md
    assert f"Roster ({out['agent_count']} agents)" not in md


def test_fallback_report_omits_discarded_commander_decisions():
    ctx = _ctx()
    script = [lambda b: _use("deploy_agent", {"role": "threat-hunter", "reason": "hunt"}),
              lambda b: _use("finish", {"summary": "s"}),
              lambda b: _text("x")]
    out = _orch(ctx, SwarmModel(ctx, script)).run()
    md = _render_swarm(out)

    assert out["orchestration"] == "fixed"
    assert out["commander"]["plan_discarded"] is True
    assert "Commander not used" in md
    assert "Incident Commander decisions" not in md
    assert "deploy `" not in md


def test_deploy_and_refused_lines_render_their_own_text():
    swarm = {"orchestration": "commander", "commander": {"plan": [
        {"action": "deploy", "agent": "threat-hunter-1", "role": "threat-hunter",
         "source": "edr", "reason": "hunt", "outcome": "autonomous: 1 finding(s)"},
        {"action": "refused", "error": "budget exhausted"},
    ], "summary": "done"}}
    md = "\n".join(_render_commander(swarm))

    assert "1. deploy `threat-hunter-1` (threat-hunter, edr): hunt" in md
    assert "2. deploy refused: budget exhausted" in md
    assert "deploy refused: None" not in md
