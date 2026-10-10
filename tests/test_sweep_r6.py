"""ITEM-6: each vote of a Tier-2 verifier is a model run, so it counts against
--max-agents; K is capped at what the agent budget (commander) or the fallback
cap (orchestrator._admit) leaves, and the run records votes_effective + a note."""
from bastion.agents import commander, orchestrator
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use, _text


def _verifier(body):
    return _use("deploy_agents", {"agents": [{"role": "tier2-verifier", "reason": "verify"}]})


def _boom(body):
    raise RuntimeError("commander backend down")


def test_item6_commander_verifier_votes_are_capped_by_max_agents():
    ctx = _ctx()
    model = SwarmModel(ctx, [_verifier, lambda b: _use("finish", {"summary": "s"}),
                             lambda b: _text("ok")])
    out = _orch(ctx, model, max_agents=1, votes=5).run()
    assert model.roles_called.count("Tier-2 SOC Analyst") <= 1
    rec = [r for r in out["agent_runs"] if "votes_requested" in r]
    assert rec and rec[0]["votes_requested"] == 5 and rec[0]["votes_effective"] == 1
    assert "agent budget" in rec[0]["vote_note"]


def test_item6_fallback_admission_takes_one_slot_per_vote():
    ag = orchestrator.SeniorSocAnalyst(name="s", votes=5)
    o = orchestrator.SwarmOrchestrator(_ctx())
    o._cap = {"agents": 2, "deadline": orchestrator.time.monotonic() + 3600}
    assert o._admit(ag)
    assert ag.votes == 2 and o._cap["agents"] == 0
    assert not o._admit(orchestrator.SeniorSocAnalyst(name="t", votes=1))
