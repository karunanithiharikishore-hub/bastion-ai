"""ITEM-5: the commander path shrinks --votes K under time pressure; the run must say so."""
import time

from bastion.agents import commander
from test_autonomous_agents import _ctx


class _FakeOrch:
    votes = 3
    tier2 = []
    tier1 = []
    tier3 = []

    def traced_verify(self, agent, ctx, tier1, session=None):
        agent.last_run = {"mode": "autonomous", "summary": "ok"}   # no model call
        return []


def test_r5_commander_vote_shrink_is_recorded_with_a_note():
    ctx = _ctx()
    disp = commander.Dispatcher(_FakeOrch(), ctx, session=None, budget_seconds=600)
    disp.started = time.monotonic() - (600 - 130)                # 130 s left
    agent = commander.SeniorSocAnalyst(name="soc2-lead", votes=3)
    disp._run_worker(agent, {"role": "tier2-verifier", "reason": "r"})
    run = agent.last_run
    assert run["votes_requested"] == 3 and run["votes_effective"] == 2
    assert "3" in run["vote_note"] and "2" in run["vote_note"]
    assert "3 -> 2" in commander.Dispatcher._outcome(agent, [])


def test_r5_no_note_when_votes_are_not_shrunk():
    ctx = _ctx()
    disp = commander.Dispatcher(_FakeOrch(), ctx, session=None, budget_seconds=3600)
    agent = commander.SeniorSocAnalyst(name="soc2-lead", votes=3)
    disp._run_worker(agent, {"role": "tier2-verifier", "reason": "r"})
    assert agent.last_run.get("vote_note") is None
