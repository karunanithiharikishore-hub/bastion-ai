"""ITEM-14 / ITEM-16: commander Tier-1 retry after a failed run; plan text is capped."""
import json

from bastion.agents import commander
from test_autonomous_agents import _ctx


class _FakeOrch:
    tier1_model = None
    votes = 1

    def __init__(self):
        self.tier1, self.tier2, self.tier3, self.agent_runs = [], [], [], []

    def _register(self, agent):
        pass

    def _seed(self, findings):
        return None

    def merge_tier2(self, findings):
        pass


class _FakeSession:
    def stage(self, ctx, seed=None):
        pass


def _dispatcher(mode):
    ctx = _ctx()
    disp = commander.Dispatcher(_FakeOrch(), ctx, session=_FakeSession(), budget_seconds=3600)

    def fake_run_batch(agents, items):   # no model call: each worker reports `mode`
        for a in agents:
            a.last_run = {"mode": mode, "summary": "", "error": None}
        return [[] for _ in agents]
    disp._run_batch = fake_run_batch
    return disp, ctx.events[0].source


def test_r14_tier1_source_is_redeployable_after_a_fallback_run():
    disp, src = _dispatcher("fallback (rules)")
    first = disp.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": src, "reason": "t"}]})
    assert "error" not in first
    retry = disp.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": src, "reason": "t"}]})
    assert "error" not in retry, retry


def test_r14_tier1_source_stays_refused_after_an_autonomous_run():
    disp, src = _dispatcher("autonomous")
    disp.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": src, "reason": "t"}]})
    retry = disp.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": src, "reason": "t"}]})
    assert "already deployed" in str(retry.get("problems"))


def test_r16_plan_caps_reason_and_objective():
    disp, src = _dispatcher("autonomous")
    big = "word " * 40000   # ~200 KB of commander text
    disp.handle("deploy", {"agents": [{"role": "tier1-analyst", "source": src, "reason": big}]})
    step = [p for p in disp.plan if p["action"] == "deploy"][0]
    assert len(step["reason"]) < 1000


def test_r16_refused_request_is_capped_in_the_plan():
    disp, src = _dispatcher("autonomous")
    big = "word " * 40000
    disp.handle("deploy", {"agents": [{"role": "bogus", "reason": big, "objective": big}]})
    step = [p for p in disp.plan if p["action"] == "refused"][0]
    assert len(json.dumps(step)) < 5000
