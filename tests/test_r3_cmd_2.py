"""BUG-R3-CMD-2: the fixed fallback after a commander failure must honour the
agents and wall clock the commander left, not run the full roster."""
import time

from bastion.agents import orchestrator
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch


def _boom(body):
    raise RuntimeError("commander backend down")


def test_fallback_respects_max_agents():
    ctx = _ctx()
    model = SwarmModel(ctx, [_boom])
    out = _orch(ctx, model, max_agents=2, budget_seconds=61).run()
    assert out["orchestration"] == "fixed"
    assert len(model.roles_called) <= 2


def test_fallback_skips_specialists_past_deadline(monkeypatch):
    class Clock:
        now = 0.0
        monotonic = staticmethod(lambda: Clock.now)
    ctx = _ctx()
    model = SwarmModel(ctx, [_boom])
    inner = model.messages

    def tick(body):   # each worker's first model call "takes" 30s
        if len(body["messages"]) == 1 and model.script == []:
            Clock.now += 30
        return inner(body)
    model.messages = tick
    monkeypatch.setattr(orchestrator, "time", Clock)
    out = _orch(ctx, model, max_agents=50, budget_seconds=61).run()
    assert len(model.roles_called) < 13
    assert "skipped" in (out["tier3_note"] or "")
