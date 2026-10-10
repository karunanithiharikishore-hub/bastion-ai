"""ITEM-13: a usage limit that halted the commander session must stop the
fixed-flow fallback from calling the model again. Fake backbone only."""
from bastion.llm.backbone import BackboneUnavailable
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch


def test_usage_limit_halt_is_not_retried_by_fallback():
    ctx = _ctx()
    calls = []

    class Limited(SwarmModel):
        def messages(self, body):
            calls.append(body["system"][:28])
            raise BackboneUnavailable("API HTTP 429: usage limit reached", status=429)

    model = Limited(ctx, [])
    out = _orch(ctx, model, max_parallel=4).run()
    assert out["orchestration"] == "fixed"
    assert out["commander"]["fallback_reason"]
    assert len(calls) == 1, calls   # the commander only; no doomed Tier-1 calls
