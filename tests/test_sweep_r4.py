"""ITEM-4: a later, weaker verifier deploy must not override an earlier majority
verdict. Pure merge_tier2 calls; no model is involved."""
from test_autonomous_agents import _ctx
from bastion.agents import SwarmOrchestrator
from bastion.agents.base import Finding


def _verdict(status: str, completed: int) -> Finding:
    return Finding(agent="Senior SOC analyst", role="tier2-verifier", tier=2,
                   title="verdict", severity="high", confidence=0.9, rationale="r",
                   incident_id="INC-1", status=status, origin="agent",
                   votes={"k": 3, "completed": completed,
                          "confirmed": completed if status == "escalated" else 0,
                          "dismissed": completed if status == "dismissed" else 0})


def test_weaker_later_verdict_does_not_flip_majority():
    o = SwarmOrchestrator(_ctx())
    o.tier2 = [_verdict("escalated", 3)]           # earlier 3-0 confirmed
    o.merge_tier2([_verdict("dismissed", 1)])      # later 1-vote re-deploy disagrees
    assert [f.status for f in o.tier2] == ["escalated"]
    assert o.tier2[0].votes["needs_review"] is True


def test_stronger_later_verdict_replaces_and_is_flagged():
    o = SwarmOrchestrator(_ctx())
    o.tier2 = [_verdict("dismissed", 1)]
    o.merge_tier2([_verdict("escalated", 3)])
    assert [f.status for f in o.tier2] == ["escalated"]
    assert o.tier2[0].votes["needs_review"] is True
