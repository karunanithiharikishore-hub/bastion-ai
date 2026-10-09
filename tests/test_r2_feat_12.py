# BUG-FEAT-12: a split Tier-2 vote must be flagged needs_review even when the
# incident has no Tier-1 candidate, exactly as when candidates exist.
from test_repeatability import VotingModel, _ctx

from bluecell.agents import SwarmOrchestrator
from bluecell.agents.roles import SeniorSocAnalyst
from bluecell.agents.runtime import SwarmSession


def _split_without_candidates():
    ctx = _ctx()
    inc = ctx.incidents[0]
    ctx.backbone = VotingModel(ctx.incidents, ["confirmed", "dismissed"])
    session = SwarmSession(ctx, seed=SwarmOrchestrator._seed([]))
    try:
        senior = SeniorSocAnalyst(name="soc2-lead", votes=2)
        found = senior.verify(ctx, [], use_llm=True, session=session)
    finally:
        session.close()
    return inc, found


def test_split_vote_without_tier1_candidates_is_flagged_for_review():
    inc, found = _split_without_candidates()
    f = next(f for f in found if f.incident_id == inc.id)
    assert f.origin == "rules" and f.tier == 2
    assert f.votes["needs_review"] is True
    assert f.votes["confirmed"] == 1 and f.votes["dismissed"] == 1
    assert f.confidence <= SeniorSocAnalyst.SPLIT_VOTE_MAX_CONFIDENCE
    assert "split Tier-2 vote" in f.title
