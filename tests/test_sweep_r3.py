"""ITEM-3: agreement and majority must be measured against the votes requested,
so a lone surviving Tier-2 run cannot decide an incident at full agreement."""
from bluecell.agents.voting import tally


def _v(decision, conf=0.9):
    return {"incident_id": "I", "decision": decision, "confidence": conf,
            "severity": "high", "rationale": decision, "evidence": ["e"],
            "reviewed_candidates": []}


def test_lone_surviving_vote_of_three_is_a_split():
    res = tally([{"I": _v("confirmed")}, None, None], ["I"])["I"]
    assert res["outcome"] == "split" and res["verdict"] is None
    assert res["votes"]["agreement"] == round(1 / 3, 2)


def test_two_of_three_with_one_failure_scales_by_requested():
    res = tally([{"I": _v("confirmed", 0.9)}, {"I": _v("confirmed", 0.9)}, None], ["I"])["I"]
    assert res["outcome"] == "majority" and res["decision"] == "confirmed"
    assert res["votes"]["agreement"] == round(2 / 3, 2)
    assert res["verdict"]["confidence"] == round(0.9 * 2 / 3, 2)


def test_unanimous_two_of_two_still_full_agreement():
    res = tally([{"I": _v("dismissed", 0.8)}, {"I": _v("dismissed", 0.8)}], ["I"])["I"]
    assert res["outcome"] == "majority" and res["votes"]["agreement"] == 1.0
    assert res["verdict"]["confidence"] == 0.8
