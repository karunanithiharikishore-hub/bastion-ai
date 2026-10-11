"""hunt5 analyzer items 1-3 + quick-mode lows. Fake backbones only."""
import json
import math

from conftest import SAMPLES, BENIGN_SAMPLES
from bastion import analyzer
from bastion.agents.analyst import _extract_json
from test_modes import AnalystBackbone


class Fixed(AnalystBackbone):
    def __init__(self, lead, review=None):
        super().__init__("x")
        self.lead, self.review = lead, {} if review == {} else review or {"agree": True, "confidence": 0.8, "notes": "ok"}

    def complete(self, prompt, system=None, max_tokens=1500):
        self.calls += 1
        return self.lead if max_tokens == 1400 else json.dumps(self.review)


def _top(res):
    return res["incidents"][0]["verdict"]


def test_item1_bare_benign_does_not_overrule_rules():
    res = analyzer.analyze([SAMPLES], backbone=Fixed('{"verdict": "likely-benign"}', {}),
                           mode="quick", trace=False)
    assert _top(res)["level"] == "likely-malicious"


def test_item1_weak_benign_vs_high_rule_needs_review():
    lead = json.dumps({"verdict": "likely-benign", "confidence": 0.6, "headline": "looks routine"})
    res = analyzer.analyze([SAMPLES], backbone=Fixed(lead, {"agree": True, "confidence": 0.6, "notes": "ok"}),
                           mode="quick", trace=False)
    assert _top(res)["level"] == "needs-review"


def test_item3_reviewer_rationale_follows_final_verdict():
    lead = json.dumps({"verdict": "likely-malicious", "confidence": 0.9, "headline": "Attacker stole credentials"})
    rev = {"agree": False, "corrected_verdict": "likely-benign", "confidence": 0.9, "notes": "Scheduled backup job"}
    v = _top(analyzer.analyze([BENIGN_SAMPLES], backbone=Fixed(lead, rev), mode="quick", trace=False))
    assert v["level"] == "likely-benign" and "stole" not in v["why"] and "backup" in v["why"]


def test_item2_nan_never_enters_result():
    assert _extract_json('{"confidence": NaN}') == {"confidence": None}
    res = analyzer.analyze([SAMPLES], backbone=Fixed('{"verdict": "likely-malicious", "headline": "x", "confidence": NaN}'),
                           mode="quick", trace=False)
    json.dumps(res, allow_nan=False)
    assert not math.isnan(_top(res).get("confidence") or 0.0)


def test_quick_cost_plan_is_quick_plan():
    res = analyzer.analyze([SAMPLES], backbone=AnalystBackbone("likely-malicious"), mode="quick", trace=False)
    assert res["meta"]["cost_plan"]["agent_runs"] == 0 and res["meta"]["cost_plan"]["mode"] == "quick"


def test_quick_no_agents_makes_no_model_calls():
    bb = AnalystBackbone("likely-malicious")
    res = analyzer.analyze([SAMPLES], backbone=bb, mode="quick", run_agents=False, trace=False)
    assert bb.calls == 0 and res["ai_analysis"] is None
