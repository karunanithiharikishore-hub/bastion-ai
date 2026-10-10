# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
# ITEM-23: Tier-2 verdicts beyond the cap must be noted, not silently dropped.
# ITEM-24: reviewer grounding detail must be kept, not reduced to a boolean.
import json

from bastion.agents.analyst import ai_analyze


class _Backbone:
    def __init__(self, *outs):
        self.outs = list(outs)
        self.prompts = []

    def complete(self, prompt, system=None, max_tokens=0):
        self.prompts.append(prompt)
        return self.outs.pop(0)


def _verdicts(n):
    return [{"incident_id": f"INC-{i}", "status": "dismissed", "confidence": 0.5,
             "rationale": "r", "evidence": []} for i in range(n)]


def test_tier2_overflow_is_noted_and_true_count_reported():
    bb = _Backbone(json.dumps({"verdict": "needs-review"}),
                   json.dumps({"corrected_verdict": "needs-review"}))
    out = ai_analyze([], {}, bb, tier2_verdicts=_verdicts(8))
    assert out["tier2_verdicts_seen"] == 8
    assert "+3 more" in bb.prompts[0]


def test_tier2_within_cap_has_no_overflow_note():
    bb = _Backbone(json.dumps({"verdict": "needs-review"}),
                   json.dumps({"corrected_verdict": "needs-review"}))
    out = ai_analyze([], {}, bb, tier2_verdicts=_verdicts(2))
    assert out["tier2_verdicts_seen"] == 2
    assert "more not shown" not in bb.prompts[0]


def test_reviewer_grounding_detail_is_kept():
    bb = _Backbone(json.dumps({"verdict": "needs-review"}),
                   json.dumps({"corrected_verdict": "needs-review",
                               "notes": "saw 8.8.8.8 and evil.ru"}))
    out = ai_analyze([], {}, bb)
    assert out["agents"][1]["grounded"] is False
    assert out["review"]["_grounding"]["ok"] is False
    assert "8.8.8.8" in out["review"]["_grounding"]["unverified"]["ips"]
    assert "evil.ru" in out["review"]["_grounding"]["unverified"]["domains"]
