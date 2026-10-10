# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
# ITEM-22: unknown or malformed verdicts must become needs-review, never a final_verdict string.
import json

import pytest

from bastion.agents.analyst import ai_analyze, _norm_verdict


class _Backbone:
    def __init__(self, *outs):
        self.outs = list(outs)

    def complete(self, prompt, system=None, max_tokens=0):
        return self.outs.pop(0)


@pytest.mark.parametrize("bad", [
    "malicious", "true-positive", "true positive", ["likely-benign"], {"a": -1}, 5,
])
def test_unknown_lead_verdict_becomes_needs_review(bad):
    out = ai_analyze([], {}, _Backbone(json.dumps({"verdict": bad})), want_review=False)
    assert out["final_verdict"] == "needs-review"


@pytest.mark.parametrize("bad", ["malicious", "['likely-benign']", "true positive"])
def test_unknown_reviewer_verdict_becomes_needs_review(bad):
    lead = json.dumps({"verdict": "likely-malicious"})
    out = ai_analyze([], {}, _Backbone(lead, json.dumps({"corrected_verdict": bad})))
    assert out["final_verdict"] == "needs-review"


def test_norm_verdict_still_folds_spelling_and_keeps_none():
    assert _norm_verdict("Likely Benign.") == "likely-benign"
    assert _norm_verdict(None) is None
