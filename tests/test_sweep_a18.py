# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-18 regression: usernames and file names that appear in the logs must be
grounded on the AI analyst path, not only on the toolbox path."""
import json

from bastion.agents.analyst import ai_analyze
from bastion.agents.grounding import check_text, evidence_index
from bastion.models import Event


def _ev(**kw):
    base = dict(ts="2026-01-01T00:00:00Z", source="s", category="auth",
                action="login_success", message="login", host="dc01")
    base.update(kw)
    return Event(**base)


def test_user_process_and_file_name_are_grounded():
    ev = _ev(user="john.smith", process="node.js", file_path="C:/x/update.zip")
    res = check_text("key_iocs: john.smith, update.zip, node.js",
                     evidence_index([ev], []))
    assert res["ok"], res["unverified"]


class _Backbone:
    def __init__(self, outs):
        self.outs = list(outs)

    def complete(self, prompt, system=None, max_tokens=0):
        return self.outs.pop(0)


def test_ai_analyze_lead_does_not_flag_logged_names():
    ev = [_ev(user="john.smith", process="node.js", file_path="C:/x/update.zip")]
    lead = json.dumps({"verdict": "needs-review", "confidence": 0.5, "headline": "h",
                       "key_iocs": ["john.smith", "update.zip", "node.js"]})
    reviewer = json.dumps({"agree": True, "corrected_verdict": "needs-review",
                           "confidence": 0.5, "notes": "n"})
    out = ai_analyze(ev, {}, _Backbone([lead, reviewer]))
    assert out["agents"][0]["grounded"] is True
    assert out["lead"]["_grounding"]["unverified"] == {}
