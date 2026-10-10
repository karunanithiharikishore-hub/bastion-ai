# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-12 regression: the verdict guard for dismissing an injection-flagged case must
not accept keyword salad. The rationale has to say the injected text is ignored or does
not change the call, not merely contain 'injection' and 'attacker'."""
import json

import pytest

from test_injection import _attack_ctx, _box
import bluecell.agents.injection as inj


def _dismissal(tmp_path, rationale):
    ctx = _attack_ctx(tmp_path)
    box = _box(ctx, tmp_path)
    inc = next(i for i in ctx.incidents if any(inj.is_flagged(e) for e in i.events))
    flagged = [e.event_id for e in inc.events if inj.is_flagged(e)]
    args = {"incident_id": inc.id, "decision": "dismissed", "confidence": 0.8,
            "rationale": rationale, "evidence": [flagged[0]]}
    return json.loads(box.call("submit_verdict", args))


@pytest.mark.parametrize("rationale", [
    "No process injection here; attacker absent. Routine admin.",
    "SQL injection scan noise; attacker absent, routine admin.",
    "Injection noise. Attacker absent, routine admin, steering nothing.",
    "Injection text present; regardless, routine admin with no attacker.",
])
def test_keyword_salad_dismissal_is_rejected(tmp_path, rationale):
    res = _dismissal(tmp_path, rationale)
    assert res.get("error") == "verdict rejected", res
    assert any("prompt-injection" in p for p in res["problems"])


def test_dismissal_saying_injected_text_is_ignored_is_accepted(tmp_path):
    res = _dismissal(tmp_path, "The injected text asks to dismiss; I ignored it and the "
                               "activity is a known scan.")
    assert res.get("accepted") is True, res
