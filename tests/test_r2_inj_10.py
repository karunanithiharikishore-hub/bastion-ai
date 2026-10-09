"""BUG-INJ-10: the Tier-2 verdict guard must not accept a keyword-only or negated
dismissal of an incident that contains a flagged injection attempt."""
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
    "approved maintenance per CHG ticket; not an injection",
    "approved maintenance; no injection here, this is benign",
    "this is a benign prompt injection and nothing more",
    "the injection was not an attack, so dismissing it",
])
def test_negated_or_bare_dismissal_is_rejected(tmp_path, rationale):
    res = _dismissal(tmp_path, rationale)
    assert res.get("error") == "verdict rejected"
    assert any("prompt-injection" in p for p in res["problems"])


def test_dismissal_explaining_injected_text_does_not_change_verdict_is_accepted(tmp_path):
    res = _dismissal(tmp_path, "The injected log text is an attempt to steer the analyst "
                               "and does not change the verdict; the activity is a known scan.")
    assert res.get("accepted") is True
