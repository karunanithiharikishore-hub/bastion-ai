# BUG-FEAT-14 / BUG-AGENT-11: an oversized tool result is shrunk by dropping whole
# list items, so it stays valid JSON, every log_data envelope is closed, `returned`
# matches what is shown, a `truncated` note is present, and injection_warning survives.
import copy
import json

import pytest

import bastion.agents.toolbox as toolbox
import bastion.agents.injection as inj
from test_injection import _attack_ctx, _box


def _padded_box(tmp_path, n_pad=300):
    ctx = _attack_ctx(tmp_path)
    base = list(ctx.events)
    pads = []
    for i in range(n_pad):
        c = copy.copy(base[i % len(base)])
        c.message = f"padding event {i} " + "x" * 120
        c.tags = [t for t in c.tags if "inject" not in t]
        pads.append(c)
    ctx.events = base + pads
    return _box(ctx, tmp_path)


def _assert_well_formed(text):
    res = json.loads(text)  # valid JSON, never cut mid-string
    assert text.count("<log_data id=") == text.count("</log_data id=")
    return res


def test_broad_search_keeps_trusted_injection_warning_and_valid_json(tmp_path):
    box = _padded_box(tmp_path)
    text = box.call("search_events", {"limit": 200})
    res = _assert_well_formed(text)
    assert len(text) <= toolbox.MAX_TOOL_RESULT_CHARS
    assert res["injection_warning"]["flagged_events"] >= 1
    assert res["returned"] == len(res["events"]) < 200
    assert "omitted from events" in res["truncated"]


def test_flagged_event_count_is_still_reported_when_its_line_is_dropped(tmp_path, monkeypatch):
    box = _padded_box(tmp_path)
    monkeypatch.setattr(toolbox, "MAX_TOOL_RESULT_CHARS", 1500)
    res = _assert_well_formed(box.call("search_events", {"limit": 200}))
    assert res["injection_warning"]["event_ids"]
    assert res["injection_warning"]["note"] == toolbox.INJECTION_WARNING


@pytest.mark.parametrize("tool, args", [
    ("case_overview", {}),
    ("search_events", {"limit": 200}),
    ("aggregate", {"group_by": "host"}),
])
def test_small_cap_still_yields_valid_json(tmp_path, monkeypatch, tool, args):
    box = _padded_box(tmp_path)
    monkeypatch.setattr(toolbox, "MAX_TOOL_RESULT_CHARS", 900)
    text = box.call(tool, args)
    _assert_well_formed(text)
    assert len(text) <= 900


def test_result_under_cap_is_untouched(tmp_path):
    box = _padded_box(tmp_path)
    res = _assert_well_formed(box.call("search_events", {"limit": 2}))
    assert res["returned"] == 2 and "truncated" not in res
    assert len(res["events"]) == 2


def test_helper_drops_items_and_keeps_warning_without_cutting_text():
    big = {"matches": 500, "returned": 500,
           "events": [f"<log_data id=ab>{'y' * 300}</log_data id=ab>" for _ in range(500)],
           "injection_warning": {"flagged_events": 1, "event_ids": ["e1"], "note": "n"}}
    out = toolbox.SecurityToolbox._fit(big, 2000)
    assert len(json.dumps(out)) <= 2000
    assert out["returned"] == len(out["events"]) < 500
    assert out["injection_warning"] == big["injection_warning"]
    assert all(e.endswith("</log_data id=ab>") for e in out["events"])
