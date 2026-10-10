# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-10 regression: submit_finding rejects over-long titles and recommended_action
(no silent cut after grounding), and the duplicate check ignores whitespace/case."""
import json

from test_autonomous_agents import _ctx
from bastion.agents.toolbox import Blackboard, SecurityToolbox


def _box(tmp_path):
    ctx = _ctx()
    box = SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))
    return ctx, box


def _finding(ctx, title, **extra):
    return {"title": title, "severity": "low", "confidence": 0.5,
            "rationale": "process seen", "evidence": [ctx.events[0].event_id], **extra}


def test_overlong_title_is_rejected_not_cut(tmp_path):
    ctx, box = _box(tmp_path)
    res = json.loads(box.call("submit_finding", _finding(ctx, "A" * 300)))
    assert res["error"] == "finding rejected"
    assert any("title is 300 chars" in p for p in res["problems"])
    assert box.findings == []


def test_overlong_recommended_action_is_rejected(tmp_path):
    ctx, box = _box(tmp_path)
    res = json.loads(box.call("submit_finding",
                              _finding(ctx, "Odd logon", recommended_action="x" * 100_000)))
    assert res["error"] == "finding rejected"
    assert any(p.startswith("recommended_action is 100000 chars") for p in res["problems"])
    assert box.findings == []


def test_duplicate_check_ignores_whitespace_and_case(tmp_path):
    ctx, box = _box(tmp_path)
    assert json.loads(box.call("submit_finding", _finding(ctx, "Mismatch")))["accepted"]
    for variant in ("Mismatch ", "mismatch", "  MISMATCH   "):
        res = json.loads(box.call("submit_finding", _finding(ctx, variant)))
        assert res["error"] == "duplicate finding", variant
    assert len(box.findings) == 1
