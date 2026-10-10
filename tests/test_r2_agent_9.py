"""BUG-AGENT-9: submit_finding / submit_verdict must reject empty or placeholder text,
boolean confidence, exact duplicate findings, and overlong rationales."""
import json

import pytest

from conftest import SAMPLES
from bastion.agents import AgentContext
from bastion.agents.toolbox import BASE_TOOLS, Blackboard, SecurityToolbox
from bastion.ingest import ingest_path
from bastion.pipeline import normalize, map_attack, correlate, extract_iocs, compress

RATIONALE_MAX = 4000  # the cap the bug report asks for


def _box(tmp_path):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    ctx = AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                       iocs=extract_iocs(events), digest=compress(events))
    tools = BASE_TOOLS + ("submit_verdict",)  # Tier-2 toolset
    return ctx, SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")),
                                tools=tools)


def _finding(box, ctx, **over):
    args = {"title": "Suspicious logon", "severity": "medium", "confidence": 0.7,
            "rationale": "seen once", "evidence": [ctx.events[0].event_id]}
    args.update(over)
    return json.loads(box.call("submit_finding", args))


@pytest.mark.parametrize("title", ["", "   ", "None", "null", " NONE ", None, 42])
def test_finding_rejects_empty_or_placeholder_title(tmp_path, title):
    ctx, box = _box(tmp_path)
    res = _finding(box, ctx, title=title)
    assert res["error"] == "finding rejected"
    assert any("title" in p for p in res["problems"])
    assert box.findings == []


@pytest.mark.parametrize("rationale", ["", "  \n", "None", "null", None])
def test_finding_rejects_empty_or_placeholder_rationale(tmp_path, rationale):
    ctx, box = _box(tmp_path)
    res = _finding(box, ctx, rationale=rationale)
    assert res["error"] == "finding rejected"
    assert box.findings == []


def test_verdict_rejects_empty_rationale(tmp_path):
    ctx, box = _box(tmp_path)
    inc = ctx.incidents[0]
    res = json.loads(box.call("submit_verdict", {
        "incident_id": inc.id, "decision": "confirmed", "confidence": 0.9,
        "rationale": "", "evidence": [inc.events[0].event_id]}))
    assert res["error"] == "verdict rejected"
    assert box.verdicts == {}


@pytest.mark.parametrize("confidence", [True, False])
def test_boolean_confidence_is_rejected(tmp_path, confidence):
    ctx, box = _box(tmp_path)
    res = _finding(box, ctx, confidence=confidence)
    assert res["error"] == "finding rejected"
    assert any("confidence" in p for p in res["problems"])
    inc = ctx.incidents[0]
    verdict = json.loads(box.call("submit_verdict", {
        "incident_id": inc.id, "decision": "confirmed", "confidence": confidence,
        "rationale": "real", "evidence": [inc.events[0].event_id]}))
    assert verdict["error"] == "verdict rejected"


def test_exact_duplicate_finding_is_not_filed_twice(tmp_path):
    ctx, box = _box(tmp_path)
    assert _finding(box, ctx).get("accepted") is True
    again = _finding(box, ctx)
    assert again["error"] == "duplicate finding"
    assert "do not resubmit" in again["problems"][0]
    assert len(box.findings) == 1
    assert len(box.board.read()) == 1


def test_same_title_on_a_different_incident_is_not_a_duplicate(tmp_path):
    ctx, box = _box(tmp_path)
    assert _finding(box, ctx).get("accepted") is True
    inc = ctx.incidents[0]
    other = _finding(box, ctx, incident_id=inc.id, evidence=[inc.events[0].event_id])
    assert other.get("accepted") is True
    assert len(box.findings) == 2


def test_rationale_over_the_cap_is_rejected_not_truncated(tmp_path):
    ctx, box = _box(tmp_path)
    res = _finding(box, ctx, rationale="a" * (RATIONALE_MAX + 1))
    assert res["error"] == "finding rejected"
    assert any(f"limit is {RATIONALE_MAX}" in p for p in res["problems"])
    inc = ctx.incidents[0]
    verdict = json.loads(box.call("submit_verdict", {
        "incident_id": inc.id, "decision": "confirmed", "confidence": 0.9,
        "rationale": "a" * (RATIONALE_MAX + 1), "evidence": [inc.events[0].event_id]}))
    assert verdict["error"] == "verdict rejected"
    assert box.findings == [] and box.verdicts == {}


def test_rationale_at_the_cap_is_accepted(tmp_path):
    ctx, box = _box(tmp_path)
    assert _finding(box, ctx, rationale="a" * RATIONALE_MAX).get("accepted") is True
    assert len(box.findings[0]["rationale"]) == RATIONALE_MAX
