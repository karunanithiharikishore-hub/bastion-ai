# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-3 regression: submit_finding must reject an incident_id whose events are
not among the cited evidence, the same rule submit_verdict already enforces."""
import json

from test_autonomous_agents import _ctx
from bastion.agents.toolbox import Blackboard, SecurityToolbox
from bastion.pipeline.correlate import Incident


def _two_incident_box(tmp_path):
    ctx = _ctx()
    half = len(ctx.events) // 2
    ctx.incidents[:] = [Incident(id="INC-1", events=ctx.events[:half]),
                        Incident(id="INC-2", events=ctx.events[half:])]
    box = SecurityToolbox(ctx, "t", "Tester", Blackboard(str(tmp_path / "b.jsonl")))
    return ctx, box


def _finding(evidence, incident_id):
    return {"title": "Cross-incident pivot", "severity": "low", "confidence": 0.5,
            "rationale": "process seen", "evidence": evidence, "incident_id": incident_id}


def test_finding_rejects_evidence_outside_its_incident(tmp_path):
    ctx, box = _two_incident_box(tmp_path)
    inc1_event = ctx.incidents[0].events[0].event_id
    res = json.loads(box.call("submit_finding", _finding([inc1_event], "INC-2")))
    assert res["error"] == "finding rejected"
    assert any("cite at least one event_id from INC-2" in p for p in res["problems"])
    assert box.findings == []


def test_finding_accepts_evidence_inside_its_incident(tmp_path):
    ctx, box = _two_incident_box(tmp_path)
    inc2_event = ctx.incidents[1].events[0].event_id
    res = json.loads(box.call("submit_finding", _finding([inc2_event], "INC-2")))
    assert res == {"accepted": True, "findings_filed": 1}
