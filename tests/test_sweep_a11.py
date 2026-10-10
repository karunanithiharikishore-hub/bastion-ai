# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-11 regression: a dismissed verdict never records an explicit severity above
low, so it cannot raise the tied-severity vote in voting.py."""
import json

from test_autonomous_agents import _box
from bastion.agents.toolbox import Blackboard, SecurityToolbox
from bastion.agents.roles import SeniorSocAnalyst


def test_dismissed_verdict_ignores_explicit_critical_severity(tmp_path):
    ctx, box = _box(tmp_path)
    inc = ctx.incidents[0]
    t2 = SecurityToolbox(ctx, "soc2-lead", "Tier-2", box.board, tools=SeniorSocAnalyst.tools)
    res = json.loads(t2.call("submit_verdict", {
        "incident_id": inc.id, "decision": "dismissed", "confidence": 0.8,
        "severity": "critical", "rationale": "benign admin activity",
        "evidence": [inc.events[0].event_id]}))
    assert res.get("accepted"), res
    assert t2.verdicts[inc.id]["severity"] == "low"
