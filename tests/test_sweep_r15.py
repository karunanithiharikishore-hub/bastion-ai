# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-15: a batch with many verdicts must reach the commander with every worker
in ``results`` (degraded, never emptied), and say how many verdicts it did not show."""
import json

from test_autonomous_agents import _ctx
from bluecell.agents.dispatch import CommanderToolbox


def _verdicts(n, worker):
    return [{"incident_id": f"INC-{worker}-{i:04d}", "decision": "confirmed",
             "decided_by": "agent", "votes": None, "confidence": 0.9,
             "rationale": "r" * 500, "evidence": [f"e{i}-{k}" for k in range(10)]}
            for i in range(n)]


def _call(out):
    box = CommanderToolbox(_ctx(), "soc-lead", "SOC Lead / Incident Commander", None,
                           tools=("deploy_agents",), dispatch=lambda op, args: out)
    return box.call("deploy_agents", {"agents": [{"role": "tier2-verifier", "reason": "r"}]})


def test_verdicts_beyond_the_cap_are_degraded_not_dropped():
    out = {"results": [{"agent": "soc2-lead", "role": "Tier-2", "summary": "s", "error": None,
                        "verdicts": _verdicts(2500, "a")}],
           "budget": {"agents_left": 3}}
    text = _call(out)
    assert len(text) <= CommanderToolbox.DISPATCH_RESULT_CHARS
    got = json.loads(text)
    assert [r["agent"] for r in got["results"]] == ["soc2-lead"]    # worker not dropped
    shown = got["results"][0]["verdicts"]
    assert 0 < len(shown) < 2500
    assert shown[0] == {"incident_id": "INC-a-0000", "decision": "confirmed",
                        "confidence": 0.9}                           # ids and scores kept
    assert len(shown) + got["results"][0]["more"]["verdicts"] == 2500  # the count says what is cut
    assert got["budget"] == {"agents_left": 3}


def test_many_workers_with_verdicts_all_stay_in_results():
    out = {"results": [{"agent": f"w{k}", "role": "Tier-2", "summary": "s", "error": None,
                        "verdicts": _verdicts(300, k)} for k in range(40)],
           "budget": {"agents_left": 1}}
    text = _call(out)
    assert len(text) <= CommanderToolbox.DISPATCH_RESULT_CHARS
    got = json.loads(text)
    assert [r["agent"] for r in got["results"]] == [f"w{k}" for k in range(40)]
    assert all(r["verdicts"] for r in got["results"])
