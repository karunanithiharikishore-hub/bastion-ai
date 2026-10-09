# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-CMD-3: a large deploy_agents result must stay valid JSON, keep every
worker's status, verdicts and the budget block; trimming is marked."""
import json

from test_autonomous_agents import _ctx
from bluecell.agents.dispatch import CommanderToolbox
from bluecell.agents.budget import MAX_TOOL_RESULT_CHARS


def _batch(n_workers, n_findings, n_verdicts=0):
    results = []
    for k in range(n_workers):
        res = {"agent": f"w{k}", "role": "threat-hunter", "mode": "llm",
               "summary": "s" * 1400, "error": None,
               "findings": [{"id": f"F{k}-{j}", "title": "T" + "t" * 80,
                             "severity": "high", "confidence": 0.7,
                             "incident_id": "INC-1", "origin": "agent", "attack": [],
                             "evidence": [f"e{j}-{i}" for i in range(10)],
                             "rationale": "r" * 500,
                             "recommended_action": "a" * 300}
                            for j in range(n_findings)]}
        if n_verdicts:
            res["verdicts"] = [{"incident_id": f"INC-{j}", "decision": "confirmed",
                                "decided_by": "agent", "votes": None, "confidence": 0.9,
                                "rationale": "r" * 500, "evidence": [f"e{j}"]}
                               for j in range(n_verdicts)]
            del res["findings"]
        results.append(res)
    return {"results": results, "budget": {"agents_left": 3, "budget_seconds_left": 99}}


def _call(out):
    ctx = _ctx()
    box = CommanderToolbox(ctx, "soc-lead", "SOC Lead / Incident Commander", None,
                           tools=("deploy_agents",), dispatch=lambda op, args: out)
    return box.call("deploy_agents", {"agents": [{"role": "threat-hunter", "reason": "r"}]})


def test_large_batch_stays_valid_json_and_keeps_every_worker_and_budget():
    text = _call(_batch(12, 3))
    assert len(text) <= CommanderToolbox.DISPATCH_RESULT_CHARS   # no mid-JSON cut
    got = json.loads(text)                                       # must parse
    assert [r["agent"] for r in got["results"]] == [f"w{k}" for k in range(12)]
    assert all(r["error"] is None and r["mode"] == "llm" for r in got["results"])
    assert got["budget"] == {"agents_left": 3, "budget_seconds_left": 99}
    assert any("trimmed" in r for r in got["results"])            # trimming is marked
    assert "...(truncated" not in text[-200:]                     # no toolbox cut tail


def test_small_batch_is_untouched():
    out = _batch(2, 1)
    got = json.loads(_call(out))
    assert not any("trimmed" in r for r in got["results"])


def test_verdicts_survive_shrinking():
    text = _call(_batch(12, 0, n_verdicts=8))
    assert len(text) <= CommanderToolbox.DISPATCH_RESULT_CHARS
    got = json.loads(text)
    assert all(len(r["verdicts"]) == 8 for r in got["results"])
    assert all(v["decision"] == "confirmed" for r in got["results"] for v in r["verdicts"])
    assert got["budget"]["agents_left"] == 3
