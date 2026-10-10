# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-14: runs chart must not say 'rules-only' when runs had unknown-cost LLM calls; unknown bars differ from $0 bars."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

RUNS_JS = Path(__file__).resolve().parents[1] / "src/bastion/web/static/runs.js"
HARNESS = """
const els = {};
globalThis.document = { getElementById(id) {
  return els[id] || (els[id] = { innerHTML: "", textContent: "", className: "", addEventListener() {} });
} };
"""


def _render(runs):
    script = (HARNESS + RUNS_JS.read_text() +
              f"\nRUNS = {json.dumps(runs)};\nrenderChart();\n"
              "console.log(JSON.stringify({sub: els['chart-sub'].textContent, svg: els['chart-body'].innerHTML}));\n")
    res = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=20)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    classes = re.findall(r'<rect class="([^"]*)"([^>]*)>', out["svg"])
    return out["sub"], classes


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_unknown_cost_run_not_called_rules_only_and_drawn_distinct():
    sub, bars = _render([{"started": "2026-01-01T00:00:00", "total_cost_usd": None,
                          "cost_unknown_calls": 3, "llm_calls": 3}])
    assert sub == "1 run(s) with unknown cost"
    assert "rules-only" not in sub
    cls, attrs = bars[0]
    assert "unknown" in cls and "dasharray" in attrs


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_genuine_zero_cost_run_still_rules_only():
    sub, bars = _render([{"started": "2026-01-01T00:00:00", "total_cost_usd": 0.0,
                          "cost_unknown_calls": 0, "llm_calls": 0}])
    assert sub == "no LLM spend recorded (rules-only runs)"
    assert bars[0][0] == "bar zero" and "dasharray" not in bars[0][1]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_mixed_known_and_unknown_runs():
    sub, _ = _render([{"started": "2026-01-01T00:00:00", "total_cost_usd": 0.5, "cost_unknown_calls": 0},
                      {"started": "2026-01-02T00:00:00", "total_cost_usd": None, "cost_unknown_calls": 2}])
    assert sub == "max $0.5000 per run · 1 run(s) with unknown cost"
