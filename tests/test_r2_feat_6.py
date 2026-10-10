"""BUG-FEAT-6: unknown cost must stay unknown (None / n/a), never a fake 0.0000."""
import shutil
import subprocess
from pathlib import Path

import pytest

from bastion import tracing

USAGE = {"input_tokens": 1000, "output_tokens": 1000}
ROOT = Path(__file__).resolve().parent.parent


def test_all_unknown_run_total_is_none_not_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    s = t.summary()
    assert s["total_cost_usd"] is None
    assert s["cost_basis"] == ["unknown"] and s["cost_unknown_calls"] == 1


def test_mixed_run_is_partial_sum_with_unknown_count(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    t.record_usage(USAGE, model="claude-haiku-5-5")
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    s = t.summary()
    assert s["total_cost_usd"] == pytest.approx(tracing.estimate_cost(USAGE, "claude-haiku-5-5"))
    assert s["cost_unknown_calls"] == 1 and s["cost_estimated"] is True


def test_per_agent_unknown_cost_is_none_and_no_llm_calls_stay_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    with t.open("agent-x", "agent", agent="x") as sp:
        t.record_usage(None, model="claude-haiku-5-5", source="cli", span=sp)
    s = t.summary()
    assert s["per_agent"][0]["cost_usd"] is None
    assert s["per_agent"][0]["cost_unknown_calls"] == 1
    assert s["total_cost_usd"] is None
    empty = tracing.Tracer(persist=False).summary()
    assert empty["total_cost_usd"] == 0.0 and empty["cost_unknown_calls"] == 0


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_runs_js_syntax_ok():
    js = ROOT / "src" / "bastion" / "web" / "static" / "runs.js"
    subprocess.run(["node", "--check", str(js)], check=True)
