"""BUG-FEAT-6 (render part): unknown cost shows n/a, partial cost shows >= x, never a fake $0.0000."""
from bastion import tracing
from bastion.report import render

USAGE = {"input_tokens": 1000, "output_tokens": 1000}


def _meta(trace):
    return {"generated": "now", "events_ingested": 1, "events_normalized": 1,
            "sources": [], "backbone": "off", "digest_tokens": 0, "trace": trace}


def _result(trace):
    return {"incidents": [], "iocs": {}, "hunt_checklist": [], "meta": _meta(trace)}


def test_all_unknown_run_renders_na_not_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    out = render.render_markdown(_result(t.summary()))
    assert "- Cost: n/a (" in out
    assert "$0.0000" not in out


def test_mixed_run_renders_lower_bound(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    t.record_usage(USAGE, model="claude-haiku-5-5")
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    out = render._render_trace(_meta(t.summary()))
    known = tracing.estimate_cost(USAGE, "claude-haiku-5-5")
    assert f"- Cost: >= ${known:.4f} (" in out


def test_per_agent_unknown_cost_renders_na(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path))
    t = tracing.Tracer(persist=False)
    with t.open("agent-x", "agent", agent="x", tier=1) as sp:
        t.record_usage(None, model="claude-haiku-5-5", source="cli", span=sp)
    out = render._render_trace(_meta(t.summary()))
    assert "`x`: 0 tool calls, 0 tokens, n/a" in out
    assert "$0.0000" not in out


def test_known_zero_and_known_cost_unchanged():
    out = render._render_trace(_meta({"run_id": "r", "total_cost_usd": 0.0,
                                      "cost_unknown_calls": 0, "per_agent": []}))
    assert "- Cost: $0.0000 (n/a)" in out
    out = render._render_trace(_meta({"run_id": "r", "total_cost_usd": 0.1234,
                                      "cost_unknown_calls": 0, "per_agent": []}))
    assert "- Cost: $0.1234 (n/a)" in out
