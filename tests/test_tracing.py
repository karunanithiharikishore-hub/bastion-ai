# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Tracing + cost accounting. No real model calls: fake claude scripts, fake
API payloads and a fake backbone."""
import json
import os
import stat
import threading

import pytest

from conftest import SAMPLES, BENIGN_SAMPLES
from bluecell import tracing
from bluecell.analyzer import analyze
from bluecell.cli import main
from bluecell.llm.backbone import LLMBackbone


@pytest.fixture()
def runs_dir(tmp_path, monkeypatch):
    d = tmp_path / "runs"
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(d))
    monkeypatch.delenv("BLUECELL_NO_TRACE", raising=False)
    return d


def test_spans_nest_and_time(runs_dir):
    t = tracing.start_run(["a.log"], persist=False)
    try:
        with tracing.span("outer", "agent", agent="x") as sp:
            sp.set(mode="m")
            with tracing.span("inner", "tool"):
                pass
    finally:
        summ = tracing.end_run(t)
    by = {s.name: s for s in t.spans}
    assert by["inner"].parent == by["outer"].id
    assert by["outer"].parent == by["analyze"].id
    assert by["outer"].attributes["mode"] == "m"
    assert all(s.end is not None for s in t.spans)
    assert summ["tool_calls"] == 1 and summ["spans"] == 3


def test_span_records_exception_and_closes(runs_dir):
    t = tracing.start_run([], persist=False)
    with pytest.raises(ValueError):
        with tracing.span("boom", "agent"):
            raise ValueError("bad")
    tracing.end_run(t)
    boom = next(s for s in t.spans if s.name == "boom")
    assert "ValueError: bad" in boom.attributes["error"] and boom.end is not None


def test_no_active_run_is_a_noop():
    with tracing.span("x") as sp:
        sp.set(a=1)
    assert tracing.record_llm({"input_tokens": 1}, model="claude-sonnet-5") is None
    assert tracing.stage("s") is not None


def test_threads_parent_under_owner_stack_and_do_not_lose_usage(runs_dir):
    t = tracing.start_run([], persist=False)
    with tracing.span("swarm-ish", "pipeline") as outer:
        def work(i):
            with tracing.span(f"agent{i}", "agent", agent=f"a{i}"):
                tracing.record_llm({"input_tokens": 1000, "output_tokens": 100},
                                   model="claude-sonnet-5")
                tracing.record_tool_calls([{"tool": "t", "ok": True}], agent=f"a{i}")
        ths = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        [x.start() for x in ths]
        [x.join() for x in ths]
    summ = tracing.end_run(t)
    agents = [s for s in t.spans if s.kind == "agent"]
    assert len(agents) == 8 and all(a.parent == outer.id for a in agents)
    assert summ["llm_calls"] == 8 and summ["tool_calls"] == 8
    assert len({s.id for s in t.spans}) == len(t.spans)      # unique ids
    assert {a["agent"] for a in summ["per_agent"]} == {f"a{i}" for i in range(8)}
    assert all(a["llm_calls"] == 1 and a["tool_calls"] == 1 for a in summ["per_agent"])


def test_api_cost_is_estimated_from_price_table(runs_dir):
    t = tracing.start_run([], persist=False)
    usage = {"input_tokens": 1_000_000, "output_tokens": 100_000,
             "cache_read_input_tokens": 1_000_000, "cache_creation_input_tokens": 1_000_000}
    rec = tracing.record_llm(usage, model="claude-sonnet-5", source="api")
    pin, pout = tracing.PRICES["claude-sonnet-5"]
    expect = pin + 0.1 * pout + pin * 0.1 + pin * 1.25
    assert rec["cost_basis"] == "estimated" and rec["cost_usd"] == pytest.approx(expect)
    unk = tracing.record_llm({"input_tokens": 5}, model="mystery-model")
    assert unk["cost_basis"] == "unknown" and unk["cost_usd"] is None
    none = tracing.record_llm(None, model="claude-sonnet-5")
    assert none["cost_basis"] == "unknown" and none["tokens"]["total"] == 0
    summ = tracing.end_run(t)
    assert summ["cost_estimated"] is True and "estimated" in summ["cost_note"]
    assert summ["total_cost_usd"] == pytest.approx(expect)


def test_price_lookup_prefers_longest_prefix_and_family():
    assert tracing.price_for("claude-sonnet-5-5-20260101") == tracing.PRICES["claude-sonnet-5-5"]
    assert tracing.price_for("anthropic.claude-sonnet-5") == tracing.PRICES["claude-sonnet-5"]
    assert tracing.price_for("some-haiku-thing") is not None
    assert tracing.price_for("gpt-x") is None and tracing.price_for(None) is None


STREAM = "\n".join(json.dumps(m) for m in [
    {"type": "system", "subtype": "init"},
    {"type": "assistant", "message": {"model": "claude-sonnet-5", "content": [
        {"type": "tool_use", "id": "u1", "name": "mcp__bluecell__search_events", "input": {}}]}},
    {"type": "assistant", "message": {"content": [{"type": "text", "text": "hi"}]}},
    "not json at all",
    {"type": "result", "subtype": "success", "result": "done", "num_turns": 3,
     "total_cost_usd": 0.0421, "is_error": False,
     "usage": {"input_tokens": 10, "output_tokens": 20,
               "cache_read_input_tokens": 300, "cache_creation_input_tokens": 4}},
]).replace('"not json at all"', "not json at all")


def test_parse_stream_json():
    p = tracing.parse_stream_json(STREAM)
    assert p["cost_usd"] == 0.0421 and p["num_turns"] == 3 and p["model"] == "claude-sonnet-5"
    assert p["tool_uses"] == [{"tool": "search_events", "id": "u1"}]
    assert p["usage"]["cache_read_input_tokens"] == 300
    assert tracing.parse_stream_json("")["usage"] is None
    assert tracing.parse_stream_json(None)["tool_uses"] == []


def test_cli_cost_is_reported_not_estimated(runs_dir):
    t = tracing.start_run([], persist=False)
    p = tracing.parse_stream_json(STREAM)
    tracing.record_llm(p["usage"], model=p["model"], cost_usd=p["cost_usd"],
                       source="cli-agent", calls=p["num_turns"])
    summ = tracing.end_run(t)
    assert summ["total_cost_usd"] == 0.0421 and summ["cost_basis"] == ["reported"]
    assert summ["cost_estimated"] is False and summ["llm_calls"] == 3
    assert summ["tokens"] == {"input": 10, "output": 20, "cache_read": 300,
                              "cache_creation": 4, "total": 334}


def _fake_claude(tmp_path, monkeypatch, body):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\ncat >/dev/null\ncat <<'EOF'\n" + body + "\nEOF\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_backbone_cli_complete_records_reported_cost(runs_dir, tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, json.dumps({
        "type": "result", "subtype": "success", "is_error": False, "result": "the answer",
        "total_cost_usd": 0.0123, "usage": {"input_tokens": 7, "output_tokens": 9}}))
    t = tracing.start_run([], persist=False)
    out = LLMBackbone("cli", model="claude-sonnet-5").complete("hello", system="s")
    summ = tracing.end_run(t)
    assert out == "the answer"
    assert summ["total_cost_usd"] == 0.0123 and summ["cost_basis"] == ["reported"]
    assert summ["tokens"]["total"] == 16
    assert any(s.kind == "llm" for s in t.spans)


def test_backbone_cli_plain_text_and_error_results(runs_dir, tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, "just plain text")
    t = tracing.start_run([], persist=False)
    assert LLMBackbone("cli").complete("x") == "just plain text"
    assert tracing.end_run(t)["cost_basis"] == ["unknown"]

    _fake_claude(tmp_path, monkeypatch, json.dumps(
        {"type": "result", "is_error": True, "subtype": "error_during_execution",
         "result": "limit hit", "total_cost_usd": 0.0}))
    from bluecell.llm import BackboneUnavailable
    with pytest.raises(BackboneUnavailable):
        LLMBackbone("cli").complete("x")


def test_backbone_api_complete_records_estimate(runs_dir, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-real")
    bb = LLMBackbone("api", model="claude-sonnet-5")
    monkeypatch.setattr(bb, "messages", lambda body: {
        "model": "claude-sonnet-5", "content": [{"type": "text", "text": "ok"}],
        "usage": {"input_tokens": 1000, "output_tokens": 500}})
    t = tracing.start_run([], persist=False)
    assert bb.complete("p") == "ok"
    summ = tracing.end_run(t)
    assert summ["cost_estimated"] is True and summ["total_cost_usd"] > 0


def test_persistence_roundtrip(runs_dir):
    t = tracing.start_run(["/x/logs/a.log"], persist=True)
    with tracing.span("a", "agent", agent="a", tier=1):
        tracing.record_llm({"input_tokens": 1, "output_tokens": 1}, model="claude-sonnet-5")
    summ = tracing.end_run(t, {"incidents": [{"verdict": {"level": "likely-benign"}}], "meta": {}})
    d = runs_dir / summ["run_id"]
    assert (d / "trace.jsonl").is_file() and (d / "summary.json").is_file()
    run = tracing.load_run(summ["run_id"])
    assert run["summary"]["verdict"] == "likely-benign"
    assert {s["name"] for s in run["spans"]} == {"analyze", "a"} and len(run["usage"]) == 1
    assert tracing.list_runs()[0]["run_id"] == summ["run_id"]
    assert any("[agent] a" in line for line in tracing.span_tree_lines(run))


def test_load_run_rejects_traversal_and_missing(runs_dir):
    assert tracing.load_run("../../etc/passwd") is None
    assert tracing.load_run("20260101T000000Z-abcdef") is None
    assert tracing.list_runs() == []


def test_failure_safety_unwritable_dir_and_bad_inputs(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(blocker / "sub"))   # cannot mkdir
    t = tracing.start_run(["a"], persist=True)
    tracing.record_llm(object(), model=object())
    tracing.record_tool_calls([{"tool": "x", "t0": "bad", "ms": "bad"}, None])
    res = {"meta": {}}
    assert tracing.end_run(t, res)["run_id"]     # did not raise
    assert "trace" in res["meta"]
    assert tracing.end_run(None) is None


def test_analyze_never_fails_when_tracing_breaks(runs_dir, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("tracing is broken")
    monkeypatch.setattr(tracing.Tracer, "__init__", broken)
    res = analyze([BENIGN_SAMPLES], use_llm=False)
    assert res["incidents"] and "trace" not in res["meta"]


def test_analyze_trace_summary_report_section_and_persistence(runs_dir):
    from bluecell.report import render_markdown
    res = analyze([SAMPLES], use_llm=False)
    tr = res["meta"]["trace"]
    assert tr["tool_calls"] == 0 and tr["llm_calls"] == 0 and tr["total_cost_usd"] == 0
    assert tr["spans"] > 5 and tr["per_agent"]
    assert os.path.isdir(runs_dir / tr["run_id"])
    md = render_markdown(res)
    assert "## Run cost & trace" in md and tr["run_id"] in md
    stages = {s["name"] for s in tracing.load_run(tr["run_id"])["spans"]}
    assert {"ingest", "swarm", "finalize"} <= stages


def test_no_trace_does_not_persist(runs_dir):
    res = analyze([BENIGN_SAMPLES], use_llm=False, trace=False)
    assert "trace" in res["meta"] and not runs_dir.exists()


def test_env_disables_persistence(runs_dir, monkeypatch):
    monkeypatch.setenv("BLUECELL_NO_TRACE", "1")
    analyze([BENIGN_SAMPLES], use_llm=False)
    assert not runs_dir.exists()


class _FakeAPI:
    """Thread-safe backbone whose agents end immediately, reporting usage."""
    resolved = "api"
    model = "claude-sonnet-5"

    def messages(self, body):
        return {"model": "claude-sonnet-5", "content": [{"type": "text", "text": "nothing"}],
                "usage": {"input_tokens": 100, "output_tokens": 10}}

    def complete(self, *a, **k):
        from bluecell.llm import BackboneUnavailable
        raise BackboneUnavailable("no text mode in this fake")


def test_swarm_pool_threads_keep_usage_and_agent_parenting(runs_dir):
    res = analyze([SAMPLES], backbone=_FakeAPI(), use_llm=True)
    tr = res["meta"]["trace"]
    assert tr["llm_calls"] >= 10 and tr["cost_estimated"] is True
    run = tracing.load_run(tr["run_id"])
    ids = {s["id"]: s for s in run["spans"]}
    agent_spans = [s for s in run["spans"] if s["kind"] == "agent"]
    assert len(agent_spans) >= 10
    for u in run["usage"]:
        assert u["span"] in ids                        # usage attached to a real span
    with_usage = {ids[u["span"]]["id"] for u in run["usage"]}
    assert any(ids[s]["kind"] == "agent" for s in with_usage)
    assert sum(a["llm_calls"] for a in tr["per_agent"]) >= 10


def test_cli_runs_list_and_show(runs_dir, capsys):
    main(["analyze", BENIGN_SAMPLES, "--llm", "off", "-o", os.devnull])
    capsys.readouterr()
    assert main(["runs", "--last", "5"]) == 0
    out = capsys.readouterr().out
    run_id = tracing.list_runs()[0]["run_id"]
    assert run_id in out and "samples_benign" in out
    assert main(["runs", "show", run_id]) == 0
    shown = capsys.readouterr().out
    assert "[run] analyze" in shown and "[pipeline] swarm" in shown
    assert main(["runs", "show", "nope"]) == 2


def test_cli_no_trace_flag(runs_dir):
    main(["analyze", BENIGN_SAMPLES, "--llm", "off", "--no-trace", "-o", os.devnull])
    assert tracing.list_runs() == []


def test_cli_runs_empty(runs_dir, capsys):
    assert main(["runs"]) == 0
    assert "no traced runs" in capsys.readouterr().out
