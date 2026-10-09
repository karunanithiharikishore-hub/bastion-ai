"""BUG-FEAT-6 follow-up: a timed-out CLI worker still records its usage (or an
unknown-cost record). Offline: `claude` is a fake shell script on PATH."""
import os
import stat
import types

import pytest

from bluecell import tracing
from bluecell.agents import runtime
from bluecell.agents.roles import JuniorSocAnalyst

ASSISTANT = ('{"type":"assistant","message":{"id":"msg_1","model":"claude-haiku-5-5",'
             '"usage":{"input_tokens":1200,"output_tokens":300}}}')


def _fake_claude(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def _timed_out_run(tmp_path, monkeypatch, body):
    _fake_claude(tmp_path, monkeypatch, body)
    session = runtime.SwarmSession.__new__(runtime.SwarmSession)
    session.dir = str(tmp_path)
    session.procs, session.closed = set(), False
    t = tracing.start_run(persist=False)
    try:
        run = runtime._run_cli(JuniorSocAnalyst("a"), session,
                               types.SimpleNamespace(model="claude-haiku-5-5"), 2, 1)
    finally:
        tracing.end_run(t)
    assert run["error"].startswith("claude CLI timed out after 1s")
    return t


def test_timeout_records_usage_streamed_before_kill(tmp_path, monkeypatch):
    t = _timed_out_run(tmp_path, monkeypatch,
                       f"cat >/dev/null\necho '{ASSISTANT}'\nexec sleep 30\n")
    assert len(t.usage) == 1
    rec = t.usage[0]
    assert rec["tokens"]["input"] == 1200 and rec["tokens"]["output"] == 300
    assert rec["cost_basis"] == "estimated"
    assert rec["cost_usd"] == pytest.approx(
        tracing.estimate_cost({"input_tokens": 1200, "output_tokens": 300}, "claude-haiku-5-5"))


def test_timeout_with_no_output_records_cost_unknown(tmp_path, monkeypatch):
    t = _timed_out_run(tmp_path, monkeypatch, "cat >/dev/null\nexec sleep 30\n")
    assert len(t.usage) == 1
    assert t.usage[0]["cost_basis"] == "unknown" and t.usage[0]["cost_usd"] is None
    s = t.summary()
    assert s["total_cost_usd"] is None and s["cost_unknown_calls"] == 1


def test_streamed_usage_dedupes_split_lines():
    # One API response split over two assistant lines (same id and usage) counts once.
    out = "\n".join([ASSISTANT, ASSISTANT, "{not json"])
    usage, model = runtime._streamed_usage(out)
    assert usage == {"input_tokens": 1200, "output_tokens": 300}
    assert model == "claude-haiku-5-5"
    assert runtime._streamed_usage("") == (None, None)
