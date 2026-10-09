# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-R3-AGENT-2: a crashed or timed-out worker's stdout is stream-json that echoes
tool results (log text). Only the CLI's own error text may trigger the swarm halt
or appear in the error. Offline: every `claude` here is a fake shell script on PATH."""
import os
import stat

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.roles import ThreatHunter
from bluecell.agents.runtime import SwarmSession, _run_cli
from bluecell.llm.backbone import LLMBackbone


def _ctx(backbone=None):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=backbone)


def _fake_claude(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


# A worker that streams a tool_result carrying ordinary log text, then dies with empty stderr.
_LOG_THEN_CRASH = ("cat >/dev/null\n"
                   "echo '{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\","
                   "\"content\":\"nginx: 429 rate limit exceeded for 10.0.0.9\"}]}}'\n"
                   "exit 137\n")
# A worker that hangs after streaming the same log text (timeout path).
_LOG_THEN_HANG = ("cat >/dev/null\n"
                  "echo '{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":[{\"type\":\"tool_result\","
                  "\"content\":\"nginx: 429 rate limit exceeded for 10.0.0.9\"}]}}'\n"
                  "exec sleep 30\n")
# The CLI's own limit result line (is_error), then exit 1: must still halt.
_LIMIT_RESULT = ("cat >/dev/null\n"
                 "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,"
                 "\"result\":\"You\\u2019ve hit your session limit\",\"num_turns\":1}'\n"
                 "exit 1\n")
# The CLI printing a usage limit as a plain stdout line, then exit 1: must still halt.
_LIMIT_PLAIN = "cat >/dev/null\necho 'Claude AI usage limit reached'\nexit 1\n"


def test_log_text_in_crashed_worker_does_not_halt(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _LOG_THEN_CRASH)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        agent = ThreatHunter(timeout=5)
        agent.run(ctx, session=session)
    finally:
        session.close()
    assert session.halted is None
    assert "rate limit" not in agent.last_run["error"]
    assert agent.last_run["error"].startswith("claude exited 137")


def test_log_text_in_timed_out_worker_stays_out_of_error(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _LOG_THEN_HANG)
    session = SwarmSession(_ctx(), seed=[])
    try:
        run = _run_cli(ThreatHunter(), session, LLMBackbone(mode="cli"), 2, 1, model=None)
    finally:
        session.close()
    assert run["error"].startswith("claude CLI timed out after 1s")
    assert "rate limit" not in run["error"]
    assert run["limit_text"] == ""


def test_cli_limit_result_still_halts(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _LIMIT_RESULT)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        ThreatHunter(timeout=30).run(ctx, session=session)
    finally:
        session.close()
    assert session.halted and "session limit" in session.halted


def test_cli_plain_stdout_limit_still_halts(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _LIMIT_PLAIN)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        ThreatHunter(timeout=30).run(ctx, session=session)
    finally:
        session.close()
    assert session.halted and "usage limit" in session.halted


def test_non_object_stream_line_keeps_result(tmp_path, monkeypatch):
    # R3-AGENT-7: a stray `42` line raised AttributeError and discarded the finished result.
    _fake_claude(tmp_path, monkeypatch,
                 "cat >/dev/null\necho 42\n"
                 "echo '{\"type\":\"result\",\"result\":\"done\",\"num_turns\":1}'\n")
    session = SwarmSession(_ctx(), seed=[])
    try:
        run = _run_cli(ThreatHunter(), session, LLMBackbone(mode="cli"), 2, 10, model=None)
    finally:
        session.close()
    # The result line was parsed (the zero-tool-call guard ran), not lost to a crash.
    assert run.get("turns") == 1, run
    assert "AttributeError" not in (run.get("error") or "")
