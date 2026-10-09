# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-AGENT-3: timeout/OSError text must not embed the claude argv (system
prompt), and the usage-limit halt must only match the CLI's own error text.
Offline: every `claude` here is a fake shell script on PATH."""
import os
import stat

import pytest

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.roles import ThreatHunter
from bluecell.agents.runtime import SwarmSession, _LIMIT_RE, _run_cli
from bluecell.llm import backbone as backbone_mod
from bluecell.llm.backbone import LLMBackbone, BackboneUnavailable

SECRET_DIRECTIVE = "check whether the login endpoint lacks rate limiting (password spraying)"


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


_HANG = "exec sleep 30\n"          # `exec` so the timeout kills the sleeper itself
_LIMIT_STREAM = ("cat >/dev/null\n"
                 "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,"
                 "\"result\":\"You\\u2019ve hit your session limit\",\"num_turns\":1}'\n"
                 "exit 1\n")


def _hunter(timeout=1):
    agent = ThreatHunter(timeout=timeout)
    agent.directive = f"Objective: {SECRET_DIRECTIVE}."
    return agent


# ---- runtime: the timeout error is a short summary ----------------------------
def test_runtime_timeout_error_has_no_argv_or_prompt(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _HANG)
    agent = _hunter(timeout=1)
    session = SwarmSession(_ctx(), seed=[])
    try:
        run = _run_cli(agent, session, LLMBackbone(mode="cli"), 2, 1, model=None)
    finally:
        session.close()
    assert run["error"].startswith("claude CLI timed out after 1s")
    assert "--system-prompt" not in run["error"]
    assert "You are the Threat Hunter" not in run["error"]
    assert "lacks rate limiting" not in run["error"]
    assert len(run["error"]) < 300


# ---- runtime: a timeout is not a usage limit, even when the prompt says so ----
def test_timeout_with_limit_words_in_directive_does_not_halt(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _HANG)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        agent = _hunter(timeout=1)
        findings = agent.run(ctx, session=session)
    finally:
        session.close()
    assert "timed out" in (agent.last_run["error"] or "")
    assert session.halted is None
    assert isinstance(findings, list)


# ---- runtime: a real CLI usage-limit message still halts the swarm ------------
def test_real_cli_limit_message_still_halts(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _LIMIT_STREAM)
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        _hunter(timeout=30).run(ctx, session=session)
    finally:
        session.close()
    assert session.halted and "session limit" in session.halted


# ---- backbone: the timeout error does not carry argv or the system prompt ----
def test_backbone_timeout_error_has_no_argv_or_system_prompt(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _HANG)
    bb = LLMBackbone(mode="cli", timeout=1)
    with pytest.raises(BackboneUnavailable) as exc:
        bb.complete("user prompt", system="SECRET SYSTEM PROMPT TEXT")
    msg = str(exc.value)
    assert msg.startswith("claude CLI timed out after 1s")
    assert "--append-system-prompt" not in msg and "SECRET SYSTEM" not in msg
    assert "claude -p" not in msg and "['claude'" not in msg


def test_backbone_oserror_error_is_short(monkeypatch):
    def boom(*a, **k):
        raise OSError(13, "Permission denied", "/secret/claude --system-prompt XYZ")
    monkeypatch.setattr(backbone_mod.subprocess, "run", boom)
    monkeypatch.setattr(backbone_mod.shutil, "which", lambda name: "/usr/bin/claude")
    with pytest.raises(BackboneUnavailable) as exc:
        LLMBackbone(mode="cli").complete("hi", system="XYZ")
    assert str(exc.value) == "claude CLI failed: Permission denied"


# ---- the halt pattern: limits match, ordinary prose does not ------------------
@pytest.mark.parametrize("text", [
    "You've hit your session limit · resets 5pm",
    "Claude AI usage limit reached",
    "rate limit exceeded",
    "API HTTP 429: rate_limit_error",
])
def test_limit_pattern_matches_real_limit_messages(text):
    assert _LIMIT_RE.search(text)


@pytest.mark.parametrize("text", [
    "check whether the login endpoint lacks rate limiting",
    "the session timed out after 900s",
    "Command ['claude', '--system-prompt', 'lacks rate limiting'] timed out",
])
def test_limit_pattern_ignores_prose(text):
    assert not _LIMIT_RE.search(text)
