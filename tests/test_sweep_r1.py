"""ITEM-1 regression: only account/session/usage/rate limits halt the swarm. A single
agent's own context-window error ("Context limit reached") fails just that agent.
Offline: the `claude` here is a fake shell script on PATH."""
import os
import stat

from conftest import SAMPLES
from bastion.ingest import ingest_path
from bastion.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bastion.agents import AgentContext
from bastion.agents.roles import ThreatHunter
from bastion.agents.runtime import SwarmSession
from bastion.llm.backbone import LLMBackbone


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


def _result_line(text: str) -> str:
    # The CLI's own error result (is_error), then exit 1, with a count of launches.
    return ("cat >/dev/null\n"
            f"echo x >> \"$COUNT_LOG\"\n"
            f"echo '{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,"
            f"\"result\":\"{text}\",\"num_turns\":1}}'\n"
            "exit 1\n")


def _two_agents_run(tmp_path, monkeypatch, text: str):
    count = tmp_path / "count.log"
    monkeypatch.setenv("COUNT_LOG", str(count))
    _fake_claude(tmp_path, monkeypatch, _result_line(text))
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    first, second = ThreatHunter(timeout=30), ThreatHunter(timeout=30)
    try:
        first.run(ctx, session=session)
        halted = session.halted
        second.run(ctx, session=session)
    finally:
        session.close()
    return halted, first, second, len(count.read_text().splitlines())


def test_agent_context_limit_fails_only_that_agent(tmp_path, monkeypatch):
    halted, first, second, launches = _two_agents_run(
        tmp_path, monkeypatch, "Context limit reached - /compact or /clear to continue")
    assert halted is None
    assert first.last_run["error"]              # the agent itself still failed
    assert launches == 2                        # the next agent still launched claude


def test_max_turns_limit_fails_only_that_agent(tmp_path, monkeypatch):
    halted, _, _, launches = _two_agents_run(tmp_path, monkeypatch, "Max turns limit reached")
    assert halted is None
    assert launches == 2


def test_session_limit_still_halts_swarm(tmp_path, monkeypatch):
    halted, _, _, launches = _two_agents_run(
        tmp_path, monkeypatch, "You\\u2019ve hit your session limit")
    assert halted and "session limit" in halted
    assert launches == 1                        # the second agent never launched claude
