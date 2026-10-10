"""ITEM-2 regression: account-wide failures (401/403, credit balance, 429) halt the
swarm, decided from the HTTP status, not free text. A per-agent failure does not halt.
Offline: fake API backbones raise BackboneUnavailable; the CLI case uses a fake `claude`."""
import io
import os
import stat
import urllib.error

import pytest

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.roles import ThreatHunter, JuniorSocAnalyst
from bluecell.agents.runtime import SwarmSession
from bluecell.llm import backbone as bb
from bluecell.llm.backbone import BackboneUnavailable, LLMBackbone


def _ctx(backbone=None):
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=backbone)


def _http(status, msg):
    exc = BackboneUnavailable(msg)
    exc.status = status     # the HTTP status the backbone attaches to an API error
    return exc


class Raising:
    """API backbone whose every model call fails with the given error."""
    resolved = "api"
    model = "fake"

    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def messages(self, body):
        self.calls += 1
        raise self.exc


def _two_agents(exc):
    """Run two API agents in turn; return (halted, model calls made)."""
    bbone = Raising(exc)
    ctx = _ctx(bbone)
    session = SwarmSession(ctx, seed=[])
    try:
        ThreatHunter().run(ctx, use_llm=True, session=session)
        halted = session.halted
        JuniorSocAnalyst("dns").run(ctx, use_llm=True, session=session)
    finally:
        session.close()
    return halted, bbone.calls


@pytest.mark.parametrize("exc", [
    _http(401, "API HTTP 401: authentication_error invalid x-api-key"),
    _http(403, "API HTTP 403: permission_error"),
    _http(400, "API HTTP 400: Your credit balance is too low to access the API"),
    # Guard: a real session/rate limit still halts the swarm.
    _http(429, "API HTTP 429: rate_limit_error"),
])
def test_account_wide_failure_halts_swarm(exc):
    halted, calls = _two_agents(exc)
    assert halted
    assert calls == 1                       # the second agent never called the model


@pytest.mark.parametrize("exc", [
    _http(400, "API HTTP 400: invalid_request_error max_tokens too large"),
    _http(529, "API HTTP 529: overloaded_error"),
    BackboneUnavailable("API request failed: timed out"),          # no HTTP status
    # Not a backbone error at all: text that merely mentions a rate limit must not halt.
    RuntimeError("rate limit exceeded in my own helper"),
])
def test_per_agent_failure_does_not_halt_swarm(exc):
    halted, calls = _two_agents(exc)
    assert halted is None
    assert calls == 2


def test_backbone_http_error_carries_status(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    def fake(req, timeout):
        raise urllib.error.HTTPError("u", 401, "x", {},
                                     io.BytesIO(b'{"error":{"type":"authentication_error"}}'))
    monkeypatch.setattr(bb.urllib.request, "urlopen", fake)
    with pytest.raises(BackboneUnavailable) as exc:
        LLMBackbone(mode="api").messages({})
    assert exc.value.status == 401


def test_cli_not_logged_in_halts_swarm(tmp_path, monkeypatch):
    count = tmp_path / "count.log"
    monkeypatch.setenv("COUNT_LOG", str(count))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\ncat >/dev/null\necho x >> \"$COUNT_LOG\"\n"
                   "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true,"
                   "\"result\":\"Not logged in \\u00b7 Please run /login\",\"num_turns\":1}'\n"
                   "exit 1\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    ctx = _ctx(LLMBackbone(mode="cli"))
    session = SwarmSession(ctx, seed=[])
    try:
        ThreatHunter(timeout=30).run(ctx, session=session)
        halted = session.halted
        JuniorSocAnalyst("dns").run(ctx, session=session)
    finally:
        session.close()
    assert halted and "Not logged in" in halted
    assert len(count.read_text().splitlines()) == 1     # second agent never launched claude
