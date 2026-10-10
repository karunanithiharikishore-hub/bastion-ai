# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-R4-ANALYST-ERROR: when the `claude` CLI exits non-zero with a JSON result line
(e.g. an expired login), the exception must carry the result text, not the raw JSON.
Offline: `claude` is a fake shell script on PATH."""
import os
import stat

from bluecell.agents.analyst import ai_analyze
from bluecell.llm.backbone import BackboneUnavailable, LLMBackbone

_EXPIRED = ("cat >/dev/null\n"
            "echo '{\"duration_api_ms\":0,\"stop_reason\":null,\"is_error\":true,"
            "\"result\":\"Failed to authenticate: OAuth session expired. Run /login.\"}'\n"
            "exit 1\n")


def _fake_claude(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_cli_failure_carries_result_text(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _EXPIRED)
    try:
        LLMBackbone(mode="cli").complete("hi")
    except BackboneUnavailable as exc:
        msg = str(exc)
    else:
        raise AssertionError("expected BackboneUnavailable")
    assert msg.startswith("claude CLI exited 1: Failed to authenticate: OAuth session expired")
    assert '{"' not in msg


def test_analyst_reason_shows_real_error(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _EXPIRED)
    out = ai_analyze([], [], LLMBackbone(mode="cli"), want_review=False)
    assert out["available"] is False
    assert "Failed to authenticate" in out["reason"]
    assert '{"' not in out["reason"]
