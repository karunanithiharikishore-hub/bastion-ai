# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-R4-FEAT-3: a failed `claude -p` call's CLI-reported cost and tokens must
reach the run trace before BackboneUnavailable is raised. Offline: fake `claude`."""
import os
import stat

import pytest

from bluecell import tracing
from bluecell.llm.backbone import BackboneUnavailable, LLMBackbone

_ERROR_RESULT = ("cat >/dev/null\n"
                 "echo '{\"type\":\"result\",\"subtype\":\"error_during_execution\","
                 "\"is_error\":true,\"result\":\"boom\",\"total_cost_usd\":0.4321,"
                 "\"usage\":{\"input_tokens\":1000,\"output_tokens\":500}}'\n"
                 "exit 1\n")


def _fake_claude(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_failed_cli_call_cost_and_tokens_are_traced(tmp_path, monkeypatch):
    _fake_claude(tmp_path, monkeypatch, _ERROR_RESULT)
    t = tracing.start_run(["x"], persist=False)
    with pytest.raises(BackboneUnavailable, match="claude CLI exited 1: boom"):
        LLMBackbone(mode="cli").complete("hi")
    s = tracing.end_run(t)
    assert s["llm_calls"] == 1
    assert s["total_cost_usd"] == pytest.approx(0.4321)
    assert s["tokens"]["total"] == 1500
