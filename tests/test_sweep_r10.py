"""ITEM-10 regression: a timed-out `claude -p` call takes its helper processes down
with it (own process group, killed on timeout, like runtime._run_cli).
Offline: the `claude` here is a fake shell script on PATH; no model is called."""
import os
import stat
import subprocess
import time

import pytest

from bastion.llm.backbone import BackboneUnavailable, LLMBackbone


def _alive(pid: int) -> bool:
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.strip()
    return bool(out) and not out.startswith("Z")   # a zombie is already dead


def test_timeout_kills_cli_helper_processes(tmp_path, monkeypatch):
    pid_file = tmp_path / "helper.pid"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text("#!/bin/sh\n"
                   "cat >/dev/null\n"
                   "sleep 30 &\n"
                   f"echo $! >> \"{pid_file}\"\n"
                   f"sleep 30 & echo $! >> \"{pid_file}\"\n"
                   "wait\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("BASTION_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))

    backbone = LLMBackbone(mode="cli", timeout=2)
    helpers = []
    try:
        with pytest.raises(BackboneUnavailable, match="timed out"):
            backbone.complete("ping")
        helpers = [int(x) for x in pid_file.read_text().split()]
        assert helpers, "the fake claude never started its helpers"
        assert not [h for h in helpers if _alive(h)], \
            "the CLI's helper processes survived the timeout"
    finally:
        for h in helpers:   # only the processes this test started
            if _alive(h):
                os.kill(h, 9)
