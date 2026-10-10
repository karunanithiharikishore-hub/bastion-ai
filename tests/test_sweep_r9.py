"""ITEM-9 regression: a descendant that left the process group (setsid) and inherited the
worker's pipes must not keep _run_cli blocked after the timeout kill.
Offline: the `claude` here is a fake shell script on PATH; no model is called."""
import os
import stat
import subprocess
import sys
import time

from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.roles import ThreatHunter
from bluecell.agents.runtime import SwarmSession, _run_cli
from bluecell.llm.backbone import LLMBackbone


def _alive(pid: int) -> bool:
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.strip()
    return bool(out) and not out.startswith("Z")


def _ctx():
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return AgentContext(events=events, incidents=correlate(events, window_minutes=120),
                        iocs=extract_iocs(events), digest=compress(events),
                        backbone=LLMBackbone(mode="cli"))


def test_escaped_descendant_does_not_block_timeout(tmp_path, monkeypatch):
    pid_file = tmp_path / "escaped.pid"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    # The grandchild double-forks into its own session (no setsid(1) on macOS) and keeps
    # the worker's stdout/stderr open; the worker itself sleeps in the foreground.
    exe.write_text("#!/bin/sh\n"
                   "cat >/dev/null\n"
                   f"'{sys.executable}' -c \"import os,time\n"
                   "if os.fork() == 0:\n"
                   f"    os.setsid(); open(r'{pid_file}', 'w').write(str(os.getpid())); time.sleep(25)\n"
                   "\"\n"
                   "sleep 25\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("BLUECELL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))

    session = SwarmSession(_ctx(), seed=[])
    helpers = []
    try:
        t0 = time.monotonic()
        run = _run_cli(ThreatHunter(), session, LLMBackbone(mode="cli"), 2, 2, model=None)
        elapsed = time.monotonic() - t0
        if pid_file.exists():
            helpers = [int(x) for x in pid_file.read_text().split() if x.isdigit()]
    finally:
        session.close()
        for h in helpers:   # only the process this test started
            if _alive(h):
                os.kill(h, 9)

    assert run["error"].startswith("claude CLI timed out after 2s")
    assert elapsed < 15, f"_run_cli blocked {elapsed:.1f}s after a 2s timeout"
