# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-AGENT-7: a log source name starting with "-" must not break the Tier-1
agent's MCP server argv (argparse read it as an option). Offline: `claude` is
stubbed, and the captured MCP server argv is run through the real parser."""
import json
import os
import subprocess
import sys
import types

from bluecell.agents import runtime
from bluecell.agents.roles import JuniorSocAnalyst

_real_run = subprocess.run  # the stub below replaces subprocess.run globally


def test_dash_source_name_reaches_mcp_server_as_one_option(tmp_path, monkeypatch):
    calls = []

    class FakePopen:  # stand-in for the `claude` process
        returncode, pid = 0, 0

        def __init__(self, cmd, **kw):
            calls.append(cmd)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def communicate(self, *a, **kw):
            return "", ""

    monkeypatch.setattr(runtime.subprocess, "Popen", FakePopen)
    agent = JuniorSocAnalyst("-evil")
    session = runtime.SwarmSession.__new__(runtime.SwarmSession)
    session.dir = str(tmp_path)
    session.procs, session.closed = set(), False
    backbone = types.SimpleNamespace(model="stub-model")
    runtime._run_cli(agent, session, backbone, max_turns=1, timeout=5)
    monkeypatch.undo()  # the real parser check below needs the real Popen

    cfg_path = calls[0][calls[0].index("--mcp-config") + 1]
    with open(cfg_path, encoding="utf-8") as fh:
        server_args = json.load(fh)["mcpServers"][runtime.MCP_SERVER]["args"]

    # The real parser must accept the argv: exit code 2 is argparse rejecting it.
    proc = _real_run(
        [sys.executable, "-m", "bluecell.agents.mcp_server"] + server_args[2:],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, PYTHONPATH=runtime._SRC_ROOT))
    assert proc.returncode != 2, proc.stderr.strip().splitlines()[-1:]
    assert "expected one argument" not in proc.stderr
