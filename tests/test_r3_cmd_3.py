"""R3 CMD-3: SIGTERM to the CLI reaps worker (own session) processes."""
import os
import signal
import stat
import subprocess
import sys
import time

CHILD = """
import sys, types
from bluecell import cli
from bluecell.agents import runtime
from bluecell.agents.roles import JuniorSocAnalyst
def cmd(args):
    s = runtime.SwarmSession.__new__(runtime.SwarmSession)
    s.dir, s.procs, s.closed = sys.argv[1], set(), False
    try:
        runtime._run_cli(JuniorSocAnalyst("a"), s, types.SimpleNamespace(model="m"), 1, 60)
    finally:
        s.close()
cli.build_parser = lambda: types.SimpleNamespace(parse_args=lambda a: types.SimpleNamespace(func=cmd))
cli.provenance.enforce = lambda **k: None
cli.main([])
"""


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_sigterm_kills_worker(tmp_path):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir()
    pidfile = tmp_path / "worker.pid"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nsleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ, PATH=f"{fake.parent}{os.pathsep}{os.environ['PATH']}",
               PYTHONPATH=os.pathsep.join(sys.path))
    sess = tmp_path / "sess"
    sess.mkdir()
    parent = subprocess.Popen([sys.executable, "-c", CHILD, str(sess)], env=env)
    pid = None
    try:
        for _ in range(200):
            if pidfile.exists() and pidfile.read_text().strip():
                pid = int(pidfile.read_text())
                break
            time.sleep(0.05)
        assert pid
        parent.send_signal(signal.SIGTERM)
        parent.wait(10)
        for _ in range(60):
            if not _alive(pid):
                break
            time.sleep(0.05)
        assert not _alive(pid)
    finally:
        if pid:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass
        parent.kill()
        parent.wait()
