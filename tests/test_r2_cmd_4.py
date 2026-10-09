"""R2 CMD-4: closing the session kills abandoned CLI worker processes."""
import os
import stat
import time
import types

from bluecell.agents import runtime
from bluecell.agents.roles import JuniorSocAnalyst


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def test_session_close_kills_running_worker(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir()
    pidfile = tmp_path / "worker.pid"
    fake.write_text(f"#!/bin/sh\necho $$ > {pidfile}\nsleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")

    session = runtime.SwarmSession.__new__(runtime.SwarmSession)
    session.dir = str(tmp_path)
    session.procs, session.closed = set(), False
    import threading
    t = threading.Thread(target=runtime._run_cli, daemon=True,
                         args=(JuniorSocAnalyst("a"), session,
                               types.SimpleNamespace(model="m"), 1, 60))
    t.start()
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.05)
    pid = int(pidfile.read_text())
    assert _alive(pid)
    session.close()
    t.join(10)
    assert not t.is_alive()
    for _ in range(40):
        if not _alive(pid):
            break
        time.sleep(0.05)
    assert not _alive(pid)
