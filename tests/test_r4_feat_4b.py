"""R4-FEAT-4 follow-up: a swarm session still open at interpreter exit (server stopped
mid-analysis) must not leave its worker processes running."""
import os
import subprocess
import sys
import time

_CHILD = r"""
import subprocess, sys
from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, correlate, extract_iocs, compress
from bluecell.agents import AgentContext
from bluecell.agents.runtime import SwarmSession
ev = normalize(ingest_path(SAMPLES))
ctx = AgentContext(events=ev, incidents=correlate(ev), iocs=extract_iocs(ev), digest=compress(ev))
s = SwarmSession(ctx, seed=[])
p = subprocess.Popen(["sleep", "60"], start_new_session=True)
s.procs.add(p)
print(p.pid, flush=True)
"""


def test_open_session_workers_killed_at_exit():
    tests = os.path.dirname(__file__)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [os.path.join(tests, "..", "src"), tests, os.environ.get("PYTHONPATH", "")]))
    out = subprocess.run([sys.executable, "-c", _CHILD], env=env, capture_output=True,
                         text=True, timeout=60)
    pid = int(out.stdout.split()[-1])
    time.sleep(0.2)
    try:
        os.kill(pid, 0)
        alive = True
        os.kill(pid, 9)
    except ProcessLookupError:
        alive = False
    assert not alive
