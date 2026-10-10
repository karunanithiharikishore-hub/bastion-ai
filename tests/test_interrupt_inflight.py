"""SIGINT/SIGTERM must exit promptly even with an HTTP-style model call still blocked in a pool thread."""
import glob, os, signal, subprocess, sys, time
import pytest

CHILD = """
import sys
sys.path.insert(0, sys.argv[1])
from test_autonomous_agents import _ctx
from test_commander import SwarmModel, _orch, _use
from bastion import cli
cli.provenance.enforce = lambda **k: None
def cmd(args):
    ctx = _ctx()
    deploy = lambda body: _use("deploy_agents", {"agents": [
        {"role": "tier1-analyst", "source": s, "reason": "triage"} for s in ("edr", "dns")]})
    _orch(ctx, SwarmModel(ctx, [deploy], worker_delay=30), max_parallel=2).run()
    return 0
import types
cli.build_parser = lambda: types.SimpleNamespace(parse_args=lambda a: types.SimpleNamespace(func=cmd))
print("ready", flush=True)
sys.exit(cli.main([]))
"""


@pytest.mark.parametrize("sig,code", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_exit_fast_with_inflight_model_call(tmp_path, sig, code):
    env = dict(os.environ, TMPDIR=str(tmp_path), PYTHONPATH=os.pathsep.join(sys.path))
    p = subprocess.Popen([sys.executable, "-c", CHILD, os.path.dirname(__file__)], env=env,
                         stdout=subprocess.PIPE)
    try:
        p.stdout.readline()
        time.sleep(1.5)                      # workers are now blocked in their fake model call
        assert glob.glob(str(tmp_path / "bastion-swarm-*"))
        t = time.monotonic()
        p.send_signal(sig)
        assert p.wait(timeout=10) == code
        assert time.monotonic() - t < 3
        assert not glob.glob(str(tmp_path / "bastion-swarm-*"))
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
