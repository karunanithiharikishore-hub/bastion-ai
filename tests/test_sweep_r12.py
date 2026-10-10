"""ITEM-12: Ctrl-C in cli.main prints one line to stderr and exits 130, with no traceback."""
import os, signal, subprocess, sys

CHILD = """
import sys, time
from bastion import cli
cli.provenance.enforce = lambda **k: None
def blocked(args):
    print("ready", flush=True)
    time.sleep(30)
    return 0
cli.cmd_info = blocked
sys.exit(cli.main(["info"]))
"""


def test_sweep_r12_ctrl_c_one_line_exit_130():
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    p = subprocess.Popen([sys.executable, "-c", CHILD], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert p.stdout.readline().strip() == b"ready"
        p.send_signal(signal.SIGINT)
        _, err = p.communicate(timeout=10)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    assert p.returncode == 130
    assert b"Traceback" not in err
    assert err.count(b"[bastion] interrupted") == 1
