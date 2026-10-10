"""ITEM-11: Ctrl-C/SIGTERM in CLI commander mode with a deploy in flight must exit
promptly (< 3 s) and kill the worker `claude` processes. Fake `claude` only."""
import os, signal, subprocess, sys, time
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
SAMPLES = os.path.join(ROOT, "samples")

# Commander writes one deploy request into its dispatch dir, then idles; workers idle.
FAKE_CLAUDE = r'''#!/bin/bash
SYS=""; PREV=""
for a in "$@"; do if [ "$PREV" = "--system-prompt" ]; then SYS="$a"; fi; PREV="$a"; done
case " $* " in *" --mcp-config "*) ;; *) cat >/dev/null; echo '{"type":"result","result":"ok","is_error":false}'; exit 0;; esac
cat >/dev/null
echo "$$" >> "$BCFAKE_LOG"
case "$SYS" in
 "You are the SOC Lead"*)
   D="$PWD/dispatch"; mkdir -p "$D"
   echo '{"id":"r1","op":"deploy","args":{"agents":[{"role":"threat-hunter","reason":"hunt"},{"role":"forensics","reason":"time"}]}}' > "$D/r1.req.json.tmp" && mv "$D/r1.req.json.tmp" "$D/r1.req.json" ;;
esac
sleep 120
'''

CHILD = """
import sys
from bluecell import cli
print("ready", flush=True)
sys.exit(cli.main(["analyze", sys.argv[1], "--llm", "cli", "--orchestration", "commander",
                   "--no-cache", "--budget-seconds", "600", "-o", sys.argv[2]]))
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@pytest.mark.parametrize("sig,code", [(signal.SIGINT, 130), (signal.SIGTERM, 143)])
def test_cli_commander_interrupt_exits_promptly_and_kills_workers(tmp_path, sig, code):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text(FAKE_CLAUDE)
    exe.chmod(0o755)
    log = tmp_path / "claude.log"
    log.write_text("")
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
               BCFAKE_LOG=str(log), TMPDIR=str(tmp_path), PYTHONPATH=SRC,
               PYTHONUNBUFFERED="1")
    p = subprocess.Popen([sys.executable, "-c", CHILD, SAMPLES, str(tmp_path / "out.md")],
                         env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pids = []
    try:
        assert p.stdout.readline().strip() == "ready"
        deadline = time.monotonic() + 30
        while len(log.read_text().split()) < 3:      # commander + two workers launched
            assert time.monotonic() < deadline and p.poll() is None
            time.sleep(0.2)
        pids = [int(x) for x in log.read_text().split()]
        t = time.monotonic()
        p.send_signal(sig)
        rc = p.wait(timeout=10)
        assert time.monotonic() - t < 3              # before the fix: ~10 s (relay join)
        assert rc == code
        for _ in range(15):                          # workers must be gone, not running on
            if not any(_alive(pid) for pid in pids):
                break
            time.sleep(0.2)
        assert not any(_alive(pid) for pid in pids)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
