# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-WEB-3: staged upload dirs must not survive SIGTERM / SIGHUP shutdown."""
import glob
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import pytest

from conftest import SAMPLES

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(port, path, obj):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("POST", path, json.dumps(obj), {"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = json.loads(resp.read())
    conn.close()
    return data


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_bug_web3_signal_removes_staged_dirs(sig, tmp_path):
    tmp = tmp_path / "tmp"          # private TMPDIR: only this run's stage dirs live here
    tmp.mkdir()
    samples = tmp_path / "samples"
    shutil.copytree(SAMPLES, samples)
    env = dict(os.environ, PYTHONPATH=os.path.abspath(os.path.join(ROOT, "src")),
               TMPDIR=str(tmp), BLUECELL_CACHE_DIR=str(tmp_path / "cache"),
               BLUECELL_RUNS_DIR=str(tmp_path / "runs"))
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "bluecell", "serve", str(samples),
         "--llm", "off", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        for _ in range(150):  # wait for the server to listen
            try:
                token = _post(port, "/api/stage/reset", {})["token"]
                break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("server did not start")
        _post(port, "/api/stage/add", {"token": token, "name": "a.log", "content": "secret"})
        assert glob.glob(str(tmp / "bluecell_stage_*")), "stage dir should exist before signal"
        proc.send_signal(sig)
        out, _ = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    assert glob.glob(str(tmp / "bluecell_stage_*")) == []
    assert proc.returncode == 0
    assert "shutting down" in out
