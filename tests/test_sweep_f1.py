# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-1: a non-loopback `serve --host` must refuse foreign Host headers and warn."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import pytest

from conftest import SAMPLES

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _get(url, host):
    req = urllib.request.Request(url, headers={"Host": host})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_foreign_host_refused_on_non_loopback_bind(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    cache = tempfile.mkdtemp()
    env = dict(os.environ, PYTHONPATH=os.path.join(REPO, "src"),
               BLUECELL_CACHE_DIR=cache, BLUECELL_RUNS_DIR=cache)
    err = tmp_path / "stderr.log"
    with open(err, "w") as ef:
        proc = subprocess.Popen(
            [sys.executable, "-m", "bluecell", "serve", SAMPLES, "--llm", "off",
             "--host", "0.0.0.0", "--port", str(port)],
            cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=ef)
    try:
        deadline = time.time() + 60
        while True:  # wait for the listener to come up
            try:
                _get(f"http://127.0.0.1:{port}/api/meta", f"localhost:{port}")
                break
            except OSError:
                if proc.poll() is not None or time.time() > deadline:
                    pytest.fail("server did not start")
                time.sleep(0.2)
        # DNS-rebinding style request: an attacker name that resolves to this machine
        assert _get(f"http://127.0.0.1:{port}/api/meta", f"evil.example:{port}") == 403
        assert _get(f"http://127.0.0.1:{port}/api/report", f"evil.example:{port}") == 403
        # the local dashboard itself still works
        assert _get(f"http://127.0.0.1:{port}/api/meta", f"localhost:{port}") == 200
    finally:
        proc.terminate()
        proc.wait(timeout=15)
    text = err.read_text()
    assert "WARNING" in text and "NO authentication" in text
