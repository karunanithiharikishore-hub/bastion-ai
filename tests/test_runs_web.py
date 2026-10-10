# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Runs dashboard: /api/runs, /api/runs/<id>, static page, host checks."""
import http.client
import json
import os
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from conftest import BENIGN_SAMPLES
from bastion import tracing
from bastion.analyzer import analyze
from bastion.web.server import _State, _make_handler

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "src", "bastion", "web", "static")


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))
    state = _State([BENIGN_SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown(); httpd.server_close()


def _get(port, path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("GET", path, skip_host=host is not None)
    if host is not None:
        conn.putheader("Host", host)
    conn.endheaders()
    r = conn.getresponse()
    body = r.read().decode("utf-8")
    conn.close()
    return r.status, body


def test_runs_empty(server):
    st, body = _get(server, "/api/runs")
    assert st == 200 and json.loads(body) == {"runs": []}


def test_runs_list_and_detail(server):
    res = analyze([BENIGN_SAMPLES], use_llm=False)
    rid = res["meta"]["trace"]["run_id"]
    st, body = _get(server, "/api/runs?limit=5")
    runs = json.loads(body)["runs"]
    assert st == 200 and runs[0]["run_id"] == rid and "total_cost_usd" in runs[0]
    st, body = _get(server, f"/api/runs/{rid}")
    run = json.loads(body)
    assert st == 200 and run["summary"]["run_id"] == rid
    assert any(s["name"] == "analyze" for s in run["spans"])


def test_runs_bad_limit_falls_back(server):
    assert _get(server, "/api/runs?limit=abc")[0] == 200
    assert _get(server, "/api/runs?limit=-5")[0] == 200


def test_run_detail_404_and_traversal(server):
    assert _get(server, "/api/runs/20260101T000000Z-abcdef")[0] == 404
    assert _get(server, "/api/runs/..%2F..%2Fetc%2Fpasswd")[0] == 404
    assert _get(server, "/api/runs/")[0] == 404


def test_runs_api_respects_host_check(server):
    st, _ = _get(server, "/api/runs", host="evil.example")
    assert st == 403
    st, _ = _get(server, "/api/runs/20260101T000000Z-abcdef", host="evil.example:80")
    assert st == 403


def test_runs_page_served_and_linked(server):
    st, html = _get(server, "/runs.html")
    assert st == 200 and "runs.js" in html and "Harikishore Karunanithi" in html
    st, js = _get(server, "/runs.js")
    assert st == 200 and "esc(" in js
    st, index = _get(server, "/")
    assert 'href="runs.html"' in index


def test_runs_js_escapes_and_is_valid_syntax():
    js = open(os.path.join(STATIC, "runs.js"), encoding="utf-8").read()
    assert "const esc" in js and "&lt;" in js
    # no raw innerHTML interpolation of un-escaped ${s.field} for string fields
    for risky in ("${s.run_id}", "${s.verdict}", "${s.backbone}", "${a.agent}", "${sp.name}"):
        assert risky not in js
    node = shutil.which("node")
    if node:
        assert subprocess.run([node, "--check", os.path.join(STATIC, "runs.js")],
                              capture_output=True).returncode == 0
