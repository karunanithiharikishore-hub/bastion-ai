# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Regression tests for web dashboard / CLI fixes (W1-W12)."""
import glob
import json
import os
import socket
import tempfile
import threading
import http.client

import pytest

from conftest import SAMPLES
from bluecell import cli
from bluecell.web.server import _State, _make_handler
from http.server import ThreadingHTTPServer

SYSLOG = ("Sep 26 09:01:12 web01 sshd[1]: Failed password for admin from 203.0.113.66 port 41022 ssh2\n"
          "Sep 26 09:01:14 web01 sshd[2]: Failed password for admin from 203.0.113.66 port 41024 ssh2\n"
          "Sep 26 09:03:47 web01 sshd[3]: Accepted password for admin from 203.0.113.66 port 41120 ssh2\n")


@pytest.fixture()
def srv():
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    state.run_analysis()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield state, httpd.server_address[1]
    httpd.shutdown(); httpd.server_close(); state.close()


def _req(port, method, path, obj=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    body = raw if raw is not None else (json.dumps(obj) if obj is not None else None)
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    try:
        return r.status, json.loads(data.decode("utf-8"))
    except ValueError:
        return r.status, data


# W1 ------------------------------------------------------------------------
def test_w1_very_long_upload_name_is_staged(srv):
    _, port = srv
    _req(port, "POST", "/api/stage/reset", {})
    status, data = _req(port, "POST", "/api/stage/add",
                        {"name": "a" * 300 + ".log", "content": SYSLOG})
    assert status == 200 and data["staged"] == 1
    name = _State._safe_name(None, "b" * 400 + ".json")
    assert len(name) <= 160 and name.endswith(".json")


# W2 ------------------------------------------------------------------------
def test_w2_dotfile_upload_is_analyzed(srv):
    _, port = srv
    status, data = _req(port, "POST", "/api/upload",
                        {"files": [{"name": ".auth.log", "content": SYSLOG}], "window": 120})
    assert status == 200
    assert data["meta"]["events_ingested"] >= 3
    assert _State._safe_name(None, "..") == "log.txt"


# W3 ------------------------------------------------------------------------
def test_w3_upload_dedupes_identical_names(srv):
    _, port = srv
    half = SYSLOG.splitlines(True)
    status, data = _req(port, "POST", "/api/upload", {"files": [
        {"name": "x.log", "content": "".join(half[:2])},
        {"name": "x.log", "content": half[2]}], "window": 120})
    assert status == 200
    assert data["meta"]["events_ingested"] == 3


# W4 ------------------------------------------------------------------------
def test_w4_staging_is_per_client_token(srv):
    _, port = srv
    _, a = _req(port, "POST", "/api/stage/reset", {})
    _, b = _req(port, "POST", "/api/stage/reset", {})
    assert a["token"] and b["token"] and a["token"] != b["token"]
    _req(port, "POST", "/api/stage/add", {"token": a["token"], "name": "a.log", "content": SYSLOG})
    _req(port, "POST", "/api/stage/add", {"token": b["token"], "name": "b.log",
                                          "content": SYSLOG.splitlines(True)[0]})
    sa, ra = _req(port, "POST", "/api/stage/run", {"token": a["token"], "window": 120})
    assert sa == 200 and ra["meta"]["events_ingested"] == 3
    sb, rb = _req(port, "POST", "/api/stage/run", {"token": b["token"], "window": 120})
    assert sb == 200 and rb["meta"]["events_ingested"] == 1
    # unknown token is a client error, not someone else's files
    s, _ = _req(port, "POST", "/api/stage/add", {"token": "nope", "name": "x.log", "content": "x"})
    assert s == 400


# W5 ------------------------------------------------------------------------
def test_w5_cross_site_get_refused(srv):
    _, port = srv
    s, _ = _req(port, "GET", "/api/refresh", headers={"Sec-Fetch-Site": "cross-site"})
    assert s == 403
    s, _ = _req(port, "GET", "/api/meta", headers={"Sec-Fetch-Site": "same-origin"})
    assert s == 200
    s, _ = _req(port, "GET", "/api/meta", headers={"Sec-Fetch-Site": "none"})
    assert s == 200


def test_w5_report_md_matches_result_id(srv):
    state, port = srv
    s, up = _req(port, "POST", "/api/upload",
                 {"files": [{"name": "auth.log", "content": SYSLOG}], "window": 120})
    rid = up["meta"]["result_id"]
    # a later analysis replaces the "latest" result ...
    _, launch = _req(port, "GET", "/api/refresh")
    assert launch["meta"]["result_id"] != rid
    # ... but the report for the upload is still the upload's analysis.
    s, md = _req(port, "GET", f"/api/report.md?id={rid}")
    assert s == 200
    s2, md_latest = _req(port, "GET", "/api/report.md")
    assert s2 == 200 and md != md_latest
    s3, _ = _req(port, "GET", "/api/report.md?id=doesnotexist")
    assert s3 == 404


def test_w5_failed_run_keeps_last_good_result(srv):
    state, port = srv
    good = state.result
    calls = []
    orig = state._analyze_paths
    state._analyze_paths = lambda *a, **k: calls.append(a) or orig(*a, **k)
    _req(port, "POST", "/api/stage/reset", {})
    s, _ = _req(port, "POST", "/api/stage/run", {"window": 60})
    assert s == 500
    s, _ = _req(port, "GET", "/api/report.md")
    assert s == 200
    assert state.result is good and not calls   # no silent re-analysis


# W8 ------------------------------------------------------------------------
def test_w8_empty_body_is_400_and_meta_exposes_cap(srv):
    _, port = srv
    s, data = _req(port, "POST", "/api/stage/add", raw=b"")
    assert s == 400
    s, meta = _req(port, "GET", "/api/meta")
    assert meta["max_upload_mb"] == 256


# W9 ------------------------------------------------------------------------
def test_w9_staging_dirs_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    tok = state.stage_reset()
    assert state.stage_run(token=tok) is None           # "no files staged" branch
    assert not glob.glob(str(tmp_path / "bluecell_stage_*"))
    tok = state.stage_reset()
    state.stage_add("a.log", SYSLOG, token=tok)
    state.stage_add("b.log", SYSLOG)                    # default slot
    assert len(glob.glob(str(tmp_path / "bluecell_stage_*"))) == 2
    state.close()
    assert not glob.glob(str(tmp_path / "bluecell_stage_*"))


# W10 -----------------------------------------------------------------------
def test_w10_port_in_use_exits_cleanly(capsys):
    from bluecell.web import server as srvmod
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
    port = s.getsockname()[1]
    try:
        rc = cli.main(["serve", SAMPLES, "--port", str(port), "--llm", "off"])
    finally:
        s.close()
    assert rc == 2
    assert "cannot listen on 127.0.0.1:%d" % port in capsys.readouterr().err


def test_w10_ipv6_server_class():
    from bluecell.web import server as srvmod
    if not socket.has_ipv6:
        pytest.skip("no IPv6")
    try:
        httpd = srvmod._make_server("::1", 0, _make_handler(
            _State([SAMPLES], 60, "off", "x", None)))
    except OSError:
        pytest.skip("::1 not available")
    assert httpd.address_family == socket.AF_INET6
    httpd.server_close()


# W11 -----------------------------------------------------------------------
@pytest.mark.parametrize("content", ["{not json", '"a string"', "42", '{"entries": 5}'])
def test_w11_intel_import_bad_json(tmp_path, capsys, content):
    f = tmp_path / "feed.json"; f.write_text(content)
    rc = cli.main(["intel", "--intel-db", str(tmp_path / "db.json"), "import", str(f)])
    assert rc == 2
    assert "[bluecell]" in capsys.readouterr().err


def test_w11_analyze_output_dir_missing(tmp_path, capsys):
    rc = cli.main(["analyze", SAMPLES, "--llm", "off", "-o",
                   str(tmp_path / "nope" / "x.md")])
    assert rc == 2
    assert "[bluecell]" in capsys.readouterr().err
