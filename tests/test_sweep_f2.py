# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Sweep F2 (ITEM-2, 16, 18, 20): malformed targets answer, dashboard CSP/frame headers,
socket timeout and per-slot staging quota, stale staging dirs swept at startup."""
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from conftest import SAMPLES
from bastion.web import server
from bastion.web.server import _State, _make_handler


@pytest.fixture()
def base(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    state.run_analysis()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state, f"http://127.0.0.1:{httpd.server_address[1]}", httpd.server_address[1]
    httpd.shutdown(); httpd.server_close(); state.close()


def _raw(port, request: bytes) -> bytes:
    """Send raw bytes; return what the server wrote before closing (b"" = dropped)."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request)
        chunks = []
        try:
            while chunk := s.recv(65536):
                chunks.append(chunk)
        except socket.timeout:
            pass
    return b"".join(chunks)


# ITEM-2 --------------------------------------------------------------------
@pytest.mark.parametrize("request_line,extra", [
    (b"GET http://[/x HTTP/1.1", b""),                                   # do_GET urlparse
    (b"POST http://[/x HTTP/1.1", b"Sec-Fetch-Site: cross-site\r\n"),    # _request_allowed urlparse
    (b"GET http://[/x HTTP/1.1", b"Sec-Fetch-Site: same-site\r\n"),
])
def test_malformed_target_gets_an_error_response(base, request_line, extra):
    _, _, port = base
    reply = _raw(port, request_line + b"\r\nHost: 127.0.0.1\r\n" + extra + b"\r\n")
    assert reply.startswith(b"HTTP/1.") and b" 400 " in reply.split(b"\r\n")[0], reply[:80]
    # the server keeps serving afterwards
    assert b"HTTP/1.0 200" in _raw(port, b"GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")


# ITEM-16 -------------------------------------------------------------------
def _headers(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read(), r.headers


def test_dashboard_pages_and_assets_carry_csp_and_frame_deny(base):
    _, url, _ = base
    for path in ("/", "/runs.html", "/app.js", "/runs.js", "/sentinel.js", "/styles.css"):
        status, _, h = _headers(url + path)
        assert status == 200, path
        csp = h.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp, path
        assert h.get("X-Frame-Options") == "DENY", path
        assert h.get("X-Content-Type-Options") == "nosniff", path


def test_report_md_download_has_nosniff_and_frame_deny(base):
    _, url, _ = base
    status, _, h = _headers(url + "/api/report.md")
    assert status == 200
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in h.get("Content-Security-Policy", "")


def test_csp_keeps_inline_style_only_no_inline_script(base):
    """The CSP must not break the dashboard: its scripts are external files, and only
    styles are inline (runs.html <style>, style="" attributes built by app.js/runs.js)."""
    _, url, _ = base
    for page in ("/", "/runs.html"):
        html = _headers(url + page)[1].decode()
        assert not re.search(r"<script(?![^>]*\ssrc=)[^>]*>", html), page
        assert not re.search(r"\son[a-z]+\s*=", html), page
        for src in re.findall(r'<script src="([^"]+)"', html):
            assert _headers(url + "/" + src)[0] == 200, src


# ITEM-18 -------------------------------------------------------------------
def test_handler_has_socket_timeout():
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    try:
        assert 0 < _make_handler(state).timeout <= 300
    finally:
        state.close()


def test_staged_upload_has_per_slot_byte_quota(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None,
                   max_upload_mb=1)                  # quota = 4 x 1 MB per slot
    try:
        tok = state.stage_reset()
        chunk = "x" * (1 << 20)
        for i in range(4):
            state.stage_add(f"f{i}.log", chunk, token=tok)
        with pytest.raises(ValueError, match="exceed"):
            state.stage_add("overflow.log", chunk, token=tok)
    finally:
        state.close()


# ITEM-20 -------------------------------------------------------------------
def _dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _make_leftovers(tmp):
    dead = _dead_pid()
    stale = [tmp / f"bastion_stage_p{dead}_abcd1234", tmp / f"bastion_upload_p{dead}_efgh5678"]
    live = tmp / f"bastion_stage_p{os.getpid()}_ijkl9012"
    other = tmp / "keep_me"
    for d in (*stale, live, other):
        d.mkdir()
        (d / "secret.log").write_text("token=abc")
    return stale, live, other


def test_sweep_removes_only_dead_server_staging_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    stale, live, other = _make_leftovers(tmp_path)
    server.sweep_stale_uploads()
    assert not any(d.exists() for d in stale)
    assert live.exists() and other.exists()


def test_serve_sweeps_at_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    stale, live, _ = _make_leftovers(tmp_path)

    def busy(*_a):  # stop serve() right after the startup sweep
        raise OSError("address in use")
    monkeypatch.setattr(server, "_make_server", busy)
    assert server.serve([SAMPLES], port=1, llm_mode="off") is None
    assert not any(d.exists() for d in stale)
    assert live.exists()
