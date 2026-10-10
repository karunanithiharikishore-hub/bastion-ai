"""ITEM-17: /api/refresh re-runs the analysis, so it is a POST (Origin-checked), not a GET."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from conftest import SAMPLES
from bluecell.web.server import _State, _make_handler


@pytest.fixture()
def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUECELL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    state = _State([SAMPLES], window=120, llm_mode="off", model="x", intel_db=None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown(); httpd.server_close(); state.close()


def _req(port, method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(method, path, body=None, headers=headers or {})
    r = conn.getresponse()
    status, data = r.status, r.read()
    conn.close()
    return status, data


def test_get_refresh_is_refused(srv):
    status, _ = _req(srv, "GET", "/api/refresh")
    assert status != 200


def test_post_refresh_same_origin_runs_analysis(srv):
    port = srv
    origin = f"http://127.0.0.1:{port}"
    status, data = _req(srv, "POST", "/api/refresh",
                        {"Origin": origin, "Sec-Fetch-Site": "same-origin"})
    assert status == 200
    body = json.loads(data)
    assert "error" not in body and body.get("meta", {}).get("result_id")


def test_post_refresh_cross_origin_refused(srv):
    status, _ = _req(srv, "POST", "/api/refresh", {"Origin": "http://evil.example"})
    assert status == 403
