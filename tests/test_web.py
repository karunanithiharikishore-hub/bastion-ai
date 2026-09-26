# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
import json
import threading
import urllib.request
import urllib.error

import pytest

from conftest import SAMPLES
from bluecell.web.server import _State, _make_handler
from http.server import ThreadingHTTPServer


@pytest.fixture()
def server():
    state = _State([SAMPLES], window=120, llm_mode="off",
                   model="x", intel_db=None)
    state.run_analysis()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown(); httpd.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read().decode("utf-8"), dict(r.headers)


def test_index_served_with_watermark(server):
    status, body, _ = _get(server + "/")
    assert status == 200
    assert "BlueCell" in body
    assert "Harikishore Karunanithi" in body   # watermark in page


def test_api_report_shape(server):
    status, body, headers = _get(server + "/api/report")
    assert status == 200
    data = json.loads(body)
    assert data["meta"]["author"] == "Harikishore Karunanithi"
    assert data["swarm"]["agent_count"] >= 10
    assert data["incidents"]
    assert headers.get("X-BlueCell-Author") == "Harikishore Karunanithi"


def test_api_meta(server):
    status, body, _ = _get(server + "/api/meta")
    data = json.loads(body)
    assert data["author"] == "Harikishore Karunanithi"
    assert "BLUECELL::AUTHOR" in data["watermark"]


def test_static_js_and_css(server):
    for path in ("/app.js", "/styles.css"):
        status, body, headers = _get(server + path)
        assert status == 200
        assert "Harikishore Karunanithi" in body


def test_path_traversal_blocked(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(server + "/../../../../etc/passwd")
    assert exc.value.code == 404
