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


def _post(url, obj):
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def test_upload_analyzes_dropped_logs(server):
    syslog = ("Sep 26 09:01:12 web01 sshd[1]: Failed password for admin from 203.0.113.66 port 41022 ssh2\n"
              "Sep 26 09:01:14 web01 sshd[2]: Failed password for admin from 203.0.113.66 port 41024 ssh2\n"
              "Sep 26 09:03:47 web01 sshd[3]: Accepted password for admin from 203.0.113.66 port 41120 ssh2\n")
    dns = '{"timestamp":"2026-09-26T09:06:12Z","source":"dns","host":"web01","src_ip":"10.0.0.11","query":"kj3h5g9x2zqwmnbvc7.top","answer":"198.51.100.7"}\n'
    status, data = _post(server + "/api/upload", {
        "files": [{"name": "auth.log", "content": syslog},
                  {"name": "dns.jsonl", "content": dns}],
        "window": 120,
    })
    assert status == 200
    assert data["meta"]["events_ingested"] >= 3
    assert data["meta"]["author"] == "Harikishore Karunanithi"
    assert "swarm" in data


def test_upload_rejects_empty(server):
    # No usable files -> server responds 500 with an error (urlopen raises on 5xx).
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(server + "/api/upload", {"files": []})
    assert exc.value.code == 500


def test_staged_upload_flow(server):
    # Reset -> add files one at a time -> run. This is how the dashboard uploads,
    # so large multi-file batches never hit a single-request size cap.
    s1, _ = _post(server + "/api/stage/reset", {})
    assert s1 == 200
    syslog = ("Sep 26 09:01:12 web01 sshd[1]: Failed password for admin from 203.0.113.66 port 41022 ssh2\n"
              "Sep 26 09:01:14 web01 sshd[2]: Failed password for admin from 203.0.113.66 port 41024 ssh2\n")
    dns = '{"timestamp":"2026-09-26T09:06:12Z","source":"dns","host":"web01","src_ip":"10.0.0.11","query":"kj3h5g9x2zqwmnbvc7.top"}\n'
    s2, d2 = _post(server + "/api/stage/add", {"name": "auth.log", "content": syslog})
    assert s2 == 200 and d2["staged"] == 1
    s3, d3 = _post(server + "/api/stage/add", {"name": "dns.jsonl", "content": dns})
    assert d3["staged"] == 2
    s4, d4 = _post(server + "/api/stage/run", {"window": 120})
    assert s4 == 200
    assert d4["meta"]["events_ingested"] >= 2
    assert d4["meta"]["author"] == "Harikishore Karunanithi"


def test_stage_run_without_files_errors(server):
    _post(server + "/api/stage/reset", {})
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(server + "/api/stage/run", {"window": 60})
    assert exc.value.code == 500
