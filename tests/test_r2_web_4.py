"""BUG-WEB-4: wrong-typed JSON fields must get a 400/500 JSON error, never a dropped connection."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from bastion.web import server as web
from bastion.web.server import _State, _make_handler, _int_or


@pytest.fixture
def base_url():
    state = _State([], window=120, llm_mode="off", model="x", intel_db=None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield state, httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def _post(port, path, raw):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        conn.request("POST", path, raw, {"Content-Type": "application/json"})
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read())
    finally:
        conn.close()


@pytest.mark.parametrize("path, body", [
    ("/api/stage/run", {"token": [1], "window": 5}),
    ("/api/stage/run", {"token": {"a": 1}}),
    ("/api/stage/run", '{"token":"x","window":Infinity}'),
    ("/api/stage/run", '{"window":NaN}'),
    ("/api/stage/run", {"window": 10 ** 14}),
    ("/api/stage/run", {"window": [5]}),
    ("/api/stage/add", {"token": ["t"], "name": "a.log", "content": "x"}),
    ("/api/stage/add", {"name": ["a.log"], "content": "x"}),
    ("/api/stage/add", {"name": "a.log", "content": {"x": 1}}),
    ("/api/upload", {"files": 5}),
    ("/api/upload", {"files": {"name": "a.log"}}),
    ("/api/upload", {"files": [{"name": 7, "content": "x"}]}),
    ("/api/upload", {"files": [{"name": "a.log", "content": ["x"]}]}),
])
def test_wrong_typed_fields_get_400_json(base_url, path, body):
    _, port = base_url
    raw = body if isinstance(body, str) else json.dumps(body)
    status, payload = _post(port, path, raw)
    assert status == 400
    assert "error" in payload and payload["error"].startswith("bad request")


def test_int_or_rejects_overflow_and_huge_values():
    for bad in (float("inf"), float("-inf"), float("nan"), [1], {}, 10 ** 14):
        with pytest.raises(ValueError):
            _int_or(bad, 60)
    assert _int_or("5", 60) == 5 and _int_or(None, 60) == 60


def test_unexpected_handler_error_returns_500_json(base_url, monkeypatch):
    state, port = base_url

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(state, "stage_run", boom)
    status, payload = _post(port, "/api/stage/run", "{}")
    assert status == 500
    assert payload == {"error": "internal error: RuntimeError"}
