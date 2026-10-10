"""BUG-WEB-6: a huge "window" in a request must be a 400 JSON error, never a 500/OverflowError."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bastion.web.server import _State, _make_handler


@pytest.fixture
def base_url():
    state = _State([], window=60, llm_mode="off", model="x", intel_db=None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _post(base, path, body_text):
    req = urllib.request.Request(base + path, data=body_text.encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.mark.parametrize("path", ["/api/stage/run", "/api/upload"])
@pytest.mark.parametrize("window", ["1000000000000000000", "99999999999999", "1e400", "-5", "0"])
def test_bad_window_is_400_json(base_url, path, window):
    code, payload = _post(base_url, path, '{"window": %s, "files": []}' % window)
    assert code == 400, payload
    assert payload["error"].startswith("bad request: window must be")


def test_huge_window_message_names_the_bound(base_url):
    code, payload = _post(base_url, "/api/stage/run", '{"window": 1000000000000000000}')
    assert code == 400
    assert "at most 5270400 minutes" in payload["error"]


def test_max_window_is_accepted(base_url):
    # Not rejected as a bad window: with nothing staged the run answers 400 "no files staged".
    code, payload = _post(base_url, "/api/stage/run", '{"window": 5270400}')
    assert payload == {"error": "bad request: no files staged"}
