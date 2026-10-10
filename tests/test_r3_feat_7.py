"""BUG-R3-FEAT-7: no usable upload / empty staging slot must be a 400 JSON error, not a 500."""
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


@pytest.mark.parametrize("body", ['{"files": []}', '{"files": [null, 1]}'])
def test_upload_without_usable_files_is_400(base_url, body):
    code, payload = _post(base_url, "/api/upload", body)
    assert code == 400, payload
    assert payload == {"error": "bad request: no usable files uploaded"}


def test_stage_run_with_empty_slot_is_400(base_url):
    code, payload = _post(base_url, "/api/stage/run", '{"window": 60}')
    assert code == 400, payload
    assert payload == {"error": "bad request: no files staged"}
