"""BUG-WEB-7: dashboard uploads must be listed under their file names, not the temp staging dir."""
import json
import os
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bastion import tracing
from bastion.web.server import _State, _make_handler, _upload_label

LINE = "Jan  1 00:00:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n"


@pytest.fixture()
def base(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))
    state = _State([], window=60, llm_mode="off", model="x", intel_db=None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def _latest_run(base):
    with urllib.request.urlopen(base + "/api/runs?limit=1", timeout=10) as r:
        return json.loads(r.read())["runs"][0]


def test_batch_upload_run_is_labelled_with_file_names(base):
    _post(base, "/api/upload", {"files": [
        {"name": "auth.log", "content": LINE},
        {"name": "dns.jsonl", "content": "{}\n"},
        {"name": "x.log", "content": LINE}]})
    run = _latest_run(base)
    assert run["inputs"] == ["dashboard upload: auth.log, dns.jsonl (+1 more)"]
    assert tracing.input_label(run["inputs"]) == run["inputs"][0]


def test_staged_upload_run_is_labelled_and_temp_dir_is_gone(base):
    tok = _post(base, "/api/stage/reset", {})["token"]
    _post(base, "/api/stage/add", {"token": tok, "name": "secret.log", "content": LINE})
    _post(base, "/api/stage/run", {"token": tok})
    run = _latest_run(base)
    assert run["inputs"] == ["dashboard upload: secret.log"]
    assert "bastion_" not in run["inputs"][0]


def test_upload_label_truncates_long_lists():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        for n in ("a.log", "b.log", "c.log"):
            open(os.path.join(d, n), "w").close()
        assert _upload_label(d) == "dashboard upload: a.log, b.log (+1 more)"


def test_label_override_does_not_leak_into_later_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))
    t1 = t2 = None
    try:
        with tracing.input_names(["dashboard upload: x.log"]):
            t1 = tracing.start_run(["/tmp/real.log"], persist=False)
        assert t1.inputs == ["dashboard upload: x.log"]
        t2 = tracing.start_run(["/tmp/real.log"], persist=False)
        assert t2.inputs == ["/tmp/real.log"]
    finally:
        for t in (t1, t2):
            if t is not None:
                tracing.end_run(t)
