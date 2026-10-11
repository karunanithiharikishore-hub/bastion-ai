"""Regression tests for hunt5 ITEM-4 (refresh mode / failed startup) and ITEM-5
(GET /api/report.md must not wait on a running analysis). Same server and
fake-analysis pattern as test_serve_nonblocking.py."""
import json
import threading
import time
import urllib.error
import urllib.request

from bastion.web import server


class _Fake:
    """Replaces the slow analysis and records the mode of every run. Can delay, fail
    the first run, or hold any run whose mode is `block_mode` until `release` is set."""

    def __init__(self, delay=0.0, fail_first=False, block_mode=None):
        self.delay, self.fail_first, self.block_mode = delay, fail_first, block_mode
        self.modes = []
        self.started = threading.Event()   # first run entered: startup is in flight
        self.blocked = threading.Event()   # a block_mode run is holding the analysis lock
        self.release = threading.Event()

    def __call__(self, state, paths, window, label=None):
        n = len(self.modes)
        self.modes.append(state.run_mode)
        self.started.set()
        if state.run_mode == self.block_mode:
            self.blocked.set()
            self.release.wait(20)
        if self.delay:
            time.sleep(self.delay)
        if self.fail_first and n == 0:
            raise RuntimeError("startup boom")
        return {"meta": {"mode": state.run_mode}, "ok": True}


def _serve(monkeypatch, tmp_path, fake, mode="quick"):
    monkeypatch.setattr(server._State, "_analyze_paths",
                        lambda self, paths, window, label=None: fake(self, paths, window, label))
    box = {}
    real = server._make_server
    monkeypatch.setattr(server, "_make_server", lambda *a: box.setdefault("h", real(*a)))
    log = tmp_path / "a.log"; log.write_text("x\n")
    t = threading.Thread(target=server.serve, args=([str(log)],),
                         kwargs=dict(port=0, mode=mode), daemon=True)
    t.start()
    while "h" not in box:
        time.sleep(0.02)
    fake.started.wait(10)  # startup run is in flight before the test sends requests
    return box["h"], f"http://127.0.0.1:{box['h'].server_address[1]}", t


def _stop(httpd, fake, thread):
    fake.release.set()
    httpd.shutdown()
    thread.join(10)


def _req(url, method="GET", body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.headers.get_content_type(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get_content_type(), e.read()


def test_deep_refresh_during_quick_startup_runs_deep(monkeypatch, tmp_path):
    fake = _Fake(delay=2)
    httpd, base, t = _serve(monkeypatch, tmp_path, fake, mode="quick")
    try:
        st, _, body = _req(base + "/api/refresh", "POST", {"mode": "deep"})
        assert st == 200 and json.loads(body)["meta"]["mode"] == "deep"
        assert fake.modes == ["quick", "deep"]
    finally:
        _stop(httpd, fake, t)


def test_matching_refresh_during_startup_reuses_startup_run(monkeypatch, tmp_path):
    fake = _Fake(delay=1)
    httpd, base, t = _serve(monkeypatch, tmp_path, fake, mode="quick")
    try:
        st, _, body = _req(base + "/api/refresh", "POST", {"mode": "quick"})
        assert st == 200 and json.loads(body)["meta"]["mode"] == "quick"
        assert fake.modes == ["quick"]  # no second paid run
    finally:
        _stop(httpd, fake, t)


def test_refresh_after_failed_startup_retries_instead_of_500(monkeypatch, tmp_path):
    fake = _Fake(delay=1, fail_first=True)
    httpd, base, t = _serve(monkeypatch, tmp_path, fake, mode="quick")
    try:
        st, _, body = _req(base + "/api/refresh", "POST", {})
        assert st == 200 and json.loads(body)["ok"]
        assert fake.modes == ["quick", "quick"]
    finally:
        _stop(httpd, fake, t)


def test_report_md_answers_while_analysis_runs(monkeypatch, tmp_path):
    fake = _Fake(block_mode="deep")
    monkeypatch.setattr(server, "render_markdown", lambda res: "# report\n")
    httpd, base, t = _serve(monkeypatch, tmp_path, fake, mode="quick")
    busy = None
    try:
        st, _, body = _req(base + "/api/refresh", "POST", {})
        rid = json.loads(body)["meta"]["result_id"]
        busy = threading.Thread(target=_req, args=(base + "/api/refresh", "POST", {"mode": "deep"}),
                                daemon=True)
        busy.start()
        assert fake.blocked.wait(10)  # second analysis now holds the analysis lock
        t0 = time.time()
        st, ctype, _ = _req(f"{base}/api/report.md?id={rid}", timeout=5)
        assert st == 200 and ctype == "text/markdown" and time.time() - t0 < 2
    finally:
        _stop(httpd, fake, t)
        if busy:
            busy.join(10)
