"""serve() must answer immediately while the startup analysis runs in the background."""
import json
import threading
import time
import urllib.error
import urllib.request

from bastion.web import server


def _start(monkeypatch, tmp_path, calls):
    def slow(self, paths, window, label=None):
        calls.append(1)
        time.sleep(3)
        return {"meta": {}, "ok": True}
    monkeypatch.setattr(server._State, "_analyze_paths", slow)
    box = {}
    real = server._make_server
    monkeypatch.setattr(server, "_make_server", lambda *a: box.setdefault("h", real(*a)))
    log = tmp_path / "a.log"; log.write_text("x\n")
    t = threading.Thread(target=server.serve, args=([str(log)],),
                         kwargs=dict(port=0), daemon=True)
    t.start()
    while "h" not in box:
        time.sleep(0.02)
    return box["h"], f"http://127.0.0.1:{box['h'].server_address[1]}"


def _get(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}") if r.headers.get_content_type() == "application/json" else None
    except urllib.error.HTTPError as e:
        return e.code, None


def test_nonblocking_startup(monkeypatch, tmp_path):
    calls = []
    httpd, base = _start(monkeypatch, tmp_path, calls)
    try:
        t0 = time.time()
        assert _get(base + "/")[0] == 200
        assert _get(base + "/api/meta")[0] == 200
        assert time.time() - t0 < 1.5
        assert _get(base + "/api/report") == (202, {"pending": True})      # (3)
        st, res = _get(base + "/api/refresh", "POST")                      # (2) waits, no 2nd run
        assert st == 200 and res["ok"] and len(calls) == 1
        assert _get(base + "/api/report")[1]["ok"]
    finally:
        httpd.shutdown()
