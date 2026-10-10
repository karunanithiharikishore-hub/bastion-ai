"""BUG-WEB-1: the dashboard's upload size check must use the exact JSON request body the server
caps. A file the UI accepts must never be rejected by the server with 413."""
import re
import json
import shutil
import subprocess
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from bastion.web.server import _State, _make_handler

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "src/bastion/web/static/app.js"
SAMPLE_LINE = (ROOT / "samples/dns.jsonl").read_bytes().split(b"\n", 1)[0] + b"\n"
CAP = 1 << 20  # --max-upload-mb 1

# Loads the real uploadBodyBytes() from app.js (no DOM needed) and prints the largest
# /api/stage/add body the client would accept, built exactly as postJSON() builds it.
NODE = r"""
const fs = require("fs");
const src = fs.readFileSync(process.argv[1], "utf8");
const start = src.indexOf("const TOKEN_LEN");
const end = src.indexOf("\n}\n", src.indexOf("function uploadBodyBytes")) + 3;
const uploadBodyBytes = new Function(src.slice(start, end) + "; return uploadBodyBytes;")();
const [token, line, cap] = [process.argv[2], process.argv[3], Number(process.argv[4])];
const name = "dns.jsonl";
const fits = (n) => uploadBodyBytes(name, line.repeat(n)) <= cap;
let lo = 0, hi = Math.ceil(cap / line.length) * 2;   // binary search: largest n that fits
while (lo < hi) { const mid = Math.ceil((lo + hi) / 2); if (fits(mid)) lo = mid; else hi = mid - 1; }
const content = line.repeat(lo);
const body = JSON.stringify({ token, name, content });
const repro = line.repeat(Math.floor(0.9 * cap / line.length));   // the 943,704-byte file in BUG-WEB-1
process.stdout.write(JSON.stringify({ body, bytes: uploadBodyBytes(name, content),
                                      repro: uploadBodyBytes(name, repro) }));
"""


@pytest.fixture
def base_url():
    state = _State([], window=120, llm_mode="off", model="x", intel_db=None, max_upload_mb=1)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_client_accepts_only_bodies_the_server_accepts(base_url):
    meta = json.loads(urllib.request.urlopen(base_url + "/api/meta").read())
    assert meta["max_upload_bytes"] == meta["max_upload_mb"] * 1024 * 1024 == CAP

    req = urllib.request.Request(base_url + "/api/stage/reset", data=b"{}", method="POST")
    token = json.loads(urllib.request.urlopen(req).read())["token"]
    assert len(token) == 32
    out = subprocess.run(["node", "-e", NODE, str(APP_JS), token, SAMPLE_LINE.decode(), str(CAP)],
                         capture_output=True, text=True, check=True, timeout=60)
    got = json.loads(out.stdout)

    # The old check (0.9 x raw size) accepted the 943,704-byte repro file; its JSON body is over the cap.
    assert got["repro"] > CAP
    # The largest file the client now accepts: its body is within the cap and the server takes it.
    assert got["bytes"] <= CAP and len(got["body"].encode()) == got["bytes"]
    req = urllib.request.Request(base_url + "/api/stage/add", data=got["body"].encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        assert r.status == 200
        assert json.loads(r.read()) == {"ok": True, "staged": 1}


def test_app_js_has_no_raw_size_headroom_check():
    src = APP_JS.read_text(encoding="utf-8")
    assert "* 0.9" not in src and "maxFile" not in src
    assert re.search(r"uploadBodyBytes\(\w+, reader\.result\)", src)
