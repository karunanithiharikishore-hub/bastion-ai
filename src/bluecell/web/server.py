# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Dependency-free local web dashboard.

A small ThreadingHTTPServer that:
- serves the single-page dashboard (static files in web/static/), and
- exposes a read-only JSON API that runs the BlueCell pipeline + agent swarm.

Security posture: binds to 127.0.0.1 by default, GET-only, no file writes, no
shell. It analyzes the log paths configured at launch; the browser cannot point
it at arbitrary filesystem paths.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .. import __version__, provenance
from ..analyzer import analyze
from ..intel import IntelStore
from ..llm import LLMBackbone, BackboneUnavailable

_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
           ".css": "text/css; charset=utf-8", ".json": "application/json",
           ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class _State:
    """Holds launch config + the most recent analysis result (thread-safe)."""
    def __init__(self, paths, window, llm_mode, model, intel_db):
        self.paths = paths
        self.window = window
        self.llm_mode = llm_mode
        self.model = model
        self.intel_db = intel_db
        self.lock = threading.Lock()
        self.result = None
        self.error = None

    def _backbone(self):
        if self.llm_mode == "off":
            return None
        try:
            return LLMBackbone(mode=self.llm_mode, model=self.model)
        except BackboneUnavailable:
            return None

    def run_analysis(self) -> dict:
        with self.lock:
            try:
                intel = IntelStore(self.intel_db) if self.intel_db else IntelStore()
                self.result = analyze(
                    self.paths, window_minutes=self.window,
                    backbone=self._backbone(), intel_store=intel,
                    run_agents=True, use_llm=(self.llm_mode != "off"),
                )
                self.error = None
            except Exception as exc:  # never crash the server
                self.error = f"{type(exc).__name__}: {exc}"
                self.result = None
            return self.result


def _make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"BlueCell/{__version__}"

        def log_message(self, *args):  # keep the console quiet
            pass

        def _send(self, code, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-BlueCell-Author", provenance.AUTHOR)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str).encode("utf-8"),
                       "application/json")

        def _static(self, rel):
            rel = rel.lstrip("/") or "index.html"
            # Prevent path traversal.
            safe = os.path.normpath(os.path.join(_STATIC, rel))
            if not safe.startswith(_STATIC) or not os.path.isfile(safe):
                self._send(404, b"not found", "text/plain")
                return
            ext = os.path.splitext(safe)[1].lower()
            with open(safe, "rb") as fh:
                self._send(200, fh.read(), _CTYPES.get(ext, "application/octet-stream"))

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            route = urlparse(self.path)
            path = route.path
            if path == "/api/report":
                res = state.result or state.run_analysis()
                if res is None:
                    self._json({"error": state.error or "analysis failed"}, 500)
                else:
                    self._json(res)
            elif path == "/api/refresh":
                res = state.run_analysis()
                self._json(res if res else {"error": state.error}, 200 if res else 500)
            elif path == "/api/meta":
                self._json({
                    "version": __version__, "author": provenance.AUTHOR,
                    "watermark": provenance.WATERMARK,
                    "paths": state.paths, "window": state.window,
                    "llm_mode": state.llm_mode,
                })
            elif path in ("/", "/index.html"):
                self._static("index.html")
            else:
                self._static(path)

    return Handler


def serve(paths, host="127.0.0.1", port=8787, window=60, llm_mode="off",
          model="claude-sonnet-5", intel_db=None, open_browser=False):
    """Start the dashboard server (blocking). Returns the httpd if non-blocking use is needed."""
    provenance.enforce(strict=True)
    state = _State(paths, window, llm_mode, model, intel_db)
    state.run_analysis()  # warm the cache at startup
    httpd = ThreadingHTTPServer((host, port), _make_handler(state))
    url = f"http://{host}:{port}"
    print(provenance.banner())
    print(f"\n[bluecell] dashboard serving at {url}")
    print(f"[bluecell] analyzing: {paths}  (window={window}m, llm={llm_mode})")
    if state.error:
        print(f"[bluecell] WARNING: initial analysis error: {state.error}")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[bluecell] shutting down.")
    finally:
        httpd.server_close()
    return httpd
