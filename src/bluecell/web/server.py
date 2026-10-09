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
from ..report import render_markdown

_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
           ".css": "text/css; charset=utf-8", ".json": "application/json",
           ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class _State:
    """Holds launch config + the most recent analysis result (thread-safe)."""
    def __init__(self, paths, window, llm_mode, model, intel_db, max_upload_mb=256,
                 orchestration="auto"):
        self.paths = paths
        self.window = window
        self.llm_mode = llm_mode
        self.orchestration = orchestration
        self.model = model
        self.intel_db = intel_db
        self.max_upload = max(1, int(max_upload_mb)) * 1024 * 1024  # per-request cap
        self.lock = threading.Lock()
        self.result = None
        self.error = None
        self.stage_dir = None
        self.stage_count = 0

    def _backbone(self):
        if self.llm_mode == "off":
            return None
        try:
            return LLMBackbone(mode=self.llm_mode, model=self.model)
        except BackboneUnavailable:
            return None

    def _analyze_paths(self, paths, window):
        intel = IntelStore(self.intel_db) if self.intel_db else IntelStore()
        return analyze(
            paths, window_minutes=window,
            backbone=self._backbone(), intel_store=intel,
            run_agents=True, use_llm=(self.llm_mode != "off"),
            orchestration=self.orchestration,
        )

    def run_analysis(self) -> dict:
        with self.lock:
            try:
                self.result = self._analyze_paths(self.paths, self.window)
                self.error = None
            except Exception as exc:  # never crash the server
                self.error = f"{type(exc).__name__}: {exc}"
                self.result = None
            return self.result

    # ---- staged upload (scales to many / large files) ----------------------
    _ALLOWED_EXT = (".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".syslog")

    def _safe_name(self, name):
        name = os.path.basename(str(name or "log.txt")) or "log.txt"
        if os.path.splitext(name)[1].lower() not in self._ALLOWED_EXT:
            name += ".log"
        return name

    def stage_reset(self) -> str:
        """Start a fresh staging dir; return its path."""
        import tempfile, shutil
        with self.lock:
            if getattr(self, "stage_dir", None):
                shutil.rmtree(self.stage_dir, ignore_errors=True)
            self.stage_dir = tempfile.mkdtemp(prefix="bluecell_stage_")
            self.stage_count = 0
            return self.stage_dir

    def stage_add(self, name, content) -> int:
        """Append one file to the current staging dir. Returns files staged."""
        with self.lock:
            if not getattr(self, "stage_dir", None):
                import tempfile
                self.stage_dir = tempfile.mkdtemp(prefix="bluecell_stage_")
                self.stage_count = 0
            # De-duplicate names so identical basenames don't clobber.
            base = self._safe_name(name)
            path = os.path.join(self.stage_dir, base)
            n = 1
            while os.path.exists(path):
                stem, ext = os.path.splitext(base)
                path = os.path.join(self.stage_dir, f"{stem}__{n}{ext}"); n += 1
            with open(path, "w", encoding="utf-8", errors="replace") as out:
                out.write(str(content or ""))
            self.stage_count = getattr(self, "stage_count", 0) + 1
            return self.stage_count

    def stage_run(self, window=None) -> dict:
        """Analyze the staged dir, then clear staging."""
        import shutil
        window = window or self.window
        with self.lock:
            sd = getattr(self, "stage_dir", None)
            if not sd or getattr(self, "stage_count", 0) == 0:
                self.error = "no files staged"; self.result = None; return None
            try:
                self.result = self._analyze_paths([sd], window)
                self.error = None
            except Exception as exc:
                self.error = f"{type(exc).__name__}: {exc}"; self.result = None
            finally:
                shutil.rmtree(sd, ignore_errors=True)
                self.stage_dir = None; self.stage_count = 0
            return self.result

    def run_on_uploads(self, files, window=None) -> dict:
        """One-shot batch (kept for API compatibility). For large/many files the
        staged endpoints (/api/stage/*) are preferred."""
        import tempfile, shutil
        window = window or self.window
        with self.lock:
            tmp = tempfile.mkdtemp(prefix="bluecell_upload_")
            try:
                safe_count = 0
                for f in files:
                    with open(os.path.join(tmp, self._safe_name(f.get("name"))),
                              "w", encoding="utf-8", errors="replace") as out:
                        out.write(str(f.get("content", "")))
                    safe_count += 1
                if not safe_count:
                    self.error = "no usable files uploaded"; self.result = None; return None
                self.result = self._analyze_paths([tmp], window)
                self.error = None
            except Exception as exc:
                self.error = f"{type(exc).__name__}: {exc}"; self.result = None
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            return self.result


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _host_name(host_header: str) -> str:
    """Hostname part of a Host header ("127.0.0.1:8787", "[::1]:8787")."""
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h[1:]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _int_or(value, default: int) -> int:
    """A positive window in minutes from a request body (default when absent)."""
    if value in (None, ""):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"window must be an integer, got {value!r}")
    if n < 1:
        raise ValueError(f"window must be at least 1 minute, got {n}")
    return n


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

        def _request_allowed(self) -> bool:
            """Block cross-site use of the local dashboard. When bound to loopback,
            only localhost Host headers are served (defeats DNS rebinding), and a
            POST carrying an Origin must come from the dashboard itself (a page on
            another site cannot upload logs or start an analysis)."""
            host = self.headers.get("Host", "")
            if self.server.server_address[0] in _LOOPBACK and _host_name(host) not in _LOOPBACK:
                self._send(403, b"forbidden host", "text/plain")
                return False
            origin = self.headers.get("Origin")
            if self.command == "POST" and origin and origin.lower() != f"http://{host}".lower():
                self._send(403, b"cross-origin request refused", "text/plain")
                return False
            return True

        def _static(self, rel):
            rel = rel.lstrip("/") or "index.html"
            # Prevent path traversal (compare against the directory WITH a separator,
            # so a sibling like "static_x" cannot pass a plain prefix check).
            safe = os.path.normpath(os.path.join(_STATIC, rel))
            if not safe.startswith(_STATIC + os.sep) or not os.path.isfile(safe):
                self._send(404, b"not found", "text/plain")
                return
            ext = os.path.splitext(safe)[1].lower()
            with open(safe, "rb") as fh:
                self._send(200, fh.read(), _CTYPES.get(ext, "application/octet-stream"))

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if not self._request_allowed():
                return
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
            elif path == "/api/report.md":
                res = state.result or state.run_analysis()
                if res is None:
                    self._send(500, (state.error or "analysis failed").encode(), "text/plain")
                    return
                import datetime
                md = render_markdown(res)
                fname = "bluecell_IR_report_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".md"
                body = md.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-BlueCell-Author", provenance.AUTHOR)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
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

        def _read_json(self):
            """Read + parse a JSON POST body, enforcing the per-request cap."""
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > state.max_upload:
                self._json({"error": f"request too large: {length} bytes "
                            f"(per-file limit {state.max_upload // (1024*1024)} MB). "
                            f"Upload files individually via the dashboard."}, 413)
                return None
            # Read in chunks so a big body doesn't stall on one call.
            buf = bytearray(); remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 1 << 20))
                if not chunk:
                    break
                buf.extend(chunk); remaining -= len(chunk)
            try:
                body = json.loads(bytes(buf).decode("utf-8", "replace"))
            except (ValueError, TypeError) as exc:
                self._json({"error": f"bad request: {exc}"}, 400)
                return None
            if not isinstance(body, dict):
                self._json({"error": "bad request: expected a JSON object"}, 400)
                return None
            return body

        def do_POST(self):
            if not self._request_allowed():
                return
            try:
                self._post()
            except ValueError as exc:
                self._json({"error": f"bad request: {exc}"}, 400)

        def _post(self):
            path = urlparse(self.path).path
            # Preferred: staged upload — one file per request, then run.
            if path == "/api/stage/reset":
                state.stage_reset(); self._json({"ok": True, "staged": 0}); return
            if path == "/api/stage/add":
                p = self._read_json()
                if p is None:
                    return
                n = state.stage_add(p.get("name"), p.get("content"))
                self._json({"ok": True, "staged": n}); return
            if path == "/api/stage/run":
                p = self._read_json()
                if p is None:
                    return
                window = _int_or(p.get("window"), state.window)
                res = state.stage_run(window)
                self._json(res if res else {"error": state.error or "analysis failed"},
                           200 if res else 500); return
            # Back-compat: whole-batch upload in one request.
            if path == "/api/upload":
                p = self._read_json()
                if p is None:
                    return
                res = state.run_on_uploads(p.get("files") or [],
                                           _int_or(p.get("window"), state.window))
                self._json(res if res else {"error": state.error or "analysis failed"},
                           200 if res else 500); return
            self._send(404, b"not found", "text/plain")

    return Handler


def serve(paths, host="127.0.0.1", port=8787, window=60, llm_mode="off",
          model="claude-sonnet-5", intel_db=None, open_browser=False,
          max_upload_mb=256, orchestration="auto"):
    """Start the dashboard server (blocking). Returns the httpd if non-blocking use is needed."""
    provenance.enforce(strict=True)
    state = _State(paths, window, llm_mode, model, intel_db, max_upload_mb=max_upload_mb,
                   orchestration=orchestration)
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
