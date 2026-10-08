# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Dependency-free local web dashboard.

A small ThreadingHTTPServer that:
- serves the single-page dashboard (static files in web/static/), and
- exposes a read-only JSON API that runs the BlueCell pipeline + agent swarm.

Security posture: binds to 127.0.0.1 by default, no shell. Uploaded logs are
written only to private temp dirs (removed after each run and on shutdown);
cross-site requests are refused. It analyzes the log paths configured at launch
or uploaded files; the browser cannot point it at arbitrary filesystem paths.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import uuid
from collections import OrderedDict
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
    """Holds launch config + recent analysis results (thread-safe)."""
    _KEEP_RESULTS = 8    # recent results kept so /api/report.md?id= matches the screen
    _MAX_STAGES = 32     # concurrent staging slots (oldest is dropped beyond this)

    def __init__(self, paths, window, llm_mode, model, intel_db, max_upload_mb=256):
        self.paths = paths
        self.window = window
        self.llm_mode = llm_mode
        self.model = model
        self.intel_db = intel_db
        self.max_upload_mb = max(1, int(max_upload_mb))
        self.max_upload = self.max_upload_mb * 1024 * 1024  # request-body cap
        self.lock = threading.Lock()
        self.result = None       # last *good* result (failures never clear it)
        self.results = OrderedDict()   # result_id -> result, bounded
        self.error = None
        self.stages = OrderedDict()    # token -> [dir, count]; "" = default slot

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
        )

    def _run(self, paths, window):
        """Analyze under the lock; record a good result, or set error and
        return None while keeping the last good result for /api/report.md."""
        try:
            res = self._analyze_paths(paths, window)
        except Exception as exc:  # never crash the server
            self.error = f"{type(exc).__name__}: {exc}"
            return None
        res.setdefault("meta", {})["result_id"] = uuid.uuid4().hex[:16]
        self.results[res["meta"]["result_id"]] = res
        while len(self.results) > self._KEEP_RESULTS:
            self.results.popitem(last=False)
        self.result, self.error = res, None
        return res

    def run_analysis(self) -> dict:
        with self.lock:
            return self._run(self.paths, self.window)

    def get_result(self, result_id):
        with self.lock:
            return self.results.get(result_id)

    # ---- staged upload (scales to many / large files) ----------------------
    _ALLOWED_EXT = (".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".syslog")
    _MAX_STEM = 150

    def _safe_name(self, name):
        # Leading dots are stripped: the loader skips dotfiles, and ".." is not a name.
        name = os.path.basename(str(name or "log.txt")).lstrip(".") or "log.txt"
        if os.path.splitext(name)[1].lower() not in _State._ALLOWED_EXT:
            name += ".log"
        stem, ext = os.path.splitext(name)
        return stem[:_State._MAX_STEM] + ext   # stay under filesystem name limits

    def _write_unique(self, folder, name, content):
        """Write one file into folder, de-duplicating identical basenames."""
        base = self._safe_name(name)
        path = os.path.join(folder, base)
        n = 1
        while os.path.exists(path):
            stem, ext = os.path.splitext(base)
            path = os.path.join(folder, f"{stem}__{n}{ext}"); n += 1
        with open(path, "w", encoding="utf-8", errors="replace") as out:
            out.write(str(content or ""))

    def stage_reset(self) -> str:
        """Start a fresh staging slot; return its token (sent back on add/run)."""
        with self.lock:
            token = uuid.uuid4().hex
            self.stages[token] = [tempfile.mkdtemp(prefix="bluecell_stage_"), 0]
            while len(self.stages) > self._MAX_STAGES:
                shutil.rmtree(self.stages.popitem(last=False)[1][0], ignore_errors=True)
            return token

    def stage_add(self, name, content, token=None) -> int:
        """Append one file to a staging slot. Returns files staged in it.
        No token = the shared default slot (older clients)."""
        with self.lock:
            slot = self.stages.get(token or "")
            if slot is None:
                if token:
                    raise ValueError("unknown or expired staging token")
                slot = self.stages[""] = [tempfile.mkdtemp(prefix="bluecell_stage_"), 0]
            self._write_unique(slot[0], name, content)
            slot[1] += 1
            return slot[1]

    def stage_run(self, window=None, token=None) -> dict:
        """Analyze a staging slot, then remove it."""
        window = window or self.window
        with self.lock:
            slot = self.stages.pop(token or "", None)
            if slot is None and token:
                raise ValueError("unknown or expired staging token")
            try:
                if not slot or slot[1] == 0:
                    self.error = "no files staged"; return None
                return self._run([slot[0]], window)
            finally:
                if slot:
                    shutil.rmtree(slot[0], ignore_errors=True)

    def run_on_uploads(self, files, window=None) -> dict:
        """One-shot batch (kept for API compatibility). For large/many files the
        staged endpoints (/api/stage/*) are preferred."""
        window = window or self.window
        with self.lock:
            tmp = tempfile.mkdtemp(prefix="bluecell_upload_")
            try:
                safe_count = 0
                for f in files:
                    if not isinstance(f, dict):
                        continue
                    self._write_unique(tmp, f.get("name"), f.get("content", ""))
                    safe_count += 1
                if not safe_count:
                    self.error = "no usable files uploaded"; return None
                return self._run([tmp], window)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def close(self):
        """Remove every staging dir (uploaded log content) - call on shutdown."""
        with self.lock:
            for folder, _ in self.stages.values():
                shutil.rmtree(folder, ignore_errors=True)
            self.stages.clear()


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
            # A cross-site <img>/<link> can still fire a GET (e.g. /api/refresh,
            # which re-runs analysis); browsers label those with Sec-Fetch-Site.
            site = (self.headers.get("Sec-Fetch-Site") or "").lower()
            if (site in ("cross-site", "same-site")
                    and urlparse(self.path).path.startswith("/api/")):
                self._send(403, b"cross-site request refused", "text/plain")
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
                # ?id= renders the exact analysis on screen, not just the latest.
                rid = (parse_qs(route.query).get("id") or [""])[0]
                res = state.get_result(rid) if rid else (state.result or state.run_analysis())
                if res is None:
                    if rid:
                        self._send(404, b"report expired: re-run the analysis", "text/plain")
                    else:
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
                    "max_upload_mb": state.max_upload_mb,
                })
            elif path in ("/", "/index.html"):
                self._static("index.html")
            else:
                self._static(path)

        def _read_json(self):
            """Read + parse a JSON POST body, enforcing the request-body cap."""
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0:
                self._json({"error": "bad request: empty body"}, 400)
                return None
            if length > state.max_upload:
                self._json({"error": f"request too large: {length} bytes (limit "
                            f"{state.max_upload_mb} MB per request, JSON-encoded; "
                            f"restart with a larger --max-upload-mb)"}, 413)
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
            except OSError as exc:  # e.g. disk full while staging an upload
                self._json({"error": f"could not store upload: {exc}"}, 500)

        def _post(self):
            path = urlparse(self.path).path
            # Preferred: staged upload — one file per request, then run.
            if path == "/api/stage/reset":
                token = state.stage_reset()
                self._json({"ok": True, "staged": 0, "token": token}); return
            if path == "/api/stage/add":
                p = self._read_json()
                if p is None:
                    return
                n = state.stage_add(p.get("name"), p.get("content"), p.get("token"))
                self._json({"ok": True, "staged": n}); return
            if path == "/api/stage/run":
                p = self._read_json()
                if p is None:
                    return
                window = _int_or(p.get("window"), state.window)
                res = state.stage_run(window, p.get("token"))
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


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _make_server(host, port, handler):
    """Bind an HTTP server; IPv6 literals (e.g. ::1) need an AF_INET6 socket."""
    return (_V6Server if ":" in host else ThreadingHTTPServer)((host, port), handler)


def serve(paths, host="127.0.0.1", port=8787, window=60, llm_mode="off",
          model="claude-sonnet-5", intel_db=None, open_browser=False,
          max_upload_mb=256):
    """Start the dashboard server (blocking). Returns the httpd, or None if the
    address could not be bound."""
    provenance.enforce(strict=True)
    state = _State(paths, window, llm_mode, model, intel_db, max_upload_mb=max_upload_mb)
    try:
        httpd = _make_server(host, port, _make_handler(state))
    except OSError as exc:
        print(f"[bluecell] cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return None
    state.run_analysis()  # warm the cache at startup
    url = f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"
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
        state.close()
    return httpd
