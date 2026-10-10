# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Dependency-free local web dashboard.

A small ThreadingHTTPServer that:
- serves the single-page dashboard (static files in web/static/), and
- exposes a read-only JSON API that runs the Bastion AI pipeline + agent swarm.

Security posture: binds to 127.0.0.1 by default, no shell. Uploaded logs are
written only to private temp dirs (removed after each run and on shutdown);
cross-site requests are refused. It analyzes the log paths configured at launch
or uploaded files; the browser cannot point it at arbitrary filesystem paths.
"""
from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import signal
import socket
import sys
import tempfile
import threading
import uuid
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .. import __version__, provenance, tracing
from ..analyzer import analyze
from ..intel import IntelStore
from ..llm import LLMBackbone, BackboneUnavailable
from ..report import render_markdown

_STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_CTYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
           ".css": "text/css; charset=utf-8", ".json": "application/json",
           ".svg": "image/svg+xml", ".ico": "image/x-icon"}


_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"


def _tmpdir(kind):
    """Private staging dir named with the owning pid, so a later start can tell leftovers of a dead server."""
    return tempfile.mkdtemp(prefix=f"bastion_{kind}_p{os.getpid()}_")


_STALE = re.compile(r"bastion_(?:stage|upload)_p(\d+)_")


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # alive, owned by another user
        pass
    return True


def sweep_stale_uploads():
    """Remove staged-upload dirs whose server died without cleanup (kill -9, OOM, power loss)."""
    tmp = tempfile.gettempdir()
    for name in os.listdir(tmp):
        m = _STALE.match(name)
        if m and not _pid_alive(int(m.group(1))):
            shutil.rmtree(os.path.join(tmp, name), ignore_errors=True)


class _State:
    """Holds launch config + recent analysis results (thread-safe)."""
    _KEEP_RESULTS = 8    # recent results kept so /api/report.md?id= matches the screen
    _MAX_STAGES = 32     # concurrent staging slots (oldest is dropped beyond this)

    def __init__(self, paths, window, llm_mode, model, intel_db, max_upload_mb=256,
                 orchestration="auto", votes=1, tier1_model=None, allow_hosts=None,
                 max_agents=None, max_commander_turns=None, budget_seconds=None):
        self.paths = paths
        self.commander = dict(max_agents=max_agents, max_commander_turns=max_commander_turns,
                              budget_seconds=budget_seconds)  # None = analyzer default
        self.allow_hosts = allow_hosts or set(_LOOPBACK)  # Host names served (DNS rebinding guard)
        self.window = window
        self.llm_mode = llm_mode
        self.orchestration = orchestration   # auto | commander | fixed
        self.votes = max(1, int(votes or 1))  # Tier-2 self-consistency runs
        self.tier1_model = tier1_model
        self.model = model
        self.intel_db = intel_db
        self.max_upload_mb = max(1, int(max_upload_mb))
        self.max_upload = self.max_upload_mb * 1024 * 1024  # request-body cap
        self.max_stage = 4 * self.max_upload  # staged characters per slot
        self.lock = threading.Lock()
        self.result = None       # last *good* result (failures never clear it)
        self.results = OrderedDict()   # result_id -> result, bounded
        self.error = None
        self.stages = OrderedDict()    # token -> [dir, count]; "" = default slot
        self.stage_lock = threading.Lock()  # guards stages/inflight only; never held during analysis
        self.inflight = set()          # staged dirs under analysis, removed by close() too

    def _backbone(self):
        if self.llm_mode == "off":
            return None
        try:
            return LLMBackbone(mode=self.llm_mode, model=self.model)
        except BackboneUnavailable:
            return None

    def _analyze_paths(self, paths, window, label=None):
        intel = IntelStore(self.intel_db) if self.intel_db else IntelStore()
        with tracing.input_names([label] if label else []):
            return analyze(
                paths, window_minutes=window,
                backbone=self._backbone(), intel_store=intel,
                run_agents=True, use_llm=(self.llm_mode != "off"),
                orchestration=self.orchestration, votes=self.votes,
                tier1_model=self.tier1_model, **self.commander,
            )

    def _run(self, paths, window, label=None):
        """Analyze under the lock; record a good result, or set error and
        return None while keeping the last good result for /api/report.md."""
        try:
            res = self._analyze_paths(paths, window, label)
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
    _ALLOWED_EXT = (".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".log", ".txt", ".syslog",
                    ".xml", ".cef", ".leef")   # keep in step with ingest_path
    _MAX_STEM = 150

    def _safe_name(self, name):
        # Leading dots are stripped: the loader skips dotfiles, and ".." is not a name.
        name = os.path.basename(str(name or "log.txt")).lstrip(".") or "log.txt"
        if os.path.splitext(name)[1].lower() not in _State._ALLOWED_EXT:
            name += ".log"
        stem, ext = os.path.splitext(name)
        # Budget in UTF-8 bytes (NAME_MAX is 255 bytes); "__N" and ext fit in the margin.
        return stem.encode()[:_State._MAX_STEM].decode(errors="ignore") + ext

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
        with self.stage_lock:
            token = uuid.uuid4().hex
            self.stages[token] = [_tmpdir("stage"), 0, 0]
            while len(self.stages) > self._MAX_STAGES:
                shutil.rmtree(self.stages.popitem(last=False)[1][0], ignore_errors=True)
            return token

    def stage_add(self, name, content, token=None) -> int:
        """Append one file to a staging slot. Returns files staged in it.
        No token = the shared default slot (older clients)."""
        with self.stage_lock:
            slot = self.stages.get(token or "")
            if slot is None:
                if token:
                    raise ValueError("unknown or expired staging token")
                slot = self.stages[""] = [_tmpdir("stage"), 0, 0]
            size = len(str(content or ""))
            if slot[2] + size > self.max_stage:
                raise ValueError(f"staged files exceed the {self.max_stage >> 20} MB limit "
                                 "for one run; run it or start a new staging slot")
            self._write_unique(slot[0], name, content)
            slot[1] += 1
            slot[2] += size
            return slot[1]

    def stage_run(self, window=None, token=None) -> dict:
        """Analyze a staging slot, then remove it."""
        window = window or self.window
        with self.stage_lock:
            slot = self.stages.pop(token or "", None)
            if slot is None and token:
                raise ValueError("unknown or expired staging token")
            if slot:
                self.inflight.add(slot[0])
        try:
            with self.lock:
                if not slot or slot[1] == 0:
                    raise ValueError("no files staged")
                return self._run([slot[0]], window, _upload_label(slot[0]))
        finally:
            if slot:
                with self.stage_lock:
                    self.inflight.discard(slot[0])
                shutil.rmtree(slot[0], ignore_errors=True)

    def run_on_uploads(self, files, window=None) -> dict:
        """One-shot batch (kept for API compatibility). For large/many files the
        staged endpoints (/api/stage/*) are preferred."""
        window = window or self.window
        with self.lock:
            tmp = _tmpdir("upload")
            try:
                safe_count = 0
                for f in files:
                    if not isinstance(f, dict):
                        continue
                    self._write_unique(tmp, f.get("name"), f.get("content", ""))
                    safe_count += 1
                if not safe_count:
                    raise ValueError("no usable files uploaded")
                return self._run([tmp], window, _upload_label(tmp))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def close(self):
        """Remove every staging dir (uploaded log content) - call on shutdown.
        Takes only stage_lock, so it does not wait for a running analysis."""
        with self.stage_lock:
            for folder, *_ in self.stages.values():
                shutil.rmtree(folder, ignore_errors=True)
            self.stages.clear()
            for folder in self.inflight:
                shutil.rmtree(folder, ignore_errors=True)


def _upload_label(folder):
    """Run label for staged uploads: the file names, not the (later deleted) temp dir."""
    names = sorted(os.listdir(folder))
    more = f" (+{len(names) - 2} more)" if len(names) > 2 else ""
    return "dashboard upload: " + ", ".join(names[:2]) + more


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _allowed_hosts(bind, extra=()):
    """Host names served. Loopback binds: loopback only. Other binds also accept the
    bind address, this machine's name and IPs, and --allow-host names."""
    if bind in _LOOPBACK:
        return set(_LOOPBACK)
    me = socket.gethostname()
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(me, None)}
    except OSError:
        ips = set()
    return set(_LOOPBACK) | {x.lower() for x in (bind, me, *ips, *extra)}


def _host_name(host_header: str) -> str:
    """Hostname part of a Host header ("127.0.0.1:8787", "[::1]:8787")."""
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h[1:]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


_MAX_WINDOW = 10 * 366 * 24 * 60  # minutes; larger values overflow timedelta downstream


def _int_or(value, default: int) -> int:
    """A positive window in minutes from a request body (default when absent)."""
    if value in (None, ""):
        return default
    try:
        n = int(value)  # OverflowError: Infinity
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"window must be an integer, got {value!r}")
    if n < 1:
        raise ValueError(f"window must be at least 1 minute, got {n}")
    if n > _MAX_WINDOW:
        raise ValueError(f"window must be at most {_MAX_WINDOW} minutes, got {n}")
    return n


def _opt_str(obj, key):
    """A request field that must be a string when present (None = absent)."""
    value = obj.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"Bastion AI/{__version__}"
        timeout = 60  # a stalled client must not hold its handler thread forever

        def log_message(self, *args):  # keep the console quiet
            pass

        def _send(self, code, body: bytes, ctype: str, extra=()):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Bastion-Author", provenance.AUTHOR)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", _CSP)
            for key, value in extra:
                self.send_header(key, value)
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
            if _host_name(host) not in state.allow_hosts:
                self._send(403, b"forbidden host", "text/plain")
                return False
            # A cross-site <img>/<link> can still fire a GET (e.g. /api/report,
            # which may start analysis); browsers label those with Sec-Fetch-Site.
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
            self._guard(self._get)

        def _guard(self, route_fn):
            """Backstop for every request: a malformed target or handler bug gets an error reply, never a dropped connection."""
            try:
                if self._request_allowed():
                    route_fn()
            except ValueError as exc:  # e.g. urlparse on "http://[/x"
                self._json({"error": f"bad request: {exc}"}, 400)
            except OSError as exc:  # e.g. disk full while staging an upload
                self._json({"error": f"could not store upload: {exc}"}, 500)
            except Exception as exc:
                self._json({"error": f"internal error: {type(exc).__name__}"}, 500)

        def _get(self):
            route = urlparse(self.path)
            path = route.path
            if path == "/api/report":  # read-only: analysis starts only via POST /api/refresh
                res = state.result
                if res is None:
                    self._json({"error": state.error or "no analysis yet: POST /api/refresh"}, 404)
                else:
                    self._json(res)
            elif path == "/api/report.md":
                # ?id= renders the exact analysis on screen, not just the latest.
                rid = (parse_qs(route.query).get("id") or [""])[0]
                res = state.get_result(rid) if rid else state.result  # GET never starts an analysis
                if res is None:
                    msg = b"report expired: re-run the analysis" if rid else b"no analysis yet: POST /api/refresh"
                    self._send(404, msg, "text/plain")
                    return
                import datetime
                md = render_markdown(res)
                fname = "bastion_IR_report_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".md"
                self._send(200, md.encode("utf-8"), "text/markdown; charset=utf-8",
                           [("Content-Disposition", f'attachment; filename="{fname}"')])
            elif path == "/api/meta":
                self._json({
                    "version": __version__, "author": provenance.AUTHOR,
                    "watermark": provenance.WATERMARK,
                    "paths": state.paths, "window": state.window,
                    "llm_mode": state.llm_mode,
                    "max_upload_mb": state.max_upload_mb,
                    "max_upload_bytes": state.max_upload,   # exact cap the client checks against
                    "orchestration": state.orchestration, "votes": state.votes,
                    "tier1_model": state.tier1_model,
                })
            elif path == "/api/runs":
                try:
                    limit = max(1, min(500, int(parse_qs(route.query).get("limit", ["100"])[0])))
                except ValueError:
                    limit = 100
                self._json({"runs": tracing.list_runs(limit=limit)})
            elif path.startswith("/api/runs/"):
                run = tracing.load_run(path[len("/api/runs/"):])
                if run is None:
                    self._json({"error": "run not found"}, 404)
                else:
                    self._json(run)
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
                # Discard (bounded) the unread body: closing with bytes unread makes the kernel
                # RST the socket, so the client never reads the 413 above.
                left = min(length, 4 * state.max_upload)
                while left > 0 and (chunk := self.rfile.read(min(left, 1 << 20))):
                    left -= len(chunk)
                self.close_connection = True
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
            self._guard(self._post)

        def _post(self):
            path = urlparse(self.path).path
            if path == "/api/refresh":  # re-runs the analysis, so POST (Origin-checked) not GET
                res = state.run_analysis()
                self._json(res if res else {"error": state.error}, 200 if res else 500); return
            # Preferred: staged upload — one file per request, then run.
            if path == "/api/stage/reset":
                token = state.stage_reset()
                self._json({"ok": True, "staged": 0, "token": token}); return
            if path == "/api/stage/add":
                p = self._read_json()
                if p is None:
                    return
                n = state.stage_add(_opt_str(p, "name"), _opt_str(p, "content"),
                                    _opt_str(p, "token"))
                self._json({"ok": True, "staged": n}); return
            if path == "/api/stage/run":
                p = self._read_json()
                if p is None:
                    return
                window = _int_or(p.get("window"), state.window)
                res = state.stage_run(window, _opt_str(p, "token"))
                self._json(res if res else {"error": state.error or "analysis failed"},
                           200 if res else 500); return
            # Back-compat: whole-batch upload in one request.
            if path == "/api/upload":
                p = self._read_json()
                if p is None:
                    return
                files = p.get("files", [])
                if files is None:
                    files = []
                if not isinstance(files, list):
                    raise ValueError("files must be a list")
                for f in files:
                    if isinstance(f, dict):
                        _opt_str(f, "name"); _opt_str(f, "content")
                res = state.run_on_uploads(files, _int_or(p.get("window"), state.window))
                self._json(res if res else {"error": state.error or "analysis failed"},
                           200 if res else 500); return
            self._send(404, b"not found", "text/plain")

    return Handler


class _V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _make_server(host, port, handler):
    """Bind an HTTP server; IPv6 literals (e.g. ::1) need an AF_INET6 socket."""
    return (_V6Server if ":" in host else ThreadingHTTPServer)((host, port), handler)


def _interrupt(signum, frame):
    raise KeyboardInterrupt  # routes SIGTERM/SIGHUP through serve()'s clean-shutdown path


def serve(paths, host="127.0.0.1", port=8787, window=60, llm_mode="off",
          model="claude-sonnet-5", intel_db=None, open_browser=False,
          max_upload_mb=256, orchestration="auto", votes=1, tier1_model=None, allow_host=(),
          max_agents=None, max_commander_turns=None, budget_seconds=None):
    """Start the dashboard server (blocking). Returns the httpd, or None if the
    address could not be bound."""
    provenance.enforce(strict=True)
    sweep_stale_uploads()
    allow = _allowed_hosts(host, allow_host)
    state = _State(paths, window, llm_mode, model, intel_db, max_upload_mb=max_upload_mb,
                   orchestration=orchestration, votes=votes, tier1_model=tier1_model,
                   allow_hosts=allow, max_agents=max_agents,
                   max_commander_turns=max_commander_turns, budget_seconds=budget_seconds)
    if llm_mode != "off" and state._backbone() is None:
        if llm_mode != "auto":  # an explicit backbone must not silently fall back to rules
            print(f"[bastion] WARNING: --llm {llm_mode} requested but that backbone is "
                  "unavailable; serving deterministic (rules-only) results.", file=sys.stderr)
        state.llm_mode = "off"  # banner and /api/meta report the mode actually in use
    try:
        httpd = _make_server(host, port, _make_handler(state))
    except OSError as exc:
        print(f"[bastion] cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return None
    state.run_analysis()  # warm the cache at startup
    url = f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"
    print(provenance.banner())
    print(f"\n[bastion] dashboard serving at {url}")
    if host not in _LOOPBACK:
        print("[bastion] WARNING: listening beyond localhost. The dashboard has NO "
              "authentication: anyone who can reach this port can read the analysis and "
              "upload logs. Use only on a trusted network (Host allowed: "
              f"{', '.join(sorted(allow))}; add more with --allow-host).", file=sys.stderr)
    print(f"[bastion] analyzing: {paths}  (window={window}m, llm={state.llm_mode})")
    if state.error:
        print(f"[bastion] WARNING: initial analysis error: {state.error}")
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    # `kill`/systemd/docker stop send SIGTERM; SIGHUP is a terminal hangup. Both must clean up
    # staged uploads like Ctrl-C does. Handlers only install on the main thread.
    prev = {}
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            try:
                prev[getattr(signal, name)] = signal.signal(getattr(signal, name), _interrupt)
            except ValueError:  # not the main thread
                pass
    atexit.register(state.close)  # backstop for exits that bypass the finally below
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[bastion] shutting down.")
    finally:
        httpd.server_close()
        state.close()
        atexit.unregister(state.close)
        for sig, handler in prev.items():
            if handler is not None:  # None = previous handler was set outside Python
                signal.signal(sig, handler)
    return httpd
