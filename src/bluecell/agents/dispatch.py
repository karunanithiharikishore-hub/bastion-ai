# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Dispatch tools for the Incident Commander, and the IPC that carries them.

The commander gets the read-only investigation tools plus four dispatch tools:
``list_roles``, ``deploy_agent``, ``deploy_agents`` and ``finish``. The
toolbox does not run agents itself; it forwards each dispatch call to a
``dispatch(op, args) -> dict`` function owned by the parent orchestrator:

- api : the commander's tool loop runs in-process, so ``dispatch`` is the
        orchestrator's ``Dispatcher.handle`` called directly.
- cli : the commander is a ``claude -p`` process and its tools are served by
        ``mcp_server.py``, a grandchild process that cannot run agents. The
        server's ``dispatch`` is a ``FileDispatchClient``: it writes
        ``<session>/dispatch/<id>.req.json`` (atomic rename) and blocks until
        ``<id>.res.json`` appears. In the parent, a ``FileDispatchServer``
        thread polls that directory, claims each request (rename to
        ``.taken``), runs it through ``Dispatcher.handle`` (which launches the
        worker agents) and writes the response atomically. The session dir is
        a private ``mkdtemp`` (0700), so only this run can drop requests in it.
        No sockets or ports; the MCP call simply stays open while the workers run
        (``MCP_TOOL_TIMEOUT`` is raised for the commander's ``claude`` process).

        Failure handling: every file is written to ``*.tmp`` and renamed, so no
        side ever reads a partial JSON. A request is claimed exactly once (the
        rename to ``.taken`` is atomic). A client that times out withdraws its
        request if it is still unclaimed, and returns at once if the session
        dir disappears (the parent closed the case). The polling loop survives
        handler/OS errors. When the commander stops, the parent closes its
        ``Dispatcher`` (late results are discarded, never merged), stops the
        thread, and answers any request still queued with an error.
"""
from __future__ import annotations

import contextvars
import json
import os
import threading
import time
import uuid

from .budget import MAX_TOOL_RESULT_CHARS
from .toolbox import SecurityToolbox, _obj, _STR, tool_specs

POLL_SECONDS = 0.2

COMMAND_TOOL_SPECS = [
    {"name": "list_roles",
     "description": "The worker roles you can deploy (with what each one does), the "
                    "log sources a Tier-1 analyst can own, and the remaining budget "
                    "(agents, wall-clock seconds).",
     "input_schema": _obj({})},
    {"name": "deploy_agent",
     "description": "Deploy ONE worker agent and wait for it to finish. Returns its "
                    "summary and the findings/verdicts it filed (already checked "
                    "against the evidence). Counts against the agent budget.",
     "input_schema": _obj({
         "role": dict(_STR, description="a role key from list_roles"),
         "reason": dict(_STR, description="why you are deploying it now (recorded "
                                          "in the case's decision log)"),
         "objective": dict(_STR, description="specific direction for the agent "
                                             "(required for 'investigator')"),
         "incident_id": dict(_STR, description="focus incident, optional"),
         "source": dict(_STR, description="log source (required for 'tier1-analyst')"),
     }, ["role", "reason"])},
    {"name": "deploy_agents",
     "description": "Deploy several worker agents IN PARALLEL and wait for all of them. "
                    "Each item takes the same fields as deploy_agent. The whole batch "
                    "is refused if it does not fit in the remaining budget.",
     "input_schema": _obj({
         "agents": {"type": "array", "items": _obj({
             "role": _STR, "reason": _STR, "objective": _STR,
             "incident_id": _STR, "source": _STR}, ["role", "reason"])},
     }, ["agents"])},
    {"name": "finish",
     "description": "Close the case: give your final summary (what was deployed, what "
                    "was concluded per incident, what remains open). No deploys are "
                    "accepted after this.",
     "input_schema": _obj({"summary": _STR}, ["summary"])},
]
COMMAND_TOOLS = tuple(t["name"] for t in COMMAND_TOOL_SPECS)


class CommanderToolbox(SecurityToolbox):
    """Read-only investigation tools + dispatch tools forwarded to ``dispatch``."""

    # A batch of worker results is larger than one investigation tool result.
    DISPATCH_RESULT_CHARS = 4 * MAX_TOOL_RESULT_CHARS

    def __init__(self, *a, dispatch=None, **kw):
        super().__init__(*a, **kw)
        self.dispatch = dispatch

    def specs(self) -> list:
        return tool_specs(self.tools) + [t for t in COMMAND_TOOL_SPECS
                                         if t["name"] in self.tools]

    def result_cap(self, name: str) -> int:
        return (self.DISPATCH_RESULT_CHARS if name in COMMAND_TOOLS
                else super().result_cap(name))

    # (text cap per field, findings kept per worker, evidence ids kept per item);
    # the first level that fits the result cap wins. Verdicts are never dropped.
    _SHRINK = ((None, None, None), (600, None, 10), (200, 10, 5), (80, 5, 3),
               (20, 2, 2), (0, 0, 0))

    def _forward(self, op: str, args: dict):
        if self.dispatch is None:
            return {"error": "dispatch is not available in this session"}
        out = self.dispatch(op, args)
        if not isinstance(out, dict) or not out.get("results"):
            return self._envelope(out)
        # toolbox.call cuts oversized text mid-JSON, so shrink the batch here instead.
        for cap, keep, keep_ev in self._SHRINK:
            trial = self._envelope(self._shrink(out, cap, keep, keep_ev))
            if len(json.dumps(trial, default=str)) <= self.DISPATCH_RESULT_CHARS:
                break
        # shortcut: a batch whose verdicts alone exceed the cap is still cut by toolbox.call, upgrade by paging the results
        return trial

    @staticmethod
    def _shrink(out: dict, cap, keep, keep_ev) -> dict:
        """A copy of a batch result with worker text, findings and evidence cut.
        Status, verdict decisions and the budget block are kept; every cut is marked."""
        def cut(s):
            if cap is None or len(s) <= cap:
                return s
            return s[:cap] + "..." if cap else ""

        results = []
        for res in out["results"]:
            res, notes = dict(res), set()
            for f in ("summary", "error"):
                if isinstance(res.get(f), str) and cut(res[f]) != res[f]:
                    res[f] = cut(res[f])
                    notes.add("text cut")
            findings = res.get("findings")
            if findings is not None and keep is not None and len(findings) > keep:
                notes.add(f"{len(findings) - keep} finding(s) omitted")
                res["findings"] = findings[:keep]
            for key in ("findings", "verdicts"):
                if not res.get(key):
                    continue
                items = []
                for it in res[key]:
                    it = dict(it)
                    for f in ("title", "rationale", "recommended_action"):
                        if isinstance(it.get(f), str) and cut(it[f]) != it[f]:
                            it[f] = cut(it[f])
                            notes.add("text cut")
                    if isinstance(it.get("evidence"), list) and keep_ev is not None \
                            and len(it["evidence"]) > keep_ev:
                        it["evidence"] = it["evidence"][:keep_ev]
                        notes.add("evidence cut")
                    items.append(it)
                res[key] = items
            if notes:
                res["trimmed"] = "; ".join(sorted(notes))
            results.append(res)
        return dict(out, results=results)

    # Worker-written text (summaries, titles, rationales, actions) can echo the
    # attacker-controlled logs the workers read: it reaches the commander only
    # inside this toolbox's nonce envelope, like every other log-derived text.
    _WORKER_TEXT = ("summary", "error", "title", "rationale", "recommended_action")

    def _envelope(self, out):
        if not isinstance(out, dict):
            return out
        for res in out.get("results") or []:
            self._wrap_fields(res, 1500)
            for f in (res.get("findings") or []) + (res.get("verdicts") or []):
                self._wrap_fields(f, 500)
        return out

    def _wrap_fields(self, obj: dict, cap: int) -> None:
        for k in self._WORKER_TEXT:
            if isinstance(obj.get(k), str) and obj[k]:
                obj[k] = self.env.wrap(obj[k], cap)

    def t_list_roles(self):
        return self._forward("list_roles", {})

    def t_deploy_agent(self, role, reason, objective=None, incident_id=None, source=None):
        out = self._forward("deploy", {"agents": [{
            "role": role, "reason": reason, "objective": objective,
            "incident_id": incident_id, "source": source}]})
        if "error" in out:
            return out
        return dict(out["results"][0], budget=out.get("budget"))

    def t_deploy_agents(self, agents):
        if isinstance(agents, str):
            try:
                agents = json.loads(agents)
            except json.JSONDecodeError:
                return {"error": "agents must be a list of {role, reason, ...} objects"}
        if isinstance(agents, dict):
            agents = [agents]
        if not isinstance(agents, list) or not agents:
            return {"error": "agents must be a non-empty list of {role, reason, ...}"}
        return self._forward("deploy", {"agents": agents})

    def t_finish(self, summary):
        return self._forward("finish", {"summary": summary})


# ---------------------------------------------------------------------------
# File IPC (CLI backbone)
# ---------------------------------------------------------------------------
def _write_atomic(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, default=str)
    os.replace(tmp, path)


def dispatch_dir(session_dir: str) -> str:
    return os.path.join(session_dir, "dispatch")


class FileDispatchClient:
    """MCP-server side: forward a dispatch call to the parent and wait."""

    def __init__(self, session_dir: str, timeout: float):
        self.dir = dispatch_dir(session_dir)
        self.timeout = timeout
        os.makedirs(self.dir, exist_ok=True)

    def __call__(self, op: str, args: dict) -> dict:
        rid = uuid.uuid4().hex
        req = os.path.join(self.dir, f"{rid}.req.json")
        res = os.path.join(self.dir, f"{rid}.res.json")
        _write_atomic(req, {"id": rid, "op": op, "args": args})
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                with open(res, encoding="utf-8") as fh:
                    out = json.load(fh)
            except FileNotFoundError:
                if not os.path.isdir(self.dir):     # parent closed the session
                    return {"error": "the orchestrator closed the case; call finish"}
                time.sleep(POLL_SECONDS)
                continue
            _unlink(res)
            return out
        # Withdraw the request if the parent has not claimed it yet, so it is
        # not executed after we stopped waiting for it.
        withdrawn = _unlink(req)
        return {"error": f"dispatch timed out after {int(self.timeout)}s waiting for "
                         "the orchestrator" + ("" if withdrawn else
                                               " (the request may still be running)")
                         + "; call finish"}


def _unlink(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


class FileDispatchServer:
    """Parent side: a polling thread that answers ``FileDispatchClient`` calls.

    Requests are handled one at a time, in arrival order, on the polling
    thread. ``stop`` (or leaving the ``with`` block) stops claiming new
    requests, answers any still queued with an error, and waits up to
    ``join_timeout`` seconds for an in-flight request; the owner must make sure
    a request still running after that cannot touch its state (the commander
    closes its ``Dispatcher`` first, which discards late results).
    """

    def __init__(self, session_dir: str, handler, join_timeout: float = 10.0):
        self.dir = dispatch_dir(session_dir)
        self.handler = handler
        self.join_timeout = join_timeout
        self.errors: list = []          # polling-loop failures (never fatal)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="bluecell-dispatch",
                                        daemon=True)
        os.makedirs(self.dir, exist_ok=True)

    def start(self) -> "FileDispatchServer":
        # The polling thread runs the workers: give it the caller's context so
        # their spans and LLM usage land in the active trace run.
        ctx = contextvars.copy_context()
        self._thread = threading.Thread(target=ctx.run, args=(self._loop,),
                                        name="bluecell-dispatch", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> bool:
        """Stop polling. Returns True if the polling thread has finished."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self.join_timeout)
        self._reject_pending("the case is closed; no further dispatch calls")
        return not self._thread.is_alive()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def _pending(self) -> list:
        items = []
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        for n in names:
            if not n.endswith(".req.json"):
                continue
            try:
                items.append((os.path.getmtime(os.path.join(self.dir, n)), n))
            except OSError:        # withdrawn by the client meanwhile
                continue
        return [n for _, n in sorted(items)]

    def _claim(self, name: str):
        """Atomically take a request; returns (id, request) or None."""
        path = os.path.join(self.dir, name)
        taken = path[:-len(".req.json")] + ".taken"
        try:
            os.replace(path, taken)
        except OSError:
            return None            # withdrawn (client timed out) or already taken
        rid = name[:-len(".req.json")]
        try:
            with open(taken, encoding="utf-8") as fh:
                req = json.load(fh)
        except (OSError, ValueError) as exc:
            req = {"_error": f"unreadable dispatch request: {exc}"}
        finally:
            _unlink(taken)
        return rid, req

    def _answer(self, rid: str, out: dict) -> None:
        try:
            _write_atomic(os.path.join(self.dir, f"{rid}.res.json"), out)
        except OSError as exc:     # session dir removed: nobody is waiting
            self.errors.append(f"could not answer {rid}: {exc}")

    def poll_once(self) -> int:
        """Answer every pending request; returns how many were handled."""
        handled = 0
        for name in self._pending():
            if self._stop.is_set():
                break
            claimed = self._claim(name)
            if claimed is None:
                continue
            rid, req = claimed
            if "_error" in req:
                out = {"error": req["_error"]}
            else:
                try:
                    out = self.handler(req.get("op"), req.get("args") or {})
                except Exception as exc:  # a dispatch bug must not hang the commander
                    out = {"error": f"{type(exc).__name__}: {exc}"}
            self._answer(rid, out)
            handled += 1
        return handled

    def _reject_pending(self, error: str) -> None:
        for name in self._pending():
            claimed = self._claim(name)
            if claimed is not None:
                self._answer(claimed[0], {"error": error})

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:   # keep serving; the client would hang otherwise
                self.errors.append(f"{type(exc).__name__}: {exc}")
            self._stop.wait(POLL_SECONDS)
