# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Lightweight run tracer and cost accounting (stdlib only).

One ``Tracer`` per ``analyze()`` run records:
- spans: name, kind (run|pipeline|agent|tool|llm), parent, start, end,
  duration_ms, attributes;
- LLM usage: input/output/cache tokens and cost in USD.

Cost provenance matters and is recorded per usage record:
- ``reported``  : the ``claude`` CLI reported ``total_cost_usd`` itself.
- ``estimated`` : computed here from token counts and ``PRICES`` (API mode).
                  List prices only; no batch/priority/partner discounts.
- ``unknown``   : no token counts and no reported cost.

Runs persist to ``$BASTION_RUNS_DIR`` (default ``~/.bastion/runs``) as
``<run_id>/trace.jsonl`` + ``<run_id>/summary.json``. Tracing never raises
into the analysis: every public entry point swallows its own errors.

Thread model: the swarm runs agents on a thread pool, and pool threads do not
inherit context variables. Each tracer keeps one span stack per thread; a
thread with no open span parents its spans under the top of the stack of the
thread that started the run (normally the "swarm" pipeline stage).
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import random
import re
import shutil
import string
import threading
import time
from datetime import datetime, timezone

# USD per million tokens: (input, output). Cache writes bill at 1.25x input,
# cache reads at 0.1x input. Matched by longest model-id prefix, then family.
PRICES = {
    "claude-fable-5-1": (10.00, 50.00),
    "claude-fable-5": (10.00, 50.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-opus-4-5": (5.00, 25.00),
    "claude-opus-4-1": (15.00, 75.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-mythos-5-1": (10.00, 50.00),
    "claude-mythos-5": (10.00, 50.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-3-5-haiku": (0.80, 4.00),
}
# Checked against platform.claude.com/docs/en/about-claude/pricing on 2026-10-10.
# Long-prompt tiers: above this many prompt tokens per call the whole call bills at the higher rate.
LONG_PROMPT_PRICES = {"claude-haiku-5-5": (100_000, (0.50, 2.50))}
_FAMILY_DEFAULT = {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5",
                   "haiku": "claude-haiku-5-5", "fable": "claude-fable-5-1"}
CACHE_WRITE_MULT = 1.25
CACHE_READ_MULT = 0.10

RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6}$")
_KINDS = ("run", "pipeline", "agent", "tool", "llm")


def runs_dir() -> str:
    return os.environ.get("BASTION_RUNS_DIR") or os.path.join(
        os.path.expanduser("~"), ".bastion", "runs")


def _now() -> float:
    return time.time()


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def price_for(model: str | None):
    """(input, output) USD/MTok for a model id, or None if unknown."""
    key = _price_key(model)
    return PRICES[key] if key else None


def _price_key(model: str | None):
    """The PRICES key a model id bills under, or None if unknown."""
    m = (model or "").lower()
    if m.startswith("anthropic."):
        m = m[len("anthropic."):]
    for key in PRICES:
        # Exact id, optionally with a date stamp or Bedrock "-v1:0" suffix.
        if re.fullmatch(re.escape(key) + r"(?:-\d{8})?(?:-v\d+(?::\d+)?)?", m):
            return key
    # Version-less alias (e.g. "claude-opus") -> newest listed model of that family.
    # Ids with a version number that are not listed get no price (shortcut: family
    # aliases only, add new versions to PRICES when they ship).
    if not re.search(r"\d", m):
        for fam, key in _FAMILY_DEFAULT.items():
            if fam in m:
                return key
    return None


def estimate_cost(usage: dict, model: str | None):
    """Estimated USD for one Messages API ``usage`` block, or None."""
    key = _price_key(model)
    if key is None or not usage:
        return None
    pin, pout = PRICES[key]
    prompt = sum(_int(usage.get(k)) for k in (
        "input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    if key in LONG_PROMPT_PRICES and prompt > LONG_PROMPT_PRICES[key][0]:
        pin, pout = LONG_PROMPT_PRICES[key][1]
    cost = (_int(usage.get("input_tokens")) * pin
            + _int(usage.get("output_tokens")) * pout
            + _int(usage.get("cache_creation_input_tokens")) * pin * CACHE_WRITE_MULT
            + _int(usage.get("cache_read_input_tokens")) * pin * CACHE_READ_MULT)
    return round(cost / 1_000_000, 6)


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _usage_tokens(usage: dict | None) -> dict:
    u = usage or {}
    out = {"input": _int(u.get("input_tokens")), "output": _int(u.get("output_tokens")),
           "cache_read": _int(u.get("cache_read_input_tokens")),
           "cache_creation": _int(u.get("cache_creation_input_tokens"))}
    out["total"] = sum(out.values())
    return out


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tail = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{stamp}-{tail}"


def _jsonable(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v][:50]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in list(v.items())[:50]}
    return str(v)[:500]


# ---------------------------------------------------------------------------
class Span:
    __slots__ = ("tracer", "id", "name", "kind", "parent", "start", "end",
                 "attributes", "usage", "thread")

    def __init__(self, tracer, sid, name, kind, parent, attributes):
        self.tracer = tracer
        self.id = sid
        self.name = name
        self.kind = kind if kind in _KINDS else "pipeline"
        self.parent = parent
        self.start = _now()
        self.end = None
        self.attributes = dict(attributes or {})
        self.usage = []          # usage records attached directly to this span
        self.thread = threading.get_ident()

    def set(self, **attrs) -> "Span":
        try:
            self.attributes.update(attrs)
        except Exception:
            pass
        return self

    @property
    def duration_ms(self):
        return None if self.end is None else round((self.end - self.start) * 1000, 1)

    def to_dict(self) -> dict:
        return {"type": "span", "id": self.id, "name": self.name, "kind": self.kind,
                "parent": self.parent, "start": _iso(self.start),
                "end": _iso(self.end) if self.end else None,
                "duration_ms": self.duration_ms,
                "attributes": _jsonable(self.attributes)}

    # context manager
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc is not None:
            self.set(error=f"{exc_type.__name__}: {exc}"[:300])
        self.tracer._close(self)
        return False


class _NullSpan:
    id = None

    def set(self, **attrs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


NULL_SPAN = _NullSpan()


class Tracer:
    def __init__(self, inputs=None, attrs=None, persist: bool = True,
                 directory: str | None = None):
        self.run_id = _new_run_id()
        self.persist = persist
        self.directory = directory
        self.lock = threading.RLock()
        self.spans: list = []
        self.usage: list = []
        self.owner = threading.get_ident()
        self._stacks: dict = {}
        self._seq = 0
        self._stage = None
        self.inputs = _input_names.get() or [str(p) for p in (inputs or [])]
        self.finished = False
        self.root = self.open("analyze", "run", **(attrs or {}))

    # ---- span management --------------------------------------------------
    def _parent(self):
        tid = threading.get_ident()
        stack = self._stacks.get(tid)
        if stack:
            return stack[-1]
        owner = self._stacks.get(self.owner)
        return owner[-1] if owner else None

    def open(self, name, kind="pipeline", **attrs) -> Span:
        with self.lock:
            self._seq += 1
            parent = self._parent()
            sp = Span(self, f"s{self._seq}", name, kind,
                      parent.id if parent else None, attrs)
            self.spans.append(sp)
            self._stacks.setdefault(sp.thread, []).append(sp)
        if sp.kind == "agent":
            FEED.agent(sp, "deploy")
        return sp

    def _close(self, sp: Span) -> None:
        was_open = sp.end is None
        try:
            self._close_locked(sp)
        finally:
            if was_open and sp.kind == "agent":
                FEED.agent(sp, "error" if sp.attributes.get("error") else "done")

    def _close_locked(self, sp: Span) -> None:
        with self.lock:
            if sp.end is None:
                sp.end = _now()
            stack = self._stacks.get(sp.thread) or []
            if sp in stack:
                # Close anything left open above it on this thread first.
                while stack:
                    top = stack.pop()
                    if top.end is None:
                        top.end = sp.end
                    if top is sp:
                        break

    def add_span(self, name, kind, start, end, parent=None, **attrs) -> Span:
        """Record an already-finished span (e.g. tool calls reconstructed
        from an agent's audit trail)."""
        with self.lock:
            self._seq += 1
            par = parent if parent is not None else self._parent()
            sp = Span(self, f"s{self._seq}", name, kind,
                      par.id if par else None, attrs)
            sp.start = start if start is not None else _now()
            sp.end = end if end is not None else sp.start
            self.spans.append(sp)
            return sp

    def stage(self, name, **attrs) -> Span:
        """Start a sequential pipeline stage, closing the previous one."""
        with self.lock:
            if self._stage is not None:
                self._close(self._stage)
            self._stage = self.open(name, "pipeline", **attrs)
            return self._stage

    # ---- usage --------------------------------------------------------------
    def record_usage(self, usage=None, *, model=None, cost_usd=None,
                     source="api", span=None, **extra) -> dict:
        tokens = _usage_tokens(usage)
        if cost_usd is not None:
            cost, basis = float(cost_usd), "reported"
        else:
            cost = estimate_cost(usage or {}, model) if usage else None
            basis = "estimated" if cost is not None else "unknown"
        with self.lock:
            target = span if isinstance(span, Span) else self._parent()
            rec = {"type": "usage", "span": target.id if target else None,
                   "model": model, "source": source, "tokens": tokens,
                   "cost_usd": cost, "cost_basis": basis}
            rec.update({k: _jsonable(v) for k, v in extra.items()})
            self.usage.append(rec)
            if target is not None:
                target.usage.append(rec)
            return rec

    # ---- summary ------------------------------------------------------------
    def _descendants(self, sid) -> set:
        # Stops at nested agent spans: each agent owns only its own calls, so
        # per-agent rows add up to the run total (no double count up the tree).
        kids = {}
        for s in self.spans:
            kids.setdefault(s.parent, []).append(s)
        out, todo = set(), [sid]
        while todo:
            cur = todo.pop()
            if cur in out:
                continue
            out.add(cur)
            todo.extend(k.id for k in kids.get(cur, []) if k.kind != "agent")
        return out

    def _rollup(self, ids: set) -> dict:
        recs = [u for u in self.usage if u["span"] in ids]
        tok = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0, "total": 0}
        for u in recs:
            for k in tok:
                tok[k] += u["tokens"].get(k, 0)
        costs = [u["cost_usd"] for u in recs if u["cost_usd"] is not None]
        # None = cost unknown (calls were made but none had a cost); a partial
        # sum is paired with unknown_calls so callers can show ">= x".
        unknown = sum(u.get("calls", 1) for u in recs if u["cost_usd"] is None)
        return {"tokens": tok, "llm_calls": sum(u.get("calls", 1) for u in recs),
                "cost_usd": round(sum(costs), 6) if costs else (0.0 if not recs else None),
                "unknown_calls": unknown,
                "cost_basis": sorted({u["cost_basis"] for u in recs}),
                "tool_calls": sum(1 for s in self.spans
                                  if s.kind == "tool" and s.id in ids)}

    def summary(self) -> dict:
        with self.lock:
            all_ids = {s.id for s in self.spans}
            total = self._rollup(all_ids)
            per_agent = []
            for s in self.spans:
                if s.kind != "agent":
                    continue
                r = self._rollup(self._descendants(s.id))
                per_agent.append({
                    "agent": s.attributes.get("agent", s.name),
                    "tier": s.attributes.get("tier"),
                    "mode": s.attributes.get("mode"),
                    "duration_ms": s.duration_ms,
                    "tool_calls": r["tool_calls"], "llm_calls": r["llm_calls"],
                    "tokens": r["tokens"], "cost_usd": r["cost_usd"],
                    "cost_unknown_calls": r["unknown_calls"], "cost_basis": r["cost_basis"],
                })
            end = self.root.end or _now()
            basis = total["cost_basis"]
            return {
                "run_id": self.run_id,
                "persisted": self.persist,   # False = --no-trace, nothing under runs dir
                "started": _iso(self.root.start),
                "duration_ms": round((end - self.root.start) * 1000, 1),
                "total_cost_usd": total["cost_usd"],   # None = unknown, never a fake 0
                "cost_unknown_calls": total["unknown_calls"],
                "cost_estimated": "estimated" in basis,
                "cost_basis": basis,
                "cost_note": _cost_note(basis),
                "tokens": total["tokens"],
                "llm_calls": total["llm_calls"],
                "tool_calls": total["tool_calls"],
                "spans": len(self.spans),
                "per_agent": per_agent,
            }

    # ---- lifecycle ----------------------------------------------------------
    def finish(self, result: dict | None = None, error: str | None = None) -> dict:
        with self.lock:
            if self._stage is not None:
                self._close(self._stage)
                self._stage = None
            if error:
                self.root.set(error=error)
            self._close(self.root)
            self.finished = True
            summ = self.summary()
        if result is not None:
            try:
                result.setdefault("meta", {})["trace"] = summ
            except Exception:
                pass
        if self.persist:
            self._write(summ, result, error)
        return summ

    def _write(self, summ, result, error) -> None:
        try:
            base = os.path.join(self.directory or runs_dir(), self.run_id)
            os.makedirs(base, exist_ok=True)
            with open(os.path.join(base, "trace.jsonl"), "w", encoding="utf-8") as fh:
                for s in self.spans:
                    fh.write(json.dumps(s.to_dict(), default=str) + "\n")
                for u in self.usage:
                    fh.write(json.dumps(u, default=str) + "\n")
            record = dict(summ, inputs=self.inputs,
                          attributes=_jsonable(self.root.attributes),
                          error=error)
            if result:
                record.update(_result_facts(result))
            with open(os.path.join(base, "summary.json"), "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2, default=str)
            _prune_runs(os.path.dirname(base), self.run_id)
        except Exception:
            pass   # tracing must never break analysis


RUNS_KEEP_DEFAULT = 200
_TMP_STALE_S = 300   # interrupted writes older than this are orphans


def _prune_runs(base: str, keep_id: str) -> None:
    """Keep the newest BASTION_RUNS_KEEP run dirs and sweep stale *.tmp files.
    Ordered by dir mtime: run ids only resolve to the second. Only RUN_ID_RE
    named dirs are ever removed."""
    try:
        keep = max(1, int(os.environ.get("BASTION_RUNS_KEEP") or RUNS_KEEP_DEFAULT))
    except ValueError:
        keep = RUNS_KEEP_DEFAULT
    now = _now()

    def mtime(n):
        try:
            return os.path.getmtime(os.path.join(base, n))
        except OSError:
            return 0.0
    names = sorted((n for n in os.listdir(base) if RUN_ID_RE.match(n)), key=mtime)
    for n in names[:-keep]:
        if n != keep_id:
            shutil.rmtree(os.path.join(base, n), ignore_errors=True)
    for n in os.listdir(base):
        p = os.path.join(base, n)
        try:
            if n.endswith(".tmp") and now - os.path.getmtime(p) > _TMP_STALE_S:
                os.remove(p)
        except OSError:
            pass


def _cost_note(basis) -> str:
    if not basis:
        return "no LLM calls"
    if basis == ["reported"]:
        return "cost reported by the claude CLI"
    parts = []
    if "reported" in basis:
        parts.append("partly reported by the claude CLI")
    if "estimated" in basis:
        parts.append("partly estimated from token counts at list prices"
                     if len(basis) > 1 else "estimated from token counts at list prices")
    if "unknown" in basis:
        parts.append("some calls had no usage data (cost unknown)")
    return "; ".join(parts)


def _result_facts(result: dict) -> dict:
    meta = result.get("meta") or {}
    incs = result.get("incidents") or []
    top = (incs[0].get("verdict") or {}) if incs else {}
    return {"verdict": top.get("level") or ("no-incidents" if not incs else None),
            "incidents": len(incs),
            "agents": meta.get("agents_deployed", 0),
            "backbone": meta.get("backbone"),
            "events": meta.get("events_ingested"),
            "cache": meta.get("cache"),
            "original_run_id": meta.get("original_run_id"),
            "original_run_persisted": meta.get("original_run_persisted")}


# ---------------------------------------------------------------------------
# Live progress feed (GET /api/progress). In-memory, capped, never raises.
# Agent spans give deploy/done/error; tool calls come from the API driver
# directly and, in CLI mode, from <session>/events.jsonl lines the MCP server
# subprocess appends and this process tails (watch/unwatch).
# ---------------------------------------------------------------------------
FEED_CAP = 2000
_DETAIL_BAD = re.compile(r"[<>&\"'`]")


def feed_detail(*parts) -> str | None:
    """Short escape-safe plain text for the feed. Log-derived text is never echoed:
    anything the injection scanner flags is withheld."""
    try:
        from .agents import injection
        text = " ".join(str(p) for p in parts if p not in (None, ""))
        text = " ".join(injection.sanitize(text, 400).split())
        if not text:
            return None
        if injection.scan_text(text) or re.search(r"<\s*/?\s*script", text, re.I):
            return "[flagged content withheld]"
        return _DETAIL_BAD.sub("", text)[:120] or None
    except Exception:
        return None


def args_detail(args) -> str | None:
    if not isinstance(args, dict):
        return None
    return feed_detail(*(f"{k}={v}" for k, v in list(args.items())[:3]))


class _Feed:
    def __init__(self):
        self.lock = threading.RLock()
        self.seq = 0
        self.reset_state()

    def reset_state(self):
        self.events, self.who, self.watched = [], {}, {}
        self.running, self.mode, self.started = False, None, None
        self.counts = {"agents_active": 0, "agents_total": 0, "tool_calls": 0, "findings": 0}

    def begin(self, mode, started):
        with self.lock:
            self.reset_state()
            self.running, self.started = True, started
            self.mode = mode if mode in ("quick", "deep") else "deep"

    def end(self):
        self.poll()
        with self.lock:
            self.running = False

    def emit(self, agent, kind, tool=None, detail=None, ts=None):
        try:
            with self.lock:
                if self.started is None:
                    return
                tier, role = self.who.get(agent, (0, ""))
                self.seq += 1
                self.events.append({
                    "seq": self.seq, "t": round((ts or _now()) - self.started, 3),
                    "agent": agent, "tier": tier, "role": role, "kind": kind,
                    "tool": tool, "detail": detail})
                del self.events[:-FEED_CAP]
                c = self.counts
                if kind == "tool":
                    c["tool_calls"] += 1
                elif kind in ("finding", "verdict"):
                    c["findings"] += 1
        except Exception:
            pass

    def agent(self, sp, kind):
        try:
            a = sp.attributes
            name = str(a.get("agent") or sp.name)
            with self.lock:
                if kind == "deploy":
                    self.who[name] = (a.get("tier") if a.get("tier") in (0, 1, 2, 3) else 0,
                                      feed_detail(a.get("role")) or "")
                    self.counts["agents_total"] += 1
                    self.counts["agents_active"] += 1
                else:
                    self.poll()   # its tool lines land before its done
                    self.counts["agents_active"] = max(0, self.counts["agents_active"] - 1)
                self.emit(name, kind,
                          detail=feed_detail(a.get("error")) if kind == "error" else None)
        except Exception:
            pass

    def tool(self, agent, name, ok=True, args=None, ts=None):
        """One finished tool call; submit_finding / submit_verdict also file a finding."""
        name = str(name)
        self.emit(agent, "tool", tool=name, detail=args_detail(args) if ok else "failed", ts=ts)
        if ok and name in ("submit_finding", "submit_verdict"):
            args = args if isinstance(args, dict) else {}
            self.emit(agent, "finding" if name == "submit_finding" else "verdict",
                      tool=name, detail=feed_detail(args.get("title") or args.get("verdict")
                                                    or args.get("level")), ts=ts)

    # ---- CLI mode: tail the MCP server's events.jsonl ------------------------
    def watch(self, path):
        with self.lock:
            self.watched[path] = 0

    def unwatch(self, path):
        self.poll()
        with self.lock:
            self.watched.pop(path, None)

    def poll(self):
        with self.lock:
            for path, off in list(self.watched.items()):
                try:
                    with open(path, "rb") as fh:
                        fh.seek(off)
                        data = fh.read()
                except OSError:
                    continue
                end = data.rfind(b"\n") + 1      # leave a half-written last line for next time
                self.watched[path] = off + end
                for line in data[:end].splitlines():
                    try:
                        r = json.loads(line)
                        self.tool(str(r["agent"]), r["tool"], bool(r.get("ok")), r.get("args"),
                                  ts=r.get("ts"))
                    except (ValueError, KeyError, TypeError):
                        continue

    def snapshot(self, since=0):
        self.poll()
        with self.lock:
            return {"running": self.running, "mode": self.mode,
                    "started": _iso(self.started) if self.started else None,
                    "events": [e for e in self.events if e["seq"] > since],
                    "counts": dict(self.counts)}


FEED = _Feed()


def feed_event_line(agent, tool, ok, args) -> str:
    """The line an MCP server subprocess appends to events.jsonl for one tool call."""
    return json.dumps({"ts": _now(), "agent": agent, "tool": tool, "ok": ok,
                       "args": {k: str(v)[:200] for k, v in list((args or {}).items())[:3]}}) + "\n"


# ---------------------------------------------------------------------------
# Active-tracer registry + module-level helpers (no-ops without a run)
# ---------------------------------------------------------------------------
_current: contextvars.ContextVar = contextvars.ContextVar("bastion_tracer", default=None)
_input_names: contextvars.ContextVar = contextvars.ContextVar("bastion_input_names", default=None)


@contextlib.contextmanager
def input_names(names):
    """Record these names as the inputs of runs started inside the block (e.g. an upload's
    file names instead of its temp dir, which is gone once the run is listed)."""
    token = _input_names.set([str(n) for n in names or []])
    try:
        yield
    finally:
        _input_names.reset(token)


_active: list = []
_active_lock = threading.Lock()


def current():
    try:
        t = _current.get()
        if t is not None and not t.finished:
            return t
        with _active_lock:
            live = [t for t in _active if not t.finished]
        return live[-1] if len(live) == 1 else None
    except Exception:
        return None


def start_run(inputs=None, persist: bool | None = None, **attrs):
    """Begin a traced run; returns the Tracer (or None if tracing fails)."""
    try:
        if persist is None:
            persist = os.environ.get("BASTION_NO_TRACE", "") in ("", "0")
        t = Tracer(inputs, attrs, persist=persist)
        FEED.begin(attrs.get("mode"), t.root.start)
        _current.set(t)
        with _active_lock:
            _active.append(t)
        return t
    except Exception:
        return None


def end_run(tracer, result=None, error=None):
    if tracer is None:
        return None
    try:
        return tracer.finish(result, error)
    except Exception:
        return None
    finally:
        FEED.end()
        try:
            with _active_lock:
                if tracer in _active:
                    _active.remove(tracer)
            if _current.get() is tracer:
                _current.set(None)
        except Exception:
            pass


def span(name, kind="pipeline", **attrs):
    """Context-manager span under the active run (a no-op without one)."""
    t = current()
    if t is None:
        return NULL_SPAN
    try:
        return t.open(name, kind, **attrs)
    except Exception:
        return NULL_SPAN


def stage(name, **attrs):
    t = current()
    if t is None:
        return NULL_SPAN
    try:
        return t.stage(name, **attrs)
    except Exception:
        return NULL_SPAN


def record_llm(usage=None, *, model=None, cost_usd=None, source="api", span=None, **extra):
    t = current()
    if t is None:
        return None
    try:
        return t.record_usage(usage, model=model, cost_usd=cost_usd, source=source,
                              span=span, **extra)
    except Exception:
        return None


def record_tool_calls(calls, parent=None, agent=None) -> int:
    """Turn an agent's tool audit trail into tool spans. Entries may carry
    ``t0`` (epoch seconds) and ``ms``; without them the span has no duration."""
    t = current()
    if t is None or not calls:
        return 0
    n = 0
    try:
        par = parent if isinstance(parent, Span) else None
        for c in calls:
            start = c.get("t0")
            ms = c.get("ms")
            end = (start + ms / 1000.0) if (start is not None and ms is not None) else start
            t.add_span(f"tool:{c.get('tool')}", "tool", start, end, parent=par,
                       tool=c.get("tool"), ok=c.get("ok"), agent=agent,
                       args=c.get("args"), timing=("measured" if ms is not None else "none"))
            n += 1
    except Exception:
        pass
    return n


def parse_stream_json(stdout: str) -> dict:
    """Pull usage, cost and tool_use blocks out of ``claude -p --output-format
    stream-json`` (or a single ``--output-format json``) output."""
    out = {"result": None, "usage": None, "cost_usd": None, "num_turns": None,
           "is_error": False, "subtype": None, "tool_uses": [], "model": None}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        typ = msg.get("type")
        if typ == "assistant":
            m = msg.get("message") or {}
            out["model"] = out["model"] or m.get("model")
            for block in m.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    out["tool_uses"].append({"tool": str(block.get("name", "")).split("__")[-1],
                                             "id": block.get("id")})
        elif typ == "result":
            out["result"] = msg.get("result")
            out["usage"] = msg.get("usage")
            out["cost_usd"] = msg.get("total_cost_usd")
            out["num_turns"] = msg.get("num_turns")
            out["is_error"] = bool(msg.get("is_error"))
            out["subtype"] = msg.get("subtype")
    return out


# ---------------------------------------------------------------------------
# Reading persisted runs (CLI + web)
# ---------------------------------------------------------------------------
def list_runs(limit: int = 50, directory: str | None = None) -> list:
    base = directory or runs_dir()
    try:
        names = sorted((n for n in os.listdir(base) if RUN_ID_RE.match(n)), reverse=True)
    except OSError:
        return []
    out = []
    # Ids sort by second; read a margin and order by the precise start time.
    for n in names[:limit * 2 + 20]:
        try:
            with open(os.path.join(base, n, "summary.json"), encoding="utf-8") as fh:
                summ = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(summ, dict):
            out.append(summ)
    out.sort(key=lambda s: str(s.get("started") or ""), reverse=True)
    return out[:limit]


def input_label(inputs) -> str:
    """Short label for a run's inputs: one name, or the shared folder."""
    inputs = [str(p).rstrip("/") for p in inputs or []]
    if not inputs:
        return "-"
    if len(inputs) == 1:
        return os.path.basename(inputs[0]) or inputs[0]
    parents = {os.path.dirname(p) for p in inputs}
    parent = os.path.basename(parents.pop()) if len(parents) == 1 else ""
    if parent:  # relative files share parent "" -> fall through to "a.log +1"
        return f"{parent}/ ({len(inputs)} files)"
    return f"{os.path.basename(inputs[0])} +{len(inputs) - 1}"


def load_run(run_id: str, directory: str | None = None):
    """Summary + spans + usage for one run, or None (also for invalid ids)."""
    if not isinstance(run_id, str) or not RUN_ID_RE.match(run_id):
        return None
    base = os.path.join(directory or runs_dir(), run_id)
    try:
        with open(os.path.join(base, "summary.json"), encoding="utf-8") as fh:
            summ = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(summ, dict):
        return None
    spans, usage = [], []
    try:
        with open(os.path.join(base, "trace.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                (spans if rec.get("type") == "span" else usage).append(rec)
    except OSError:
        pass
    return {"summary": summ, "spans": spans, "usage": usage}


def span_tree_lines(run: dict) -> list:
    """Indented text rendering of a loaded run's span tree."""
    spans = run.get("spans") or []
    usage_by = {}
    for u in run.get("usage") or []:
        usage_by.setdefault(u.get("span"), []).append(u)
    kids = {}
    for s in spans:
        kids.setdefault(s.get("parent"), []).append(s)
    lines = []

    def walk(parent, depth):
        for s in kids.get(parent, []):
            dur = s.get("duration_ms")
            extra = ""
            us = usage_by.get(s["id"]) or []
            if us:
                tok = sum(u["tokens"]["total"] for u in us)
                costs = [u["cost_usd"] for u in us if u.get("cost_usd") is not None]
                extra = f"  tokens={tok}"
                if costs:
                    extra += f" cost=${sum(costs):.4f} ({'/'.join(sorted({u['cost_basis'] for u in us}))})"
            attrs = s.get("attributes") or {}
            note = ""
            for k in ("mode", "ok", "error"):
                if k in attrs and attrs[k] not in (None, ""):
                    note += f" {k}={attrs[k]}"
            lines.append(f"{'  ' * depth}[{s['kind']}] {s['name']}"
                         f"  {'' if dur is None else f'{dur:.0f}ms'}{note}{extra}")
            walk(s["id"], depth + 1)

    walk(None, 0)
    return lines
