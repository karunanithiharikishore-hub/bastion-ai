# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
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

Runs persist to ``$BLUECELL_RUNS_DIR`` (default ``~/.bluecell/runs``) as
``<run_id>/trace.jsonl`` + ``<run_id>/summary.json``. Tracing never raises
into the analysis: every public entry point swallows its own errors.

Thread model: the swarm runs agents on a thread pool, and pool threads do not
inherit context variables. Each tracer keeps one span stack per thread; a
thread with no open span parents its spans under the top of the stack of the
thread that started the run (normally the "swarm" pipeline stage).
"""
from __future__ import annotations

import contextvars
import json
import os
import random
import re
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
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
}
_FAMILY_DEFAULT = {"opus": "claude-opus-5-5", "sonnet": "claude-sonnet-5-5",
                   "haiku": "claude-haiku-5-5", "fable": "claude-fable-5-1"}
CACHE_WRITE_MULT = 1.25
CACHE_READ_MULT = 0.10

RUN_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6}$")
_KINDS = ("run", "pipeline", "agent", "tool", "llm")


def runs_dir() -> str:
    return os.environ.get("BLUECELL_RUNS_DIR") or os.path.join(
        os.path.expanduser("~"), ".bluecell", "runs")


def _now() -> float:
    return time.time()


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def price_for(model: str | None):
    """(input, output) USD/MTok for a model id, or None if unknown."""
    m = (model or "").lower()
    if m.startswith("anthropic."):
        m = m[len("anthropic."):]
    best = None
    for key in PRICES:
        if m.startswith(key) and (best is None or len(key) > len(best)):
            best = key
    if best:
        return PRICES[best]
    for fam, key in _FAMILY_DEFAULT.items():
        if fam in m:
            return PRICES[key]
    return None


def estimate_cost(usage: dict, model: str | None):
    """Estimated USD for one Messages API ``usage`` block, or None."""
    p = price_for(model)
    if p is None or not usage:
        return None
    pin, pout = p
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
        self.inputs = [str(p) for p in (inputs or [])]
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
            return sp

    def _close(self, sp: Span) -> None:
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
        kids = {}
        for s in self.spans:
            kids.setdefault(s.parent, []).append(s.id)
        out, todo = set(), [sid]
        while todo:
            cur = todo.pop()
            if cur in out:
                continue
            out.add(cur)
            todo.extend(kids.get(cur, []))
        return out

    def _rollup(self, ids: set) -> dict:
        recs = [u for u in self.usage if u["span"] in ids]
        tok = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0, "total": 0}
        for u in recs:
            for k in tok:
                tok[k] += u["tokens"].get(k, 0)
        costs = [u["cost_usd"] for u in recs if u["cost_usd"] is not None]
        return {"tokens": tok, "llm_calls": sum(u.get("calls", 1) for u in recs),
                "cost_usd": round(sum(costs), 6) if costs else (0.0 if not recs else None),
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
                    "cost_basis": r["cost_basis"],
                })
            end = self.root.end or _now()
            basis = total["cost_basis"]
            return {
                "run_id": self.run_id,
                "started": _iso(self.root.start),
                "duration_ms": round((end - self.root.start) * 1000, 1),
                "total_cost_usd": total["cost_usd"] if total["cost_usd"] is not None else 0.0,
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
        except Exception:
            pass   # tracing must never break analysis


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
            "events": meta.get("events_ingested")}


# ---------------------------------------------------------------------------
# Active-tracer registry + module-level helpers (no-ops without a run)
# ---------------------------------------------------------------------------
_current: contextvars.ContextVar = contextvars.ContextVar("bluecell_tracer", default=None)
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
            persist = os.environ.get("BLUECELL_NO_TRACE", "") in ("", "0")
        t = Tracer(inputs, attrs, persist=persist)
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
                out.append(json.load(fh))
        except (OSError, ValueError):
            continue
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
    if len(parents) == 1:
        return f"{os.path.basename(parents.pop())}/ ({len(inputs)} files)"
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
    spans, usage = [], []
    try:
        with open(os.path.join(base, "trace.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
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
