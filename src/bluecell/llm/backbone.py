# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Hybrid Claude backbone.

Two execution paths, selected automatically (override with mode=):
- "cli"  : shell out to the local `claude` CLI — keyless, uses the user's
           existing Claude Code session. Best for interactive local runs.
- "api"  : call the Anthropic API using ANTHROPIC_API_KEY. Best for headless /
           scheduled runs. Uses the `anthropic` package if installed, else a
           dependency-free urllib call.

If neither path is available the backbone raises BackboneUnavailable, and
callers fall back to the deterministic storyline. The pipeline NEVER requires
the LLM to produce a result.

Auto mode prefers the API when ANTHROPIC_API_KEY is set: the agent swarm then
runs every agent as an in-process tool loop (no ``claude`` process or MCP
server per agent), and decoding is pinned to temperature 0. Without a key it
uses the keyless CLI. The ``claude`` CLI exposes no temperature / seed /
sampling option (checked against ``claude --help``, Claude Code 2.1.x), so CLI
runs use the CLI's default sampling; see README "Repeatability & cost".
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

from .. import tracing

DEFAULT_MODEL = "claude-sonnet-5"
# Seconds per call. The AI analyst's lead call has been measured at 36-120+ s
# on the samples; 120 s was too tight and failed intermittently.
DEFAULT_TIMEOUT = 300
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"
# Deterministic-as-possible decoding for every API call (agent loops, analyst,
# narrative). Temperature 0 is greedy-ish, not a bit-identical guarantee.
DEFAULT_TEMPERATURE = 0.0


class BackboneUnavailable(RuntimeError):
    def __init__(self, message: str = "", status: int | None = None):
        super().__init__(message)
        self.status = status    # HTTP status of an API error response, else None


_RETRIES = 2   # extra attempts on 429/529; backoff 2s, 4s unless Retry-After says more


def _cli_result(stdout: str) -> dict | None:
    """The CLI's JSON result message in stdout (whole output or one line), if any."""
    stdout = (stdout or "").strip()
    for cand in [stdout, *stdout.splitlines()]:
        try:
            msg = json.loads(cand)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("result"):
            return msg
    return None


def _cli_failure_text(stdout: str, stderr: str) -> str:
    """The CLI's failure message. Its JSON result line carries it in `result`
    (e.g. an expired login), so a raw JSON line is never shown instead."""
    msg = _cli_result(stdout)
    if msg:
        return str(msg["result"]).strip()
    return (stderr or "").strip() or (stdout or "").strip()


class _Retryable(Exception):
    def __init__(self, err, wait):
        self.err, self.wait = err, wait


class LLMBackbone:
    def __init__(self, mode: str = "auto", model: str = DEFAULT_MODEL,
                 timeout: int = DEFAULT_TIMEOUT,
                 temperature: float | None = DEFAULT_TEMPERATURE):
        self.mode = mode
        self.model = model
        self.timeout = timeout
        self.temperature = temperature   # API path only; None = API default
        self.resolved = self._resolve()

    @property
    def sampling(self) -> str:
        """How decoding is controlled on the resolved path (for the run record)."""
        if self.resolved == "api":
            return ("default" if self.temperature is None
                    else f"temperature={self.temperature:g}")
        return "cli default (the claude CLI has no temperature/seed option)"

    # ---- availability -------------------------------------------------------
    def _cli_available(self) -> bool:
        return shutil.which("claude") is not None

    def _api_available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def _resolve(self) -> str:
        if self.mode == "cli":
            if not self._cli_available():
                raise BackboneUnavailable("claude CLI not found on PATH")
            return "cli"
        if self.mode == "api":
            if not self._api_available():
                raise BackboneUnavailable("ANTHROPIC_API_KEY not set")
            return "api"
        # auto: prefer the API when a key is set (in-process agent loop, no
        # per-agent process, temperature 0), else the keyless CLI.
        if self._api_available():
            return "api"
        if self._cli_available():
            return "cli"
        raise BackboneUnavailable(
            "No Claude backbone available (no `claude` CLI and no ANTHROPIC_API_KEY)")

    @staticmethod
    def available(mode: str = "auto") -> bool:
        try:
            LLMBackbone(mode=mode)
            return True
        except BackboneUnavailable:
            return False

    # ---- generation ---------------------------------------------------------
    def complete(self, prompt: str, system: str | None = None,
                 max_tokens: int = 1500) -> str:
        with tracing.span("llm:complete", "llm", mode=self.resolved, model=self.model):
            if self.resolved == "cli":
                return self._complete_cli(prompt, system)
            return self._complete_api(prompt, system, max_tokens)

    def _complete_cli(self, prompt: str, system: str | None) -> str:
        # Same isolation as the agent runtime: the prompt carries log-controlled
        # text, so no built-in tools, no user MCP servers/hooks/settings, and an
        # empty cwd (no project CLAUDE.md, nothing local to read). JSON output
        # carries the CLI-reported usage and total_cost_usd for the run trace;
        # the answer text is its "result" field.
        cmd = ["claude", "-p", "--tools", "", "--strict-mcp-config",
               "--setting-sources", "project", "--no-session-persistence",
               "--output-format", "json"]
        if self.model:
            cmd += ["--model", self.model]
        if system:
            cmd += ["--append-system-prompt", system]
        try:
            with tempfile.TemporaryDirectory(prefix="bluecell-llm-") as cwd:
                # Own session, so a timeout kills the CLI's helpers too (as runtime._run_cli).
                with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, cwd=cwd,
                                      start_new_session=True) as p:
                    try:
                        out, err = p.communicate(prompt, timeout=self.timeout)
                    except subprocess.TimeoutExpired as exc:
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except OSError:
                            pass
                        exc.stderr = p.communicate()[1]
                        raise
                proc = subprocess.CompletedProcess(cmd, p.returncode, out, err)
        except subprocess.TimeoutExpired as exc:   # str(exc) embeds the full argv
            # shortcut: stderr tail only, no argv/prompt; upgrade if callers need more
            tail = exc.stderr or b""
            tail = (tail.decode("utf-8", "replace") if isinstance(tail, bytes) else tail).strip()
            raise BackboneUnavailable(f"claude CLI timed out after {self.timeout}s"
                                      + (f" ({tail[-200:]})" if tail else "")) from exc
        except OSError as exc:
            raise BackboneUnavailable(
                f"claude CLI failed: {exc.strerror or type(exc).__name__}") from exc
        if proc.returncode != 0:
            # A failed run still reports its cost/usage in the JSON result; trace it.
            res = _cli_result(proc.stdout)
            if res and ("usage" in res or "total_cost_usd" in res):
                tracing.record_llm(res.get("usage"), model=self.model,
                                   cost_usd=res.get("total_cost_usd"), source="cli")
            raise BackboneUnavailable(
                f"claude CLI exited {proc.returncode}: {_cli_failure_text(proc.stdout, proc.stderr)[:200]}")
        out = proc.stdout.strip()
        try:
            msg = json.loads(out)
        except ValueError:
            msg = None
        if not isinstance(msg, dict) or msg.get("type") != "result":
            tracing.record_llm(None, model=self.model, source="cli")  # cost unknown
            return out   # older CLI / plain text: return as before
        tracing.record_llm(msg.get("usage"), model=self.model,
                           cost_usd=msg.get("total_cost_usd"), source="cli")
        if msg.get("is_error"):
            raise BackboneUnavailable(
                f"claude CLI error ({msg.get('subtype')}): {str(msg.get('result'))[:200]}")
        return str(msg.get("result") or "").strip()

    def _complete_api(self, prompt: str, system: str | None,
                      max_tokens: int) -> str:
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if system:
            body["system"] = system
        payload = self.messages(body)
        tracing.record_llm(payload.get("usage"), model=payload.get("model") or self.model,
                           source="api")
        parts = payload.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()

    def messages(self, body: dict, timeout: float | None = None) -> dict:
        """Raw Messages API call (used by the tool-using agent loop).

        429/529 are retried up to _RETRIES times with backoff (honouring
        Retry-After), but never past ``timeout`` (the caller's remaining budget).
        A persistent 429 still raises, so the swarm halts cleanly."""
        timeout = self.timeout if timeout is None else timeout
        end = time.monotonic() + timeout
        for attempt in range(_RETRIES + 1):
            try:
                return self._messages_once(body, max(end - time.monotonic(), 0.001))
            except _Retryable as exc:
                wait = min(exc.wait if exc.wait is not None else 2 ** (attempt + 1), 30)
                if attempt == _RETRIES or time.monotonic() + wait >= end:
                    raise exc.err from None
                time.sleep(wait)

    def _messages_once(self, body: dict, timeout: float) -> dict:
        key = os.environ["ANTHROPIC_API_KEY"]
        if self.temperature is not None and "temperature" not in body:
            body = dict(body, temperature=self.temperature)
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            _API_URL, data=data, method="POST",
            headers={
                "x-api-key": key,
                "anthropic-version": _API_VERSION,
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            err = BackboneUnavailable(f"API HTTP {exc.code}: {detail}", status=exc.code)
            if exc.code in (429, 529):
                try:
                    wait = float(exc.headers.get("retry-after"))
                except (AttributeError, TypeError, ValueError):
                    wait = None
                if wait is not None and not 0 <= wait < float("inf"):  # negative/NaN/inf
                    wait = None
                raise _Retryable(err, wait) from exc
            raise err from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackboneUnavailable(f"API request failed: {exc}") from exc
        return payload