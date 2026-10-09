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
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
import urllib.error

from .. import tracing

DEFAULT_MODEL = "claude-sonnet-5"
# Seconds per call. The AI analyst's lead call has been measured at 36-120+ s
# on the samples; 120 s was too tight and failed intermittently.
DEFAULT_TIMEOUT = 300
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class BackboneUnavailable(RuntimeError):
    pass


class LLMBackbone:
    def __init__(self, mode: str = "auto", model: str = DEFAULT_MODEL,
                 timeout: int = DEFAULT_TIMEOUT):
        self.mode = mode
        self.model = model
        self.timeout = timeout
        self.resolved = self._resolve()

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
        # auto: prefer CLI (keyless) then API.
        if self._cli_available():
            return "cli"
        if self._api_available():
            return "api"
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
        # JSON output carries the CLI-reported usage and total_cost_usd; the
        # answer text is its "result" field.
        cmd = ["claude", "-p", "--output-format", "json"]
        if self.model:
            cmd += ["--model", self.model]
        if system:
            cmd += ["--append-system-prompt", system]
        try:
            proc = subprocess.run(
                cmd, input=prompt, capture_output=True, text=True,
                timeout=self.timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise BackboneUnavailable(f"claude CLI failed: {exc}") from exc
        if proc.returncode != 0:
            raise BackboneUnavailable(
                f"claude CLI exited {proc.returncode}: {proc.stderr.strip()[:200]}")
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
        if system:
            body["system"] = system
        payload = self.messages(body)
        tracing.record_llm(payload.get("usage"), model=payload.get("model") or self.model,
                           source="api")
        parts = payload.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()

    def messages(self, body: dict) -> dict:
        """Raw Messages API call (used by the tool-using agent loop)."""
        key = os.environ["ANTHROPIC_API_KEY"]
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
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise BackboneUnavailable(f"API HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BackboneUnavailable(f"API request failed: {exc}") from exc
        return payload