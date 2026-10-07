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

DEFAULT_MODEL = "claude-sonnet-5"
_API_URL = "https://api.anthropic.com/v1/messages"
_API_VERSION = "2023-06-01"


class BackboneUnavailable(RuntimeError):
    pass


class LLMBackbone:
    def __init__(self, mode: str = "auto", model: str = DEFAULT_MODEL,
                 timeout: int = 120):
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
        if self.resolved == "cli":
            return self._complete_cli(prompt, system)
        return self._complete_api(prompt, system, max_tokens)

    def _complete_cli(self, prompt: str, system: str | None) -> str:
        cmd = ["claude", "-p"]
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
        return proc.stdout.strip()

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