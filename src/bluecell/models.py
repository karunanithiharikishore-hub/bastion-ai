# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Unified event schema (OCSF-inspired, intentionally compact).

Raw logs are heavy and token-expensive. Every source is mapped into a single
small dataclass so downstream agents reason over one shape, and so the
compressor can emit a token-lean representation for the LLM.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional


# Coarse activity categories used across all sources. Keeping the vocabulary
# small makes correlation and ATT&CK mapping tractable.
CATEGORIES = (
    "authentication",
    "process",
    "network",
    "dns",
    "file",
    "cloud_api",
    "alert",
    "other",
)


def _parse_ts(value: Any) -> datetime:
    """Best-effort timestamp parsing -> tz-aware UTC datetime.

    Accepts ISO-8601 (with or without 'Z'), epoch seconds/millis, or falls
    back to now(). Never raises: a bad timestamp must not crash ingestion.
    """
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, str) and re.fullmatch(r"\s*\d{9,16}(\.\d+)?\s*", value):
        value = float(value)          # epoch stored as text (every CSV value is text)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Heuristic: values > 1e12 are milliseconds.
        try:
            seconds = value / 1000.0 if value > 1_000_000_000_000 else float(value)
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return datetime.now(timezone.utc)
    if isinstance(value, str):
        v = value.strip().replace("Z", "+00:00")
        for candidate in (v, v.split(".")[0] + "+00:00" if "." in v else v):
            try:
                return _utc(datetime.fromisoformat(candidate))
            except ValueError:
                continue
        # Common syslog format: "Mmm dd HH:MM:SS" (no year) -> assume current.
        for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(v, fmt)
            except ValueError:
                continue
            dt = dt.replace(tzinfo=timezone.utc)
            if dt.year == 1900:
                now = datetime.now(timezone.utc)
                dt = dt.replace(year=now.year)
                # "Dec 31" read in January belongs to last year, not this one.
                if dt > now + timedelta(days=2):
                    dt = dt.replace(year=now.year - 1)
            return dt
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    """Tz-aware UTC; naive values are taken to be UTC already."""
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# Entity fields that must be strings (JSON may hold numbers, lists or objects).
_STR_FIELDS = ("host", "user", "process", "src_ip", "dst_ip", "domain",
               "file_path", "file_hash")


@dataclass
class Event:
    """One normalized security event."""

    ts: datetime
    source: str                 # e.g. "edr", "dns", "firewall", "cloudtrail"
    category: str               # one of CATEGORIES
    action: str                 # short verb, e.g. "login_failed", "dns_query"
    message: str                # human-readable one-liner
    severity: int = 0           # 0=info .. 4=critical
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    raw: dict = field(default_factory=dict)
    # Populated by later stages:
    attack: list = field(default_factory=list)   # list of ATT&CK technique ids
    tags: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ts = _parse_ts(self.ts)
        for name in _STR_FIELDS:
            val = getattr(self, name)
            if val is not None:
                val = str(val).strip()
                setattr(self, name, val or None)
        self.message = "" if self.message is None else str(self.message)
        self.action = str(self.action or "event")
        self.source = str(self.source or "unknown")
        if self.category not in CATEGORIES:
            self.category = "other"
        try:
            self.severity = max(0, min(4, int(self.severity or 0)))
        except (TypeError, ValueError, OverflowError):   # "high", NaN, inf
            self.severity = 0

    @property
    def event_id(self) -> str:
        """Stable id derived from content — used for dedup and evidence refs."""
        basis = (f"{self.ts.isoformat()}|{self.source}|{self.action}|{self.host}|{self.user}|"
                 f"{self.src_ip}|{self.dst_ip}|{self.domain}|{self.process}|{self.file_hash}|"
                 f"{self.file_path}|{self.message}")
        return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:12]

    def entities(self) -> dict:
        """Key entities used to link events during correlation."""
        return {
            k: v
            for k, v in {
                "host": self.host,
                "user": self.user,
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "domain": self.domain,
                "file_hash": self.file_hash,
            }.items()
            if v
        }

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        d["event_id"] = self.event_id
        d.pop("raw", None)  # raw is kept in memory but excluded from exports
        return d

    def compact(self) -> str:
        """Token-lean single-line representation for the LLM stage."""
        parts = [self.ts.strftime("%m-%dT%H:%M:%S"), self.source, self.action]
        for label, val in (
            ("h", self.host),
            ("u", self.user),
            ("s", self.src_ip),
            ("d", self.dst_ip),
            ("dom", self.domain),
            ("proc", self.process),
            ("hash", self.file_hash),
        ):
            if val:
                parts.append(f"{label}={val}")
        if self.attack:
            parts.append("att=" + ",".join(self.attack))
        return " ".join(parts)


def dumps(events: list, **kw) -> str:
    return json.dumps([e.to_dict() for e in events], indent=2, **kw)