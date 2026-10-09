# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Local threat-intel store — the "always-current" knowledge layer.

This is the honest version of "self-learning": the *model* is never retrained,
but the system continuously ingests fresh intelligence (CVEs, advisories, TTPs)
into a local, searchable store. At analysis time the pipeline retrieves the
entries relevant to what it is seeing and feeds them to the LLM (RAG), so
conclusions reflect the latest threats and every flag is traceable to a source.

Storage is a single JSON file (no external DB dependency). Search is a
transparent keyword/entity match — auditable and offline. A vector backend can
be layered on later without changing this interface.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone

_TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")
_GENERIC_TERMS = frozenset({"system", "admin", "administrator", "root", "user", "service"})

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(__file__)))), "data", "intel.json")


def _feed_record(rec: dict) -> dict:
    """Map one CVE-feed record onto the add() entry shape."""
    return {
        "id": rec.get("id") or rec.get("cve"),
        "title": rec.get("title") or rec.get("id") or rec.get("cve"),
        "summary": rec.get("description") or rec.get("summary", ""),
        "severity": rec.get("cvss") or rec.get("severity", ""),
        "keywords": rec.get("keywords", []),
        "techniques": rec.get("techniques", []),
        "published": rec.get("published", ""),
        "source": rec.get("source", "cve-feed"),
    }


def _as_list(v) -> list:
    """A string is one item (never split into characters); list items become str."""
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return []


class IntelStore:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path
        self.entries: list = []
        self.load_error: str | None = None
        self._load()

    # ---- persistence --------------------------------------------------------
    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                # A store file ({"entries": [...]}); a bare feed list (e.g.
                # feeds/intel_feed.json) is normalized like an import, unsaved.
                if isinstance(data, dict):
                    self.entries = [e for e in data.get("entries", []) if isinstance(e, dict)]
                elif isinstance(data, list):
                    self.entries = []
                    for rec in data:
                        if isinstance(rec, dict):
                            self.add(_feed_record(rec))
                else:
                    raise TypeError(f"top level is {type(data).__name__}, not an object or list")
            except (json.JSONDecodeError, OSError, AttributeError, TypeError, UnicodeDecodeError) as exc:
                # Keep the file on disk untouched: save() refuses to overwrite it.
                self.entries = []
                self.load_error = str(exc) or type(exc).__name__
                print(f"[bluecell] WARNING: intel store {self.path} is unreadable "
                      f"({self.load_error}); treating it as empty. Saving is disabled "
                      f"so the file is not overwritten.", file=sys.stderr)

    def save(self) -> None:
        if self.load_error:
            raise RuntimeError(f"refusing to overwrite {self.path}: it could not be loaded "
                               f"({self.load_error}). Repair or move the file, then retry.")
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"updated": datetime.now(timezone.utc).isoformat(),
                       "entries": self.entries}, fh, indent=2)
        os.replace(tmp, self.path)

    # ---- ingest -------------------------------------------------------------
    def add(self, entry: dict) -> bool:
        """Add one intel entry. Returns True if new (dedup by id)."""
        eid = entry.get("id") or entry.get("cve") or entry.get("title")
        if not eid:
            return False
        if any(e.get("id") == eid for e in self.entries):
            return False
        norm = {
            "id": eid,
            # Feeds send explicit nulls; coerce them so one record cannot
            # crash the whole import.
            "title": str(entry.get("title") or str(entry.get("summary") or "")[:120]),
            "summary": str(entry.get("summary") or ""),
            "severity": entry.get("severity", entry.get("cvss", "")),
            "techniques": _as_list(entry.get("techniques")),
            "keywords": [k.lower() for k in _as_list(entry.get("keywords"))],
            "published": entry.get("published", ""),
            "source": entry.get("source", "manual"),
            "added": datetime.now(timezone.utc).isoformat(),
        }
        # Auto-derive keywords from title/summary if none supplied.
        if not norm["keywords"]:
            text = (norm["title"] + " " + norm["summary"]).lower()
            norm["keywords"] = sorted({
                w.strip(".,;:()[]") for w in text.split()
                if len(w) > 4 and w.isascii()
            })[:20]
        self.entries.append(norm)
        return True

    def ingest_cve_feed(self, records: list) -> int:
        """Ingest a list of CVE-like dicts. Returns count of new entries."""
        added = 0
        for rec in records:
            if self.add(_feed_record(rec)):
                added += 1
        if added:
            self.save()
        return added

    # ---- retrieval (RAG) ----------------------------------------------------
    def search(self, terms, limit: int = 5) -> list:
        """Return intel entries matching any of the given terms, ranked."""
        # Generic account/word terms ("SYSTEM", "admin") match too much free text.
        wanted = {str(t).lower() for t in terms if t} - _GENERIC_TERMS
        if not wanted:
            return []
        scored = []
        for e in self.entries:
            hay = set(e.get("keywords", []))
            hay.update(str(e.get("title", "")).lower().split())
            hay.update(t.lower() for t in e.get("techniques", []))
            overlap = len(wanted & hay)
            # Whole-token hits in the summary (not substrings: "db" must not match "database").
            tokens = {t.strip(".-_") for t in _TOKEN_RE.findall(str(e.get("summary", "")).lower())}
            substr = sum(1 for t in wanted if len(t) >= 4 and t in tokens)
            score = overlap * 2 + substr
            if score > 0:
                scored.append((score, e))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _s, e in scored[:limit]]

    def context_for(self, incidents, limit: int = 5) -> list:
        """Gather intel relevant to a set of incidents (techniques + entities)."""
        terms = set()
        for inc in incidents:
            terms.update(inc.techniques)
            for vals in inc.entities.values():
                terms.update(str(v).lower() for v in vals)
            for e in inc.events:
                if e.process:
                    terms.add(e.process.lower())
        return self.search(terms, limit=limit)

    def stats(self) -> dict:
        srcs: dict = {}
        for e in self.entries:
            srcs[e.get("source", "?")] = srcs.get(e.get("source", "?"), 0) + 1
        return {"total": len(self.entries), "by_source": srcs, "path": self.path}