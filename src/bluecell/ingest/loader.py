"""File/dir loaders with source auto-detection.

Supported inputs:
- .json  : either a JSON array of records, or JSONL (one object per line)
- .jsonl : JSONL
- .csv   : header row + rows
- .log / .txt / .syslog : line-based syslog

Source type is taken from (in order): an explicit override, a ``source`` /
``log_type`` field in the record, or the filename (e.g. ``dns.json``,
``firewall.csv``). Unknown structured records fall back to the EDR parser,
which is the most general.
"""
from __future__ import annotations

import csv
import io
import json
import os
from typing import Iterable, Iterator, Optional

from ..models import Event
from .parsers import STRUCTURED_PARSERS, parse_edr, parse_syslog_line

_SOURCE_HINTS = (
    "dns", "cloudtrail", "cloud", "firewall", "router", "switch",
    "network", "edr", "endpoint", "auth", "syslog",
)


def detect_source(filename: str, record: Optional[dict] = None,
                   override: Optional[str] = None) -> str:
    if override:
        return override.lower()
    if record:
        for key in ("source", "log_type", "logtype", "type", "product"):
            v = record.get(key) or {k.lower(): x for k, x in record.items()}.get(key)
            if isinstance(v, str):
                for hint in _SOURCE_HINTS:
                    if hint in v.lower():
                        return hint
    name = os.path.basename(filename).lower()
    for hint in _SOURCE_HINTS:
        if hint in name:
            return hint
    return "edr"


def _parse_record(rec: dict, source: str) -> Optional[Event]:
    parser = STRUCTURED_PARSERS.get(source, parse_edr)
    try:
        return parser(rec)
    except Exception:
        # A single bad record must never break the batch.
        try:
            return parse_edr(rec)
        except Exception:
            return None


def _iter_json_records(text: str) -> Iterator[dict]:
    text = text.strip()
    if not text:
        return
    # Try a single JSON document (array or object) first.
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
            return
        if isinstance(data, dict):
            # Some exports wrap records under 'Records'/'events'/'logs'.
            for key in ("Records", "records", "events", "logs", "data"):
                if isinstance(data.get(key), list):
                    for item in data[key]:
                        if isinstance(item, dict):
                            yield item
                    return
            yield data
            return
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError:
            continue


def ingest_file(path: str, override: Optional[str] = None) -> list:
    """Parse one file into a list of Events."""
    ext = os.path.splitext(path)[1].lower()
    events: list = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    if ext in (".json", ".jsonl", ".ndjson"):
        first = None
        for rec in _iter_json_records(text):
            if first is None:
                first = rec
            source = detect_source(path, rec, override)
            ev = _parse_record(rec, source)
            if ev:
                events.append(ev)
    elif ext == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        for rec in reader:
            source = detect_source(path, rec, override)
            ev = _parse_record({k: v for k, v in rec.items() if v != ""}, source)
            if ev:
                events.append(ev)
    else:  # syslog / plaintext
        for line in text.splitlines():
            ev = parse_syslog_line(line)
            if ev:
                if override:
                    ev.source = override
                events.append(ev)
    return events


def ingest_path(path: str, override: Optional[str] = None) -> list:
    """Parse a file or recurse a directory into Events."""
    if os.path.isdir(path):
        events: list = []
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                if fname.startswith("."):
                    continue
                if os.path.splitext(fname)[1].lower() in (
                    ".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".syslog"
                ):
                    events.extend(ingest_file(os.path.join(root, fname), override))
        return events
    return ingest_file(path, override)


def ingest_paths(paths: Iterable[str], override: Optional[str] = None) -> list:
    events: list = []
    for p in paths:
        events.extend(ingest_path(p, override))
    return events
