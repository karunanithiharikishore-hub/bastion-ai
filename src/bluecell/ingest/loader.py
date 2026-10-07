# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
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

# Order matters: more specific / multi-word tokens first so e.g. a filename
# "MTSummary_Message trace report" matches "mtsummary" before "message trace".
_SOURCE_HINTS = (
    "messagetraceresult", "messagetrace", "mtsummary", "message trace",
    "noninteractivesignins", "interactivesignins", "msisignins",
    "applicationsignins", "signins", "signin", "entra", "aad", "azure",
    "o365", "m365",
    "cloudtrail", "dns", "cloud", "firewall", "router", "switch",
    "network", "edr", "endpoint", "auth", "syslog",
)

# Some filename tokens are aliases for a canonical parser key in STRUCTURED_PARSERS.
_HINT_ALIASES = {
    "messagetraceresult": "messagetrace", "message trace": "messagetrace",
    "mtsummary": "messagetrace",
    "noninteractivesignins": "signins", "interactivesignins": "signins",
    "msisignins": "signins", "applicationsignins": "signins", "signin": "signins",
    "entra": "azure", "aad": "azure",
}


def _canon(hint: str) -> str:
    return _HINT_ALIASES.get(hint, hint)


def detect_source(filename: str, record: Optional[dict] = None,
                  override: Optional[str] = None) -> str:
    if override:
        return _canon(override.lower())
    if record:
        # Stringify keys: CSV rows with extra columns yield a None key.
        low = {str(k).lower(): x for k, x in record.items() if k is not None}
        for key in ("source", "log_type", "logtype", "type", "product"):
            v = record.get(key) or low.get(key)
            if isinstance(v, str):
                for hint in _SOURCE_HINTS:
                    if hint in v.lower():
                        return _canon(hint)
        # Column-shape detection for Microsoft exports without a source field.
        # Unified Audit Log: RecordType/Operation/AuditData columns.
        if "auditdata" in low and ("operation" in low or "recordtype" in low):
            return "ual"
        if "ip address" in low and ("status" in low or "sign-in error code" in low
                                    or "user" in low or "username" in low):
            return "signins"
        if ("sender_address" in low or "sender address" in low) or \
           ("recipient_address" in low or "recipient address" in low):
            return "messagetrace"
    name = os.path.basename(filename).lower()
    for hint in _SOURCE_HINTS:
        if hint in name:
            return _canon(hint)
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
    # utf-8-sig strips the byte-order mark Excel / Microsoft portal CSVs start
    # with; otherwise the first column header becomes "\ufefftimestamp".
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
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
            # Drop None keys (ragged rows / restkey) and empty values.
            clean = {k: v for k, v in rec.items() if k is not None and v not in (None, "")}
            source = detect_source(path, clean, override)
            ev = _parse_record(clean, source)
            if ev:
                events.append(ev)
    else:  # syslog / plaintext (lines that are JSON objects are parsed as records,
           # since many SIEM exports write JSON-per-line into .log / .txt files)
        for line in text.splitlines():
            rec = _json_object(line)
            if rec is not None:
                ev = _parse_record(rec, detect_source(path, rec, override))
            else:
                ev = parse_syslog_line(line)
                if ev and override:
                    ev.source = override
            if ev:
                events.append(ev)
    return events


def _json_object(line: str) -> Optional[dict]:
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


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