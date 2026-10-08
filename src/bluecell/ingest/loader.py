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

import copy
import csv
import io
import json
import os
import sys
from typing import Iterable, Iterator, Optional

from ..models import Event
from .parsers import STRUCTURED_PARSERS, parse_dns, parse_edr, parse_syslog_line

# Order matters: more specific / multi-word tokens first so e.g. a filename
# "MTSummary_Message trace report" matches "mtsummary" before "message trace".
_SOURCE_HINTS = (
    "messagetraceresult", "messagetrace", "mtsummary", "message trace",
    "noninteractivesignins", "interactivesignins", "msisignins",
    "applicationsignins", "signins", "signin", "entra", "aad", "azure",
    "auditlog", "unifiedaudit", "o365", "m365",
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
    "auditlog": "ual", "unifiedaudit": "ual",
}

# Unified Audit Log exports can carry AuditData blobs far larger than csv's
# default 128 KiB field limit; raise it as far as the platform's C long allows.
_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_limit)
        break
    except OverflowError:
        _limit //= 10


def _canon(hint: str) -> str:
    return _HINT_ALIASES.get(hint, hint)


def detect_source(filename: str, record: Optional[dict] = None,
                  override: Optional[str] = None) -> str:
    if override:
        return _canon(override.lower())
    source = _detect(filename, record)
    if record and source in ("azure", "signins", "ual"):
        # Azure Activity (operationName/caller) and Entra audit logs
        # (activityDisplayName) share the azure/entra/aad hints with sign-ins
        # but are audit trails, not sign-ins.
        low = {str(k).lower() for k in record if k is not None}
        if ("operationname" in low or "activitydisplayname" in low) and \
                not ({"auditdata", "operation", "operations"} & low):
            return "cloud"
    return source


def _detect(filename: str, record: Optional[dict]) -> str:
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
        if "auditdata" in low and ("operation" in low or "operations" in low
                                   or "recordtype" in low):
            return "ual"
        if "ip address" in low and ("status" in low or "sign-in error code" in low
                                    or "user" in low or "username" in low):
            return "signins"
        if any(k in low for k in ("sender_address", "sender address", "senderaddress",
                                  "recipient_address", "recipient address",
                                  "recipientaddress", "recipient_status")):
            return "messagetrace"
    name = os.path.basename(filename).lower()
    for hint in _SOURCE_HINTS:
        if hint in name:
            return _canon(hint)
    return "edr"


def _parse_record(rec: dict, source: str) -> Optional[Event]:
    parser = STRUCTURED_PARSERS.get(source, parse_edr)
    try:
        ev = parser(rec)
        if ev is None and parser is not parse_edr and parser is not parse_dns and rec:
            # Wrong guess at the source (e.g. a filename hint): keep the record
            # as a generic event rather than silently dropping it. DNS rows
            # without a domain are deliberately dropped.
            ev = parse_edr(rec)
        return ev
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
            for key in ("Records", "records", "events", "logs", "data", "value"):
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
    with open(path, "rb") as fh:
        data = fh.read()
    # PowerShell `>` / Out-File writes UTF-16 with a BOM. utf-8-sig strips the
    # byte-order mark Excel / Microsoft portal CSVs start with; otherwise the
    # first column header becomes "\ufefftimestamp".
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    else:
        text = data.decode("utf-8-sig", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")   # universal newlines

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
        while True:
            try:
                rec = next(reader)
            except StopIteration:
                break
            except csv.Error:
                continue   # one malformed row must not abort the file
            # Drop None keys (ragged rows / restkey) and empty values; strip
            # padding ("timestamp, src_ip") so headers and values match.
            clean = {k.strip(): v.strip() if isinstance(v, str) else v
                     for k, v in rec.items() if k is not None}
            clean = {k: v for k, v in clean.items() if v not in (None, "")}
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
                events.extend(_expand_repeats(ev))
    return events


def _expand_repeats(ev: Event) -> list:
    """"message repeated N times: [...]" stands for N identical events; emit
    each so brute-force counts are right (repeat index keeps event_ids distinct)."""
    n = ev.raw.get("repeated") if isinstance(ev.raw, dict) else None
    if not n:
        return [ev]
    out = []
    for i in range(n):
        dup = copy.copy(ev)
        dup.raw = dict(ev.raw, repeat_index=i)
        dup.attack, dup.tags = list(ev.attack), list(ev.tags)
        out.append(dup)
    return out


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
                    fpath = os.path.join(root, fname)
                    try:
                        events.extend(ingest_file(fpath, override))
                    except OSError as exc:
                        # One unreadable file must not abort the whole directory.
                        print(f"bluecell: skipping {fpath}: {exc}", file=sys.stderr)
        return events
    return ingest_file(path, override)


def ingest_paths(paths: Iterable[str], override: Optional[str] = None) -> list:
    events: list = []
    for p in paths:
        events.extend(ingest_path(p, override))
    return events