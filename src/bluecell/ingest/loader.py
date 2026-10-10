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
import itertools
import json
import os
import re
import sys
from typing import Iterable, Iterator, Optional

from ..models import Event
from .parsers import (_REPEAT_CAP, STRUCTURED_PARSERS, parse_dns, parse_edr,
                      parse_syslog_line)

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
        # Column-shape detection for exports without a source field. These run
        # before the filename hint, so a misleading name ("firewall_*.csv") loses.
        # Unified Audit Log: RecordType/Operation/AuditData columns.
        if "auditdata" in low and ("operation" in low or "operations" in low
                                   or "recordtype" in low):
            return "ual"
        if ("eventname" in low and "eventsource" in low) or "awsregion" in low:
            return "cloudtrail"   # AWS CloudTrail
        if "operationname" in low and ("caller" in low or "correlationid" in low
                                       or "calleripaddress" in low):
            return "cloud"        # Azure Activity log
        if "devicename" in low and ("actiontype" in low or "remoteip" in low
                                    or "initiatingprocessfilename" in low):
            return "edr"          # Defender / Sentinel Advanced Hunting (DeviceNetworkEvents etc.)
        # A Sentinel SecurityEvent export carries Status/IpAddress too; EventID + Computer/Account wins.
        sec_event = "eventid" in low and ("computer" in low or "account" in low)
        if not sec_event and ("ip address" in low or "ipaddress" in low) and (
                "status" in low or "sign-in error code" in low or "user" in low
                or "username" in low or "userprincipalname" in low or "resulttype" in low):
            return "signins"
        if {"source address", "destination address"} <= set(low):
            return "network"      # PAN-OS traffic CSV
        if {"src_ip", "dst_ip"} <= set(low):
            return "network"      # firewall-shaped rows; beats a filename hint like "azure_firewall"
        if any(k in low for k in ("sender_address", "sender address", "senderaddress",
                                  "recipient_address", "recipient address",
                                  "recipientaddress", "recipient_status")):
            return "messagetrace"
    name = os.path.basename(filename).lower()
    for hint in _SOURCE_HINTS:
        if hint in name:
            return _canon(hint)
    return "edr"


def _is_blank(rec: dict) -> bool:
    return not any(v not in (None, "", [], {}) for v in rec.values())


def _parse_record(rec: dict, source: str) -> Optional[Event]:
    # Blank rows (Excel trailing ",,,") and {} carry nothing; parsing them would
    # stamp a phantom event at now().
    if _is_blank(rec):
        return None
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


_WRAPPER_KEYS = ("Records", "records", "events", "logs", "data", "value", "results")
# A dict carrying any of these is an event itself, not an envelope around a list.
_EVENT_KEYS = frozenset({"timestamp", "time", "eventtime", "eventtimestamp", "@timestamp",
                         "createddatetime", "host", "hostname", "user", "username",
                         "userprincipalname", "eventname", "operationname", "message"})
_WS = re.compile(r"\s*")


def _splunk_fields(rec: dict) -> dict:
    """Splunk exports name the event time and raw line _time/_raw; map them to
    timestamp/message unless the record already has those keys."""
    extra = {new: rec[old] for old, new in (("_time", "timestamp"), ("_raw", "message"))
             if old in rec and new not in rec}
    return {**rec, **extra} if extra else rec


def _unwrap(obj) -> Iterator[dict]:
    """Yield the record dicts in a decoded JSON value, unwrapping lists and
    'Records'-style wrappers at every level, plus Elasticsearch hits
    (``_source``), ES search responses (``hits.hits``) and Splunk exports
    (``result`` / ``results``)."""
    if isinstance(obj, list):
        for item in obj:
            yield from _unwrap(item)
    elif isinstance(obj, dict):
        if any(str(k).lower() in _EVENT_KEYS for k in obj):
            yield _splunk_fields(obj)   # a single event with a list field keeps its own fields
        elif isinstance(obj.get("_source"), dict):
            yield obj["_source"]
        elif isinstance(obj.get("result"), dict):
            yield _splunk_fields(obj["result"])
        elif isinstance(obj.get("hits"), dict):
            yield from _unwrap(obj["hits"].get("hits", []))
        else:
            key = next((k for k in _WRAPPER_KEYS if isinstance(obj.get(k), list)), None)
            if key is None:
                yield _splunk_fields(obj)
            else:
                yield from _unwrap(obj[key])


# Event.to_dict()/asdict recurse over raw, so records nested deeper than this
# would crash export later; they are skipped at ingest instead.
_MAX_JSON_DEPTH = 64


def _too_deep(obj) -> bool:
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > _MAX_JSON_DEPTH:
            return True
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return False


def _iter_json_records(text: str) -> Iterator[dict]:
    """Yield every record in a stream of JSON values (one document, JSONL,
    concatenated or pretty-printed objects)."""
    dec = json.JSONDecoder()
    pos = _WS.match(text, 0).end()
    while pos < len(text):
        try:
            obj, pos = dec.raw_decode(text, pos)
        except (json.JSONDecodeError, RecursionError) as exc:
            if isinstance(exc, RecursionError):
                print("bluecell: skipping JSON nested too deeply", file=sys.stderr)
            nl = text.find("\n", pos)
            if nl < 0:
                return
            pos = nl + 1   # skip one broken line; the rest of the stream still parses
        else:
            if _too_deep(obj):
                print(f"bluecell: skipping JSON nested deeper than {_MAX_JSON_DEPTH}",
                      file=sys.stderr)
            else:
                yield from _unwrap(obj)
        pos = _WS.match(text, pos).end()


_CSV_DELIMITERS = ",;\t|"


def _csv_reader(text: str, quoting: int = csv.QUOTE_MINIMAL) -> csv.DictReader:
    """DictReader for CSV text: an Excel ``sep=X`` first line sets the delimiter
    and is dropped; otherwise the delimiter is sniffed (comma when unsure)."""
    head, _, rest = text.lstrip("\n").partition("\n")
    m = re.fullmatch(r"sep=(.)\s*", head)
    if m:
        return csv.DictReader(io.StringIO(rest), delimiter=m.group(1), quoting=quoting)
    try:
        delim = csv.Sniffer().sniff(text[:65536], delimiters=_CSV_DELIMITERS).delimiter
    except csv.Error:
        delim = ","
    # shortcut: a comma in the header forces comma so ;-heavy values in a comma CSV
    # cannot flip the parse; a ;-file whose column name has a comma will misparse, upgrade to header-count voting if seen.
    if delim != "," and "," in head:
        delim = ","
    return csv.DictReader(io.StringIO(text), delimiter=delim, quoting=quoting)


def _fold_overflow(rec: dict, fieldnames: list) -> dict:
    """Re-join fields a ragged row pushed past the header (DictReader's None key).
    An unquoted "Receive, Deliver" in Recipient_status splits into extra fields:
    merge them back into that column and shift the rest so later columns keep
    their values. Other overflow is kept under a raw key, never dropped."""
    extra = rec.pop(None, None)
    if not extra:
        return rec
    names = [re.sub(r"[^a-z]", "", str(n).lower()) for n in fieldnames]
    raw = [rec.get(n) for n in fieldnames] + extra
    width = len(fieldnames)
    # shortcut: the surplus is always merged into Recipient_status even if a later
    # unquoted comma really belonged to a later column; upgrade to per-pair validation.
    if "recipientstatus" in names:
        i, k = names.index("recipientstatus"), len(extra)
        raw[i:i + k + 1] = [",".join(raw[i:i + k + 1])]
        return dict(zip(fieldnames, raw))
    out = dict(zip(fieldnames, raw[:width]))
    out["_overflow"] = ",".join(extra)
    return out


def _read_csv_rows(text: str, quoting: int) -> tuple:
    """(rows, swallowed): swallowed is True when a row's quoted field holds lines
    shaped like further records (a stray leading quote ate them)."""
    reader = _csv_reader(text, quoting)
    width = len(reader.fieldnames or [])
    delim = reader.reader.dialect.delimiter
    rows: list = []
    while True:
        try:
            rec = next(reader)
        except StopIteration:
            return rows, False
        except csv.Error:
            continue   # one malformed row must not abort the file
        rows.append(_fold_overflow(rec, reader.fieldnames))
        if any(isinstance(v, str) and any(line.count(delim) == width - 1
                                          for line in v.split("\n")[1:])
               for v in rec.values()):
            return rows, True


def _csv_rows(text: str, path: str) -> list:
    rows, swallowed = _read_csv_rows(text, csv.QUOTE_MINIMAL)
    if swallowed:
        # Quotes are unbalanced, so one row ate the records after it: re-parse with
        # quoting off so each physical line is its own row.
        print(f"bluecell: unbalanced quote in {path}; re-parsing without quote handling",
              file=sys.stderr)
        rows, _ = _read_csv_rows(text, csv.QUOTE_NONE)
    return rows


_SHAPE_SAMPLE = 200   # records that decide a file's source


def _file_shape(sample: list) -> dict:
    """Union of the sampled records' keys, each holding its first non-empty value."""
    shape: dict = {}
    for rec in sample:
        for k, v in rec.items():
            if k is not None and (k not in shape or shape[k] in (None, "", [], {})):
                shape[k] = v
    return shape


def _detect_view(shape: dict, rec: dict) -> dict:
    """The row as detection sees it: its own non-empty cells over the file's shape,
    so an empty cell in one row cannot change the file's source."""
    return {**shape, **{k: v for k, v in rec.items() if v not in (None, "", [], {})}}


def ingest_file(path: str, override: Optional[str] = None) -> list:
    """Parse one file into a list of Events."""
    ext = os.path.splitext(path)[1].lower()
    events: list = []
    skipped = 0   # non-blank records that produced no event (BUG-INGEST-12)
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
        recs = _iter_json_records(text)
        head = list(itertools.islice(recs, _SHAPE_SAMPLE))
        shape = _file_shape(head)   # one source per file, decided from its first records
        count = 0
        for rec in itertools.chain(head, recs):
            count += 1
            source = detect_source(path, _detect_view(shape, rec), override)
            ev = _parse_record(rec, source)
            if ev:
                events.append(ev)
            elif not _is_blank(rec):
                skipped += 1
        if text.strip() and not count:
            print(f"bluecell: no JSON records found in {path}", file=sys.stderr)
    elif ext == ".csv":
        rows = []
        for rec in _csv_rows(text, path):
            # Drop None keys (ragged rows / restkey) and empty values; strip
            # padding ("timestamp, src_ip") so headers and values match.
            clean = {k.strip(): v.strip() if isinstance(v, str) else v
                     for k, v in rec.items() if k is not None}
            rows.append({k: v for k, v in clean.items() if v not in (None, "")})
        shape = _file_shape(rows[:_SHAPE_SAMPLE])   # one source per file
        for clean in rows:
            source = detect_source(path, _detect_view(shape, clean), override)
            ev = _parse_record(clean, source)
            if ev:
                events.append(ev)
            elif not _is_blank(clean):
                skipped += 1
    else:  # syslog / plaintext (lines that are JSON objects are parsed as records,
           # since many SIEM exports write JSON-per-line into .log / .txt files)
        for line in text.split("\n"):   # not splitlines(): U+2028/0x85/\x0c would forge lines
            recs = list(_iter_json_records(line))
            if recs:
                # Vendor JSON may carry its own "repeated" key; only the syslog
                # parser's repeat counter may expand into events.
                for rec in recs:
                    ev = _parse_record(rec, detect_source(path, rec, override))
                    if ev:
                        events.append(ev)
                    elif not _is_blank(rec):
                        skipped += 1
            else:
                ev = parse_syslog_line(line)
                if ev and override:
                    ev.source = override
                if ev:
                    events.extend(_expand_repeats(ev))
    if skipped:
        print(f"bluecell: skipped {skipped} unrecognized record(s) in {path}", file=sys.stderr)
    return events


def _expand_repeats(ev: Event) -> list:
    """"message repeated N times: [...]" stands for N identical events; emit
    each so brute-force counts are right (repeat index keeps event_ids distinct)."""
    n = ev.raw.get("repeated") if isinstance(ev.raw, dict) else None
    if not isinstance(n, int) or isinstance(n, bool):
        return [ev]
    n = min(n, _REPEAT_CAP)
    if n <= 0:
        return [ev]
    out = []
    for i in range(n):
        dup = copy.copy(ev)
        dup.raw = dict(ev.raw, repeat_index=i)
        dup.attack, dup.tags = list(ev.attack), list(ev.tags)
        out.append(dup)
    return out


_EVAL_VERDICTS = ("likely-malicious", "likely-benign", "needs-review")


def _is_eval_label(path: str) -> bool:
    """True for an eval case's ``expected.json`` (see bluecell.evals): a small
    JSON object whose ``verdict`` is a BlueCell verdict level. Directory walks
    skip it so ``bluecell analyze evals/cases/<case>`` never ingests the answer
    key as an event."""
    try:
        if os.path.getsize(path) > 65536:
            return False
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return False
    return isinstance(obj, dict) and obj.get("verdict") in _EVAL_VERDICTS


def ingest_path(path: str, override: Optional[str] = None) -> list:
    """Parse a file or recurse a directory into Events."""
    if os.path.isdir(path):
        events: list = []
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                if fname.startswith("."):
                    continue
                if fname == "expected.json" and _is_eval_label(os.path.join(root, fname)):
                    continue   # an eval case's label file, not a log
                if os.path.splitext(fname)[1].lower() in (
                    ".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".syslog"
                ):
                    fpath = os.path.join(root, fname)
                    try:
                        events.extend(ingest_file(fpath, override))
                    except (OSError, RecursionError) as exc:
                        # One unreadable or over-nested file must not abort the whole directory.
                        print(f"bluecell: skipping {fpath}: {exc}", file=sys.stderr)
        return events
    return ingest_file(path, override)


def ingest_paths(paths: Iterable[str], override: Optional[str] = None) -> list:
    events: list = []
    for p in paths:
        events.extend(ingest_path(p, override))
    return events