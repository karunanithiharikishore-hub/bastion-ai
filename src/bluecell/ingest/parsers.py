"""Per-source parsers.

Each parser takes one raw record (a dict from JSON/CSV, or a string line for
syslog) and returns an Event, or None if the record is not usable. Parsers are
deliberately defensive: malformed records are skipped, never fatal.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Event


# ---- helpers ---------------------------------------------------------------

def _get(d: dict, *keys, default=None):
    """Return the first present, non-empty value among keys (case-insensitive)."""
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, "", []):
            return v
    return default


_SEV_WORDS = {
    "info": 1, "informational": 1, "low": 1, "notice": 1,
    "warn": 2, "warning": 2, "medium": 2,
    "high": 3, "error": 3, "err": 3,
    "critical": 4, "crit": 4, "fatal": 4, "alert": 4, "emergency": 4,
}


def _severity(val) -> int:
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        n = int(val)
        return max(0, min(4, n))
    s = str(val).strip().lower()
    if s.isdigit():
        return max(0, min(4, int(s)))
    return _SEV_WORDS.get(s, 0)


# ---- structured (dict) parsers --------------------------------------------

def parse_edr(r: dict) -> Optional[Event]:
    """Endpoint / EDR alerts and process telemetry."""
    action = _get(r, "action", "event_type", "operation", "activity", default="edr_event")
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "eventTime", default=None),
        source="edr",
        category="alert" if _get(r, "alert", "detection", "threat_name") else "process",
        action=str(action),
        message=str(_get(r, "message", "description", "threat_name", "name", default=action)),
        severity=_severity(_get(r, "severity", "risk", "level")),
        host=_get(r, "host", "hostname", "device", "endpoint", "computer_name"),
        user=_get(r, "user", "username", "account", "user_name"),
        process=_get(r, "process", "process_name", "image", "proc"),
        file_path=_get(r, "file_path", "path", "target_file"),
        file_hash=_get(r, "sha256", "hash", "file_hash", "md5"),
        src_ip=_get(r, "src_ip", "source_ip", "local_ip"),
        dst_ip=_get(r, "dst_ip", "dest_ip", "remote_ip"),
        raw=r,
    )


def parse_dns(r: dict) -> Optional[Event]:
    domain = _get(r, "query", "domain", "question", "name", "qname")
    if not domain:
        return None
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", default=None),
        source="dns",
        category="dns",
        action="dns_query",
        message=f"DNS query {domain} -> {_get(r, 'answer', 'response', 'resolved_ip', default='?')}",
        severity=_severity(_get(r, "severity")),
        host=_get(r, "host", "client", "source_host"),
        src_ip=_get(r, "src_ip", "client_ip", "source_ip"),
        dst_ip=_get(r, "resolved_ip", "answer_ip"),
        domain=str(domain).rstrip("."),
        raw=r,
    )


def parse_network(r: dict) -> Optional[Event]:
    """Firewall / router / switch / netflow style connection records."""
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", default=None),
        source=str(_get(r, "source", "device_type", default="firewall")),
        category="network",
        action=str(_get(r, "action", "verdict", "disposition", default="connection")),
        message=str(_get(
            r, "message",
            default=f"{_get(r, 'src_ip', 'source_ip', default='?')} -> "
                    f"{_get(r, 'dst_ip', 'dest_ip', default='?')}:"
                    f"{_get(r, 'dst_port', 'port', default='?')}")),
        severity=_severity(_get(r, "severity", "level")),
        host=_get(r, "host", "device", "hostname"),
        src_ip=_get(r, "src_ip", "source_ip", "src"),
        dst_ip=_get(r, "dst_ip", "dest_ip", "dst", "destination_ip"),
        raw=r,
    )


def parse_cloud(r: dict) -> Optional[Event]:
    """Cloud audit logs (AWS CloudTrail / Azure / GCP), normalized loosely."""
    action = _get(r, "eventName", "operationName", "methodName", "action", default="cloud_api")
    return Event(
        ts=_get(r, "eventTime", "timestamp", "time", "@timestamp", default=None),
        source=str(_get(r, "eventSource", "provider", default="cloud")),
        category="cloud_api",
        action=str(action),
        message=str(_get(r, "message", "errorMessage", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if _get(r, "errorCode") else "info"))),
        user=_get(r, "userIdentity.userName", "userName", "principal", "caller")
        or (r.get("userIdentity", {}) or {}).get("userName") if isinstance(r.get("userIdentity"), dict) else _get(r, "userName", "principal"),
        src_ip=_get(r, "sourceIPAddress", "callerIp", "src_ip"),
        raw=r,
    )


def parse_auth(r: dict) -> Optional[Event]:
    """Generic authentication events (server auth, IdP, VPN)."""
    action = _get(r, "action", "event", default="auth")
    return Event(
        ts=_get(r, "timestamp", "ts", "time", default=None),
        source=str(_get(r, "source", default="auth")),
        category="authentication",
        action=str(action),
        message=str(_get(r, "message", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if "fail" in str(action).lower() else "info"))),
        host=_get(r, "host", "hostname", "server"),
        user=_get(r, "user", "username", "account"),
        src_ip=_get(r, "src_ip", "source_ip", "client_ip"),
        raw=r,
    )


# ---- syslog (line) parser --------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user|for|account)\s+(?P<u>[\w.\-\\@]+)", re.I)


def parse_syslog_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    m = _SYSLOG_RE.match(line)
    if not m:
        # Not RFC3164-ish; keep the line as an 'other' event so nothing is lost.
        return Event(ts=None, source="syslog", category="other",
                     action="log", message=line[:500], raw={"line": line})
    msg = m.group("msg")
    low = msg.lower()
    if "fail" in low and ("password" in low or "authentication" in low or "login" in low):
        action, category, sev = "login_failed", "authentication", 3
    elif "accepted" in low and "password" in low:
        action, category, sev = "login_success", "authentication", 1
    elif "sudo" in (m.group("proc") or "").lower():
        action, category, sev = "sudo", "process", 2
    else:
        action, category, sev = "log", "other", 1
    ips = _IP_RE.findall(msg)
    um = _USER_RE.search(msg)
    return Event(
        ts=m.group("ts"),
        source="syslog",
        category=category,
        action=action,
        message=msg[:500],
        severity=sev,
        host=m.group("host"),
        process=m.group("proc"),
        user=um.group("u") if um else None,
        src_ip=ips[0] if ips else None,
        raw={"line": line},
    )


# Map a detected source label -> structured parser.
STRUCTURED_PARSERS = {
    "edr": parse_edr,
    "endpoint": parse_edr,
    "dns": parse_dns,
    "network": parse_network,
    "firewall": parse_network,
    "router": parse_network,
    "switch": parse_network,
    "cloud": parse_cloud,
    "cloudtrail": parse_cloud,
    "auth": parse_auth,
}
