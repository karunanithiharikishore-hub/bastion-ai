# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Per-source parsers.

Each parser takes one raw record (a dict from JSON/CSV, or a string line for
syslog) and returns an Event, or None if the record is not usable. Parsers are
deliberately defensive: malformed records are skipped, never fatal.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit

from ..models import Event


# ---- helpers ---------------------------------------------------------------

def _get(d: dict, *keys, default=None):
    """Return the first present, non-empty value among keys (case-insensitive).

    Robust to messy inputs: CSV rows with more columns than headers produce a
    ``None`` key (csv.DictReader restkey), so keys are stringified before
    lowercasing to avoid AttributeError on non-string keys.
    """
    lower = {str(k).lower(): v for k, v in d.items() if k is not None}
    for k in keys:
        v = lower.get(str(k).lower())
        if v is None and "." in str(k):
            v = _dotted(d, str(k))
        if isinstance(v, list):   # ECS arrays (host.name: ["DC01"]): first non-empty element
            v = next((x for x in v if x not in (None, "", [])), None)
        if v not in (None, "", []):
            return v
    return default


def _dotted(d: dict, path: str):
    """ECS nested value: "host.name" -> d["host"]["name"]. Flat dotted keys win (checked first in _get)."""
    if d.get(path) is not None:   # flat dotted key inside a nested object (Falco output_fields["fd.sip"])
        return d[path]
    head, _, rest = path.partition(".")
    v = _get(d, head)
    if not rest:
        return v
    return _dotted(v, rest) if isinstance(v, dict) else None


def _entity(r: dict, *keys):
    """Host/user name. A dict is an ECS object (host: {ip: ...}), not a name, so it is skipped."""
    return _get(r, *(k for k in keys if not isinstance(_get(r, k), dict)))


def _clean_ip(val) -> Optional[str]:
    """IP text with control chars, port and brackets removed; None if it is not an IP.

    "1.2.3.4:443" -> "1.2.3.4", "[2001:db8::1]:443" -> "2001:db8::1"; IPv6 is
    returned in compressed lowercase and "::ffff:1.2.3.4" as "1.2.3.4", so one
    host always has one spelling. Unspecified addresses
    ("0.0.0.0", "::") mean "any"/"unset" in firewall and syslog exports, so they
    are dropped too: kept, they would link every such record into one incident.
    """
    if val in (None, ""):
        return None
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(val)).strip()   # NUL and C0 controls
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::\d+)?", s) or \
        re.fullmatch(r"((?:\d{1,3}\.){3}\d{1,3}):\d+", s)
    if m:
        s = m.group(1)
    try:
        ip = ipaddress.ip_address(s.split("%", 1)[0])   # zone id (fe80::1%eth0) is not part of the address
    except ValueError:
        return None
    if getattr(ip, "ipv4_mapped", None):   # ::ffff:1.2.3.4 is the same host as 1.2.3.4
        ip = ip.ipv4_mapped
    return None if ip.is_unspecified else str(ip)


def _ip_field(r: dict, *keys) -> Optional[str]:
    """First of keys whose value is a real IP; placeholders ('-', 'N/A') fall through."""
    for k in keys:
        for part in str(_get(r, k) or "").split(","):   # "a, b" (X-Forwarded-For style) -> first valid
            ip = _clean_ip(part)
            if ip:
                return ip
    return None


def _log_source(r: dict, default: str) -> str:
    """Log-source label from source/device_type; firewall CSVs put an address in `source`, which is not a label."""
    for v in (_get(r, "source"), _get(r, "device_type")):
        if v is not None and not _is_addr(v):
            return str(v)
    return default


def _is_addr(v) -> bool:
    s = str(v).strip()
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return _clean_ip(s) is not None   # "ip:port" / "[ipv6]:port"


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
        try:
            return max(0, min(4, int(val)))
        except (ValueError, OverflowError):   # NaN / inf
            return 0
    s = str(val).strip().lower()
    if s.isdigit():
        return max(0, min(4, int(s)))
    return _SEV_WORDS.get(s, 0)


# ---- structured (dict) parsers --------------------------------------------

# Every key parse_edr reads. A record with none of them is not an EDR event (BUG-INGEST-12).
_EDR_KEYS = (
    "action", "event_type", "operation", "activity", "ActionType", "alert", "detection",
    "threat_name", "process", "process_name", "image", "proc", "ProcessCommandLine", "FileName",
    "InitiatingProcessFileName", "InitiatingProcessCommandLine", "RemoteIP", "LocalIP",
    "RemotePort", "src_ip", "source_ip", "local_ip", "dst_ip", "dest_ip", "remote_ip",
    "timestamp", "ts", "time", "@timestamp", "eventTime", "TimeGenerated", "TimeGenerated [UTC]",
    "message", "description", "name", "severity", "risk", "level", "host", "hostname", "device",
    "endpoint", "computer_name", "DeviceName", "user", "username", "account", "user_name",
    "AccountName", "InitiatingProcessAccountName", "file_path", "path", "target_file", "sha256",
    "hash", "file_hash", "sha1", "md5", "RemoteUrl",
    "EventID", "Computer", "MachineName", "TimeCreated", "AlertName", "AlertSeverity", "CompromisedEntity",
    "event.action", "source.ip", "destination.ip",
    "UtcTime", "CommandLine", "Hashes", "TargetFilename", "QueryName", "DestinationIp", "DestinationPort",
    "Date and Time", "Event ID", "Task Category",
)


def _sysmon_sha256(r: dict) -> Optional[str]:
    """Sysmon Hashes is "MD5=..,SHA256=..,IMPHASH=.."; keep only the SHA256 value."""
    m = re.search(r"SHA256=([0-9A-Fa-f]+)", str(_get(r, "Hashes", default="")))
    return m.group(1) if m else None


def _url_host(u: str) -> Optional[str]:
    try:
        return urlsplit(u if "//" in u else "//" + u).hostname
    except ValueError:  # malformed IPv6 brackets in a log row: keep the row, drop the host
        return None


def parse_edr(r: dict) -> Optional[Event]:
    """Endpoint / EDR alerts, process telemetry, and Defender Advanced Hunting Device* tables."""
    if _get(r, *_EDR_KEYS) is None:
        return None
    action = _get(r, "action", "event.action", "event_type", "operation", "activity", "ActionType", "Task Category",
                  default="edr_event")
    # Sentinel SecurityEvent / Get-WinEvent logons (R4-INGEST-2).
    eid = str(_get(r, "EventID", "Event ID", default=_get(r, "Id") if _get(r, "MachineName") else "")).strip()
    # ECS event.action "logon-failed" (winlogbeat 4625) is the same failure.
    # Generic EDR/ECS failures (ITEM-12): ECS event.category/outcome, or an sshd-style message with no action.
    ecs = {"failure": "login_failed", "failed": "login_failed", "success": "login_success"}.get(
        str(_get(r, "event.outcome", default="")).lower()) \
        if "authentication" in str(_get(r, "event.category", default="")).lower() else None
    if ecs is None and re.match(r"failed (?:password|login|logon)\b", str(_get(r, "message", default="")), re.I):
        ecs = "login_failed"
    # 4776 (NTLM) / 4768 / 4769 outcome is in Status (0x0 = success); 4769 success is a ticket, not a sign-in.
    status = str(_get(r, "Status", default="")).strip().lower()
    status_auth = ("login_success" if status in ("0x0", "0") else "login_failed") if status else None
    if eid == "4769" and status_auth == "login_success":
        status_auth = None
    winauth = {"4624": "login_success", "4625": "login_failed", "4771": "login_failed", "4740": "account_lockout"}.get(eid) or \
        (status_auth if eid in ("4776", "4768", "4769") else None) or \
        {"logon-failed": "login_failed", "logon_failed": "login_failed", "failed_login": "login_failed",
         "login_failed": "login_failed"}.get(str(action).lower()) or ecs
    if winauth:
        action = winauth
    # CSV gives "false"/"0" as text, which is truthy; treat those as no alert.
    alert = any(str(v).strip().lower() not in ("false", "0", "no", "none", "")
                for v in (_get(r, "alert"), _get(r, "detection"), _get(r, "threat_name"), _get(r, "AlertName"))
                if v is not None)
    # DeviceProcessEvents: FileName is the process itself; InitiatingProcess* is its parent.
    proc = _get(r, "process", "process_name", "image", "proc")
    if proc is None and _get(r, "ProcessCommandLine") is not None:
        proc = _get(r, "FileName")
    proc = proc or _get(r, "InitiatingProcessFileName", "FileName")
    # DeviceNetworkEvents rows carry RemoteIP/LocalIP; they are connections, not processes.
    # DeviceLogonEvents: a sign-in, not a connection. Its message names "failed"
    # as a word, because attack.py's _FAIL_RE does not match "LogonFailed".
    logon = str(action).lower() in ("logonsuccess", "logonfailed", "logonattempted")
    net = _get(r, "RemoteIP", "LocalIP", "DestinationIp") is not None and not logon
    src_ip = _ip_field(r, "src_ip", "source_ip", "source.ip", "local_ip", "LocalIP", "SourceIp")
    dst_ip = _ip_field(r, "dst_ip", "dest_ip", "destination.ip", "remote_ip", "RemoteIP", "DestinationIp")
    if logon:
        # Inbound logon: RemoteIP is the client, so it is the source (INGEST-22).
        # dst_ip falls back to RemoteIP when there is no LocalIP (INGEST-2 asserts it).
        src_ip = _ip_field(r, "RemoteIP") or _ip_field(r, "src_ip", "source_ip", "source.ip")
        dst_ip = _ip_field(r, "LocalIP") or dst_ip
    default_msg = (f"{src_ip or '?'} -> {dst_ip or '?'}:{_get(r, 'RemotePort', default='?')}"
                   if net else action)
    if logon:
        verb = {"logonfailed": "failed", "logonsuccess": "succeeded"}.get(str(action).lower(), "attempted")
        default_msg = f"logon {verb} for {_get(r, 'AccountName', default='?')} from {src_ip or '?'}"
    src_ip = src_ip or (_ip_field(r, "IpAddress") if winauth else None)
    url = str(_get(r, "RemoteUrl", default=""))  # full URL stays in message; domain gets the host only
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "eventTime", "TimeGenerated", "TimeGenerated [UTC]",
                "TimeCreated", "UtcTime", "Date and Time", default=None),
        source="edr",
        category="alert" if alert else ("authentication" if logon or winauth else "network" if net else "process"),
        action=str(action),
        message=str(_get(r, "AlertName", "message", "description", "threat_name", "name",
                         "ProcessCommandLine", "InitiatingProcessCommandLine", "CommandLine", "TargetFilename", "QueryName",
                         default=default_msg)) + (f" url={url}" if url else ""),
        severity=_severity(_get(r, "severity", "risk", "level", "AlertSeverity")),
        host=_entity(r, "host.name", "host", "hostname", "device", "endpoint", "computer_name", "DeviceName",
                     "Computer", "MachineName", "CompromisedEntity"),
        user=_entity(r, "user.name", "user", "username", "account", "user_name", "AccountName", "TargetUserName",
                     "InitiatingProcessAccountName"),
        process=proc,
        file_path=_get(r, "file_path", "path", "target_file", "TargetFilename"),
        file_hash=_get(r, "sha256", "hash", "file_hash", "sha1", "md5", default=_sysmon_sha256(r)),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_get(r, "LocalPort", "SourcePort") if net else None,
        dst_port=_get(r, "RemotePort", "DestinationPort") if net else None,
        domain=(_url_host(url) if url else None) or _get(r, "QueryName", "DestinationHostname"),
        raw=r,
    )


def parse_dns(r: dict) -> Optional[Event]:
    domain = _get(r, "query", "domain", "question", "name", "qname", "query_name", "QueryName",
                  "rrname", "dns.question.name")
    if not domain:
        return None
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "TimeGenerated", "TimeGenerated [UTC]", default=None),
        source="dns",
        category="dns",
        action="dns_query",
        message=f"DNS query {domain} -> {_get(r, 'answer', 'response', 'resolved_ip', default='?')}",
        severity=_severity(_get(r, "severity")),
        host=_entity(r, "host.name", "host", "source_host"),
        src_ip=_ip_field(r, "src_ip", "client_ip", "source_ip", "client", "srcip", "src", "id.orig_h"),
        dst_ip=_ip_field(r, "resolved_ip", "answer_ip", "answer", "response"),
        domain=str(domain).rstrip("."),
        raw=r,
    )


def parse_network(r: dict) -> Optional[Event]:
    """Firewall / router / switch / netflow style connection records, and
    Defender DeviceNetworkEvents (routed here by its filename)."""
    src_ip = _ip_field(r, "src_ip", "source_ip", "source", "source_address", "source address", "src_addr", "src", "LocalIP",
                       "id.orig_h", "data.srcip", "output_fields.fd.cip")
    dst_ip = _ip_field(r, "dst_ip", "dest_ip", "destination", "destination_address", "destination address", "dst_addr", "dst",
                       "destination_ip", "RemoteIP", "id.resp_h", "output_fields.fd.sip")
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "TimeGenerated", "TimeGenerated [UTC]",
                "receive time", "generate time", "receive_time", default=None),
        source=_log_source(r, "firewall"),
        category="network",
        action=str(_get(r, "action", "verdict", "disposition", "ActionType", default="connection")),
        message=str(_get(
            r, "message", "alert.signature", "rule.description", "output",
            default=f"{src_ip or '?'} -> {dst_ip or '?'}:"
                    f"{_get(r, 'dst_port', 'dest_port', 'dport', 'id.resp_p', 'destination port', 'port', 'RemotePort', default='?')}")),
        severity=_severity(_get(r, "severity", "level", "priority")),
        host=_entity(r, "host.name", "host", "device", "hostname", "DeviceName", "device name", "agent.name"),
        user=_entity(r, "user.name", "user", "AccountName", "InitiatingProcessAccountName", "data.srcuser"),
        process=_get(r, "InitiatingProcessFileName"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_get(r, "src_port", "source_port", "sport", "source port", "LocalPort", "id.orig_p"),
        dst_port=_get(r, "dst_port", "dest_port", "destination_port", "dport", "destination port", "port", "RemotePort", "id.resp_p"),
        domain=_get(r, "RemoteUrl"),
        raw=r,
    )


def _value(v):
    """Azure wraps some fields as {"value": .., "localizedValue": ..}."""
    return v.get("value") or v.get("localizedValue") if isinstance(v, dict) else v


def parse_cloud(r: dict) -> Optional[Event]:
    """Cloud audit logs (AWS CloudTrail / Azure Activity / Entra audit / GCP),
    normalized loosely."""
    action = _value(_get(r, "eventName", "operationName", "activityDisplayName",
                         "methodName", "protoPayload.methodName", "verb", "action", default="cloud_api"))
    # CloudTrail failures: errorCode, or (ConsoleLogin) only errorMessage /
    # responseElements.ConsoleLogin == "Failure". Azure: status.value / result.
    resp = r.get("responseElements") if isinstance(r.get("responseElements"), dict) else {}
    status = str(_value(_get(r, "status", "result", "resultType")) or "").lower()
    failed = bool(_get(r, "errorCode", "errorMessage")) or \
        str(resp.get("ConsoleLogin", "")).lower() == "failure" or \
        any(w in status for w in ("fail", "denied"))
    category = "cloud_api"
    tags = []
    service = _get(r, "eventSource")   # CloudTrail: one trail = one source, the service is a tag
    if failed and str(action) == "ConsoleLogin":
        action, category = "login_failed", "authentication"
        tags.append("aws:console-login-failed")
    elif str(action) == "ConsoleLogin" and str(resp.get("ConsoleLogin", "")).lower() == "success":
        action, category = "login_success", "authentication"
    if service:
        tags.append(f"service:{service}")
    ev = Event(
        ts=_get(r, "eventTime", "timestamp", "time", "@timestamp", "activityDateTime", "eventTimestamp", "stageTimestamp", "TimeGenerated", "TimeGenerated [UTC]",
                default=None),
        source="cloudtrail" if service else str(_get(r, "provider", default="cloud")),
        category=category,
        action=str(action),
        message=str(_get(r, "message", "errorMessage", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if failed else "info"))),
        user=_cloud_user(r),
        # Service principals ("ec2.amazonaws.com") sit in sourceIPAddress too.
        src_ip=_ip_field(r, "sourceIPAddress", "callerIp", "callerIpAddress", "src_ip",
                      "sourceIPs", "protoPayload.requestMetadata.callerIp"),
        raw=r,
    )
    ev.tags.extend(tags)
    return ev


def _cloud_user(r: dict):
    """CloudTrail userIdentity.userName, else a flat user field, else the
    role/session name from the ARN (AssumedRole identities have no userName)."""
    ident = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
    user = ("root" if ident.get("type") == "Root" else
            ident.get("userName") or _get(r, "userName", "principal", "caller", "user.username",
                                      "protoPayload.authenticationInfo.principalEmail"))
    if not user and ident.get("arn"):
        user = str(ident["arn"]).rsplit("/", 1)[-1]
    by = r.get("initiatedBy") if isinstance(r.get("initiatedBy"), dict) else {}
    if not user and by:   # Entra audit log: initiatedBy.user / initiatedBy.app
        who = by.get("user") or by.get("app") or {}
        if isinstance(who, dict):
            user = who.get("userPrincipalName") or who.get("displayName")
    return user


def _auth_verdict(r: dict) -> Optional[bool]:
    """True = failed login, False = successful login, None = no verdict field."""
    for k in ("status", "result", "outcome", "success", "response"):
        v = _get(r, k)
        if v is None:
            continue
        if isinstance(v, bool):
            return not v
        s = str(v).strip().lower()
        if s in ("false", "0", "no") or any(w in s for w in ("fail", "denied", "deny", "reject", "invalid", "block", "error")):
            return True
        if s in ("true", "1", "yes", "ok") or "succe" in s or "accept" in s:
            return False
    return None


# Wording that makes an auth row a logon attempt; anything else is a generic event.
_LOGON_RE = re.compile(r"\b(?:log[-_ ]?(?:on|in)|sign[-_ ]?in|auth|password|credential)", re.I)


def parse_auth(r: dict) -> Optional[Event]:
    """Generic authentication events (server auth, IdP, VPN)."""
    action = str(_get(r, "action", "event", "eventType", default="auth"))
    verdict = _auth_verdict(r)
    failed = ("fail" in action.lower()) if verdict is None else verdict
    if verdict is not None:
        action = "login_failed" if failed else "login_success"
    elif not _LOGON_RE.search(action):
        action = "auth_event"  # "service failed" is not a sign-in; _FAIL_RE must not see it
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "published", "TimeGenerated", "TimeGenerated [UTC]", default=None),
        source=_log_source(r, "auth"),
        category="authentication",
        action=str(action),
        message=str(_get(r, "message", "displayMessage", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if failed else "info"))),
        host=_entity(r, "host.name", "host", "hostname", "server"),
        user=_entity(r, "user.name", "user", "username", "account", "actor.alternateId"),
        src_ip=_ip_field(r, "src_ip", "source_ip", "source", "client_ip", "client.ipAddress"),
        raw=r,
    )


# ---- syslog (line) parser --------------------------------------------------

# RFC 5424: "<PRI>VER TIMESTAMP HOST APP PROCID MSGID [SD...]|- MSG" ("-" = nil).
_RFC5424_RE = re.compile(
    r"^<\d{1,3}>\d{1,2}\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?:\s+(?P<msg>.*))?$"
)
# Syslog stamp: BSD "Oct  3 22:00:00[.123]" (year may sit before the time), journalctl
# short-full "Sat 2026-10-03 22:00:02 UTC", or ISO "2026-10-03T22:00:00.123+00:00".
_TS = (r"(?:\w{3}\s+\d+(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
       r"|\w{3}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+[A-Z]{2,5}"
       r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_SYSLOG_RE = re.compile(
    rf"^(?:<\d+>\d?\s*)?(?P<ts>{_TS})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.()]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
# Cisco IOS: "*Oct  3 22:00:07.123: %SEC_LOGIN-4-LOGIN_FAILED: ..." has no host field.
_CISCO_RE = re.compile(rf"^\*?(?P<ts>{_TS})\s*:\s*%(?P<proc>[A-Z_]+)-\d-\w+:\s*(?P<host>)(?P<msg>.*)$")
_BRACKET_USER_RE = re.compile(r"\[user:\s*(?P<u>[^\]\s]+)\]")   # Cisco "[user: admin]"
# sshd: "Accepted password|publickey|keyboard-interactive/pam|... for USER from IP"; dropbear: "Password auth succeeded"
_SSH_ACCEPTED_RE = re.compile(r"\baccepted\s+\S+\s+for\s+|\bauth succeeded\b", re.I)
# Whole-word "fail" only: "failover", "testfail" in a username are not failures.
_FAIL_WORD_RE = re.compile(r"\bfail(?:ed|ing|s|ure)?\b")
# sudo: "jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=..."
_SUDO_RE = re.compile(r"^\s*(?P<u>[\w.\-\\@]+)\s+:\s+.*\bCOMMAND=", re.I)
# su: "FAILED SU (to root) bob on pts/0"; vsftpd: "[bob] FAIL LOGIN: Client ..." (the account is the actor)
_SU_RE = re.compile(r"^FAILED SU \(to \S+\)\s+(?P<u>[\w.\-\\@]+)", re.I)
_VSFTPD_RE = re.compile(r"^\[(?P<u>[\w.\-\\@]+)\]\s+FAIL LOGIN", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_RHOST_RE = re.compile(r"\brhost=(?P<h>\S+)")
# pam: "authentication failure; logname= uid=0 ... rhost=1.2.3.4  user=root"
_USER_EQ_RE = re.compile(r"(?<![\w])user=(?P<u>[\w.\-\\@]+)", re.I)   # sudo prints USER=root
# rsyslog/journald dedup: "message repeated 5 times: [ Failed password ...]"
_REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$", re.I)
_REPEAT_CAP = 1000
# Processes whose failures are authentication failures.
_AUTH_PROCS = ("sshd", "sshd-session", "login", "su", "sudo", "pam", "gdm-password",
               "polkitd", "vsftpd", "dovecot", "systemd-logind", "passwd", "chage", "sec_login", "dropbear")
# Failure wording that does not itself contain "fail" (sshd probes, PAM, sudo, dropbear).
_AUTH_FAIL_PHRASES = ("invalid user", "illegal user", "authentication failure",
                      "maximum authentication attempts", "incorrect password", "not allowed",
                      "bad password attempt", "nonexistent user")
# "for"/"user"/"account" followed by the account name. Filler words that can sit
# in between ("session closed for user X", "for invalid user X") are skipped so
# they are never taken as the account itself. "for 'root'" (dropbear) may be quoted.
_USER_RE = re.compile(
    r"\b(?:user|for|account)\s+'?"
    r"(?!(?:user|for|account|invalid|illegal|from|nonexistent|directory|file)\b)(?P<u>[\w.\-\\@]+)", re.I)


def _syslog_ip(msg: str) -> Optional[str]:
    """pam rhost= first, then the first IPv4, then the first valid IPv6."""
    rm = _RHOST_RE.search(msg)
    if rm and _clean_ip(rm.group("h")):
        return _clean_ip(rm.group("h"))
    for cand in _IP_RE.findall(msg) + _IP6_RE.findall(msg):
        if _clean_ip(cand):   # 999.999.999.999 is not an address
            return _clean_ip(cand)
    return None


_FRAME_RE = re.compile(rf"^(?:<\d+>\d?\s*)?(?P<ts>{_TS})\s+(?P<host>\S+)\s+")
_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
# ASA 106023 "src outside:IP/port dst inside:IP/port", 302013 "for outside:IP/port (..) to inside:IP/port"
_ASA_RE = re.compile(r"%ASA-\d-\d+:\s*(?P<m>.*?(?P<act>Deny|Built|Teardown)\b.*?(?:src|for)\s+\S+?:(?P<s>[\w.:]+)/(?P<sp>[\w-]+)"
                     r".*?(?:dst|to)\s+\S+?:(?P<d>[\w.:]+)/(?P<dp>[\w-]+).*)", re.I)
_ASA_ID_RE = re.compile(r"%ASA-\d-(\d{6}):")
# shortcut: _ASA_RE is still quadratic up to this cap, upgrade by anchoring its .*? chain if real ASA messages run longer
_ASA_MAX = 512
# Connection ids -> action (None: "denied"/"permitted" in the text). Endpoints are "from|src X[/p] to|dst Y[/p]",
# except 106100's "outside/X(p) -> inside/Y(p)".
_ASA_CONN = {"106001": "deny", "106006": "deny", "106007": "deny", "106014": "deny", "106015": "deny",
             "106021": "deny", "106100": None, "710003": "deny", "305011": "allow", "305012": "connection"}
_ASA_EP_RE = re.compile(r"\b(?:from|src)\s+(?P<s>\S+?)(?:/(?P<sp>[\w-]+))?\s+(?:to|dst)\s+"
                        r"(?P<d>\S+?)(?:/(?P<dp>[\w-]+))?(?=[\s(]|$)")
_ASA_106100_RE = re.compile(r"\S+?/(?P<s>[\w.:]+)\(\d+\)\s+->\s+\S+?/(?P<d>[\w.:]+)\((?P<dp>\d+)\)")
# AAA / login ids -> authentication events, so attack.py's failure (T1110) rule applies.
_ASA_AUTH = {"113004": "login_success", "113005": "login_failed", "113015": "login_failed",
             "605004": "login_failed", "605005": "login_success", "611101": "login_success", "611102": "login_failed"}
_ASA_USER_RE = re.compile(r'(?:\buser\s*=\s*|\bfor user "|\bUname:\s*)(?P<u>[^\s:,"]+)')
_ASA_CIP_RE = re.compile(r"(?:user IP\s*=\s*|IP address:\s*|\bfrom\s+)(?P<ip>[\w.:]+)")


def _asa_ip(tok: str) -> Optional[str]:
    """ASA endpoint token 'iface:ip' or 'ip' -> ip. Try the whole token first so 'fe80::5' is not cut at 'fe80:'."""
    return _clean_ip(tok) or _clean_ip(tok.split(":", 1)[-1])


def _syslog_ts(ts: Optional[str]) -> Optional[str]:
    """Stamp -> the form models.py reads: drop weekday, zone and fraction; year-in-stamp to ISO."""
    if not ts:
        return None
    ts = re.sub(r"^\w{3}\s+(?=\d{4}-)|\s+[A-Z]{2,5}$|(?<=:\d{2})\.\d+", "", ts)
    try:
        return datetime.strptime(ts, "%b %d %Y %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _vendor_firewall(line: str) -> Optional[Event]:
    """Syslog-framed or bare FortiGate key=value / Cisco ASA line -> firewall event (None if neither)."""
    f = _FRAME_RE.match(line)
    body = line[f.end():] if f else line
    r = {"ts": _syslog_ts(f.group("ts")), "host": f.group("host")} if f else {}
    kv = {k.lower(): v.strip('"') for k, v in _KV_RE.findall(body)}
    a = _ASA_RE.search(body[:_ASA_MAX])
    aid = _ASA_ID_RE.search(body)
    aid = aid.group(1) if aid else None
    if "srcip" in kv or "dstip" in kv:
        r.update(src_ip=kv.get("srcip"), dst_ip=kv.get("dstip"), src_port=kv.get("srcport"), dst_port=kv.get("dstport"),
                 action=kv.get("action") or "connection", host=kv.get("devname") or r.get("host"))
        if kv.get("date") and kv.get("time"):
            r["ts"] = f"{kv['date']} {kv['time']}"
    elif a:
        r.update(src_ip=a.group("s"), dst_ip=a.group("d"), src_port=a.group("sp"), dst_port=a.group("dp"),
                 action={"deny": "deny", "built": "allow"}.get(a.group("act").lower(), "connection"))
    elif aid in _ASA_CONN:
        ep = _ASA_EP_RE.search(body) or _ASA_106100_RE.search(body)
        if not ep:
            return None
        r.update(src_ip=_asa_ip(ep.group("s")), dst_ip=_asa_ip(ep.group("d")),
                 src_port=ep.groupdict().get("sp"), dst_port=ep.group("dp"),
                 action=_ASA_CONN[aid] or ("deny" if "denied" in body else "allow"))
    elif aid in _ASA_AUTH:
        um, im = _ASA_USER_RE.search(body), _ASA_CIP_RE.search(body)
        r.update(user=um.group("u") if um else None, src_ip=im.group("ip") if im else None, action=_ASA_AUTH[aid])
    else:
        return None
    ev = parse_network({**r, "message": body[:500]})
    ev.raw = {"line": line}
    if aid in _ASA_AUTH:
        ev.category = "authentication"
    return ev


def parse_syslog_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    m = _RFC5424_RE.match(line) or _SYSLOG_RE.match(line) or _CISCO_RE.match(line)
    if not m:
        # Not RFC3164-ish: vendor firewall formats, else an 'other' event (keeping any syslog ts+host).
        ev = _vendor_firewall(line)
        if ev:
            return ev
        f = _FRAME_RE.match(line)
        return Event(ts=_syslog_ts(f.group("ts")) if f else None, source="syslog", category="other",
                     action="log", message=line[:500], host=f.group("host") if f else None,
                     src_ip=_syslog_ip(line[f.end():]) if f else None, raw={"line": line})
    nil = lambda g: None if m.group(g) in (None, "", "-") else m.group(g)   # noqa: E731
    msg = (m.group("msg") or "").lstrip("\ufeff")   # RFC 5424 MSG may carry a BOM
    repeat = 0
    rp = _REPEAT_RE.match(msg)
    if rp:
        repeat, msg = min(int(rp.group("n")), _REPEAT_CAP), rp.group("msg")
    proc = nil("proc")
    low = msg.lower()
    sm = (_SUDO_RE.match(msg) if "sudo" in (proc or "").lower() else None) or _SU_RE.match(msg) or _VSFTPD_RE.match(msg)
    um = sm or _USER_RE.search(msg) or _USER_EQ_RE.search(msg)
    # A failure is only a failed *login* with auth context: an auth process, or
    # password / authentication-failure wording naming a user ("systemd: Failed
    # to start ... User Login Management" is not one).
    auth_proc = (proc or "").lower().rsplit("/", 1)[-1] in _AUTH_PROCS
    auth_ctx = auth_proc or "pam_" in low or \
        (("password" in low or "authentication failure" in low) and um is not None)
    accepted = _SSH_ACCEPTED_RE.search(msg)   # "Accepted ..." is a success whatever the user is named
    failed = not accepted and (bool(_FAIL_WORD_RE.search(low))
                               or any(p in low for p in _AUTH_FAIL_PHRASES))
    # In an auth process the failure wording alone is enough (sshd "Failed publickey",
    # "Invalid user"); elsewhere the message must also name password/auth/login.
    if failed and auth_ctx and (auth_proc or "password" in low or "authentication" in low
                                or "login" in low):
        action, category, sev = "login_failed", "authentication", 3
    elif accepted:
        action, category, sev = "login_success", "authentication", 1
    elif "sudo" in (proc or "").lower():
        action, category, sev = "sudo", "process", 2
    else:
        action, category, sev = "log", "other", 1
    if action != "sudo":
        # "for/user/account X" names an account only in auth context; elsewhere
        # ("Waiting for network", "for 10.0.0.5") it is not a user.
        auth_user = action in ("login_failed", "login_success") or auth_proc or "pam_" in low
        um = sm or (_USER_RE.search(msg) if auth_user else None) or _USER_EQ_RE.search(msg) or _BRACKET_USER_RE.search(msg)
    raw = {"line": line}
    if repeat:
        raw["repeated"] = repeat   # the loader expands this into N events
    return Event(
        ts=_syslog_ts(nil("ts")),
        source="syslog",
        category=category,
        action=action,
        message=msg[:500],
        severity=sev,
        host=nil("host"),
        process=proc,
        user=um.group("u") if um else None,
        src_ip=_syslog_ip(msg),
        raw=raw,
    )


# ---- Azure AD / Entra ID sign-in logs --------------------------------------

# Failure-reason values Graph/portal exports put on successful sign-ins.
_AZURE_BENIGN_REASONS = ("other", "none", "n/a", "na", "null", "-")


# MFA / KMSI / silent-sign-in interrupts: the password was not rejected.
_AZURE_MFA_INTERRUPT_CODES = ("50058", "50072", "50074", "50076", "50140")


def _azure_is_interrupt(status, errcode) -> bool:
    code = str(errcode if errcode is not None else "").strip()
    if code in _AZURE_MFA_INTERRUPT_CODES:
        return True
    return "interrupt" in str(status or "").lower() and code in ("", "0", "0.0")


def _azure_is_failure(status, errcode, reason) -> bool:
    s = str(status or "").lower()
    if any(w in s for w in ("fail", "denied", "block")):
        return True
    code = str(errcode if errcode is not None else "").strip()
    if code and code not in ("0", "0.0"):
        return True
    r = str(reason or "").strip().lower().rstrip(".")
    if r and "success" not in r and r not in _AZURE_BENIGN_REASONS and not code:
        # A populated failure-reason field (with no explicit success code 0)
        # implies a non-success sign-in.
        return True
    return False


def parse_azure_signin(r: dict) -> Optional[Event]:
    """Azure AD / Entra ID sign-in export (Interactive / NonInteractive / MSI /
    Application sign-ins CSV or JSON)."""
    user = _get(r, "User", "Username", "User principal name", "userPrincipalName",
                "userDisplayName", "Identity")
    ip_raw = _get(r, "IP address", "IP Address", "ipAddress", "IP address (seen by resource)")
    ip = _clean_ip(ip_raw)
    status =_get(r, "Status", "Sign-in status", "status", "conditionalAccessStatus")
    errcode = _get(r, "Sign-in error code", "Sign in error code", "errorCode", "Error code",
                    "ResultType")
    reason = _get(r, "Failure reason", "failureReason", "Status reason", "ResultDescription")
    if isinstance(status, dict):
        # Graph / portal JSON: status = {"errorCode": 0, "failureReason": ..,
        # "additionalDetails": ..}. Never substring-match the dict's repr.
        if errcode is None:
            errcode = status.get("errorCode")
        reason = reason or status.get("failureReason")
        details = status.get("additionalDetails")   # context only, not a verdict
        status = None
    else:
        details = None
    location = _get(r, "Location", "location")
    app = _get(r, "Application", "App", "appDisplayName", "Resource")
    risk_level = _get(r, "Risk level during sign-in", "Risk level aggregated",
                      "riskLevelDuringSignIn", "Risk level")
    risk_state = _get(r, "Risk state", "riskState", "Risk detail")
    mfa = _get(r, "Multifactor authentication result", "authenticationRequirement",
               "MFA result")

    if user is None and ip_raw is None and status is None:
        return None  # not an azure sign-in row

    transfer = _get(r, "Original transfer method", "originalTransferMethod")
    device_id = _get(r, "Device ID", "deviceId", "Device Id")
    join_type = _get(r, "Join Type", "joinType")
    client_app = _get(r, "Client app", "clientApp", "clientAppUsed")
    token_type = _get(r, "Incoming token type", "incomingTokenType")

    interrupt = _azure_is_interrupt(status, errcode)
    failed = not interrupt and _azure_is_failure(status, errcode, reason)
    action = "mfa_interrupt" if interrupt else ("login_failed" if failed else "login_success")
    sev = 3 if failed else 1
    risky = str(risk_level or "").lower() in ("high", "medium") or \
        str(risk_state or "").lower() in ("atrisk", "at risk", "confirmedcompromised")
    if risky:
        sev = 4

    is_devicecode = "devicecode" in str(transfer or "").lower().replace(" ", "")

    ts = _get(r, "Date (UTC)", "Date", "date", "createdDateTime", "Timestamp", "TimeGenerated", "TimeGenerated [UTC]")
    local_only = ts is None and _get(r, "Date (local)") is not None  # naive local time: offset unknown, not guessed
    if local_only:
        ts = _get(r, "Date (local)")
    ev = Event(
        ts=ts,
        source="azure_ad",
        category="authentication",
        action=action,
        message=(f"Azure AD sign-in {status or ('failure' if failed else 'success')} "
                 f"for {user or '?'} from {ip or '?'} "
                 f"({location or '?'}) app={app or '?'}"
                 + (f" transfer={transfer}" if transfer else "")
                 + (f" device={device_id}" if device_id else "")
                 + (f" join={join_type}" if join_type else "")
                 + (f" client={client_app}" if client_app else "")
                 + (f" token={token_type}" if token_type else "")
                 + (f" reason={reason}" if reason else "")
                 + (f" detail={details}" if details else "")
                 + (f" risk={risk_level or risk_state}" if risky else "")
                 + (f" mfa={mfa}" if mfa else "")),
        severity=sev,
        user=str(user) if user else None,
        src_ip=str(ip) if ip else None,
        process=str(app) if app else None,
        raw=r,
    )
    if local_only:
        ev.tags.append("ts-local")
    if risky:
        # Risky/valid-account abuse -> Valid Accounts.
        ev.attack.append("T1078")
        ev.tags.append("azure:risky-signin")
    if interrupt:
        ev.tags.append("azure:mfa-interrupt")
    if is_devicecode and action == "login_success":
        # Successful device-code-flow sign-in — a known AiTM/phishing access vector.
        ev.attack.append("T1078")
        ev.tags.append("azure:devicecode-success")
        ev.severity = max(ev.severity, 3)
    return ev


# ---- Microsoft 365 Unified Audit Log (UAL) ---------------------------------
# Operation -> (action, category, severity, [attack ids]). These are the events
# that actually reveal an M365 account compromise.
_UAL_OPS = {
    # Device registration / persistence
    "add device": ("device_registered", "process", 3, ["T1098.005"]),
    "add registered owner to device": ("device_owner_added", "process", 3, ["T1098.005"]),
    "add registered users to device": ("device_users_added", "process", 3, ["T1098.005"]),
    "register device": ("device_registered", "process", 3, ["T1098.005"]),
    # Mailbox access / collection
    "mailitemsaccessed": ("mailbox_access", "other", 3, ["T1114"]),
    "mailboxlogin": ("mailbox_login", "authentication", 2, []),
    # Inbox rules / defense evasion
    "new-inboxrule": ("inbox_rule_created", "other", 4, ["T1564.008"]),
    "set-inboxrule": ("inbox_rule_modified", "other", 4, ["T1564.008"]),
    "updateinboxrules": ("inbox_rule_modified", "other", 4, ["T1564.008"]),
    "enable-inboxrule": ("inbox_rule_enabled", "other", 3, ["T1564.008"]),
    # Sending mail / potential phishing from mailbox
    "send": ("mail_sent", "other", 3, ["T1566"]),
    "sendas": ("mail_sent_as", "other", 4, ["T1566", "T1534"]),
    "sendonbehalf": ("mail_sent_onbehalf", "other", 3, ["T1566"]),
    # Auth
    "userloggedin": ("login_success", "authentication", 1, []),
    "userloginfailed": ("login_failed", "authentication", 2, ["T1110"]),
    # Consent / persistence
    "consent to application": ("app_consent", "other", 3, ["T1098.003"]),
    "add service principal": ("service_principal_added", "other", 3, ["T1098.003"]),
    "add app role assignment grant to user": ("app_role_grant", "other", 3, ["T1098.003"]),
    "add member to role": ("role_member_added", "other", 3, ["T1098"]),
    "reset user password": ("password_reset", "authentication", 2, []),
    "change user password": ("password_change", "authentication", 2, []),
}


def parse_ual(r: dict) -> Optional[Event]:
    """Microsoft 365 / Entra Unified Audit Log row (RecordType/Operation/AuditData),
    classic Purview CSV (CreationDate/UserIds/Operations/AuditData), or flat
    Management Activity API JSON (the record itself is the audit data)."""
    # AuditData is a JSON blob with the useful detail.
    audit = _get(r, "AuditData", "auditdata")
    ad = {}
    if isinstance(audit, str) and audit.strip().startswith("{"):
        try:
            ad = json.loads(audit)
        except (ValueError, TypeError):
            ad = {}
    elif isinstance(audit, dict):
        ad = audit
    elif audit is None:
        ad = r   # flat record: CreationTime / ClientIP / Workload at top level
    if not isinstance(ad, dict):
        ad = {}

    def a(*keys, default=None):
        for k in keys:
            if k in ad and ad[k] not in (None, "", []):
                return ad[k]
        return default

    op = _get(r, "Operation", "Operations") or a("Operation")
    if not op:
        return None
    # Entra operations end with a period ("Consent to application.").
    op_l = str(op).strip().rstrip(".").lower()
    action, category, sev, attack = _UAL_OPS.get(
        op_l, (str(op), "other", 1, []))

    ip = _clean_ip(a("ClientIP", "ClientIPAddress", "ActorIpAddress", "IPAddress"))
    user = _get(r, "UserId", "UserIds") or a("UserId", "UserKey")
    workload = a("Workload")
    result = a("ResultStatus")

    # Extra context for high-signal ops.
    extra = ""
    dev = a("DeviceName", "DeviceId")
    if dev:
        extra += f" device={dev}"
    params = a("Parameters")
    if params and "rule" in op_l:
        try:
            names = [p.get("Value") for p in params if isinstance(p, dict)]
            extra += " rule_params=" + ",".join(str(n)[:40] for n in names if n)[:120]
        except Exception:
            pass
    if op_l == "mailitemsaccessed":
        folders = a("Folders")
        cnt = a("OperationCount")
        if cnt:
            extra += f" items={cnt}"
        if isinstance(folders, list):
            extra += f" folders={len(folders)}"

    ev = Event(
        ts=_get(r, "CreationDate", "creationdate") or a("CreationTime"),
        source="m365_ual",
        category=category,
        action=action,
        message=(f"UAL {op} by {user or '?'} from {ip or '?'} "
                 f"[{workload or '?'}] {result or ''}{extra}").strip(),
        severity=sev,
        user=str(user) if user else None,
        src_ip=str(ip) if ip else None,
        raw=r,
    )
    for tid in attack:
        if tid not in ev.attack:
            ev.attack.append(tid)
    ev.tags.append(f"ual:{op_l}")
    return ev


# ---- Microsoft 365 message trace --------------------------------------------

def parse_o365_message(r: dict) -> Optional[Event]:
    """O365 message-trace / MTSummary export row (email flow)."""
    sender = _get(r, "sender_address", "Sender Address", "SenderAddress", "Sender", "From")
    recipient = _get(r, "recipient_address", "Recipient Address", "RecipientAddress",
                     "Recipient", "To")
    subject = _get(r, "subject", "Subject", "Message Subject", "message_subject")
    status = _get(r, "status", "Status", "Delivery Status")
    rstat = _get(r, "Recipient_status", "Recipient status")
    pairs = []
    if rstat:
        # MTSummary: "a@x.com##Receive, Deliver;b@x.com##Receive, Fail"
        pairs = [p.split("##", 1) for p in str(rstat).split(";") if p.strip()]
        recipient = recipient or ";".join(p[0].strip() for p in pairs) or None
        if status is None and pairs and len(pairs[0]) > 1:
            # The last event of the first recipient is its final disposition.
            status = pairs[0][1].split(",")[-1].strip() or None
    if sender is None and recipient is None and subject is None:
        return None
    s = str(status or "").lower()
    # Severity looks at every recipient's final disposition, not only the first.
    all_dispositions = " ".join([s] + [p[1].split(",")[-1] for p in pairs if len(p) > 1]).lower()
    sev = 2 if any(w in all_dispositions for w in ("fail", "quarantine", "spam", "block", "defer")) else 1
    return Event(
        ts=_get(r, "origin_timestamp_utc", "Origin Timestamp", "Date (UTC)", "Date",
                "received", "Received", "TimeGenerated", "TimeGenerated [UTC]"),
        source="o365",
        category="other",
        action="email_" + (s.replace(" ", "_") or "event"),
        message=(f"O365 email {status or ''}: {sender or '?'} -> {recipient or '?'} "
                 f"subj='{str(subject or '')[:80]}'"),
        severity=sev,
        user=str(sender) if sender else None,
        src_ip=_ip_field(r, "original_client_ip", "Original Client IP", "FromIP",
                         "From IP", "client_ip"),
        raw=r,
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
    # Azure AD / Entra ID sign-ins
    "azure": parse_azure_signin,
    "aad": parse_azure_signin,
    "entra": parse_azure_signin,
    "signin": parse_azure_signin,
    "signins": parse_azure_signin,
    # Microsoft 365 message trace
    "o365": parse_o365_message,
    "m365": parse_o365_message,
    "messagetrace": parse_o365_message,
    "mtsummary": parse_o365_message,
    "messagetraceresult": parse_o365_message,
    # Microsoft 365 / Entra Unified Audit Log
    "ual": parse_ual,
    "unifiedaudit": parse_ual,
    "auditlog": parse_ual,
}

# --- ITEM-24: non-syslog plaintext formats (CEF, auditd, CLF, Squid, VPC flow, Zeek, UFW) ---
_CEF_RE = re.compile(r"CEF:\d\|(?:[^|\\]|\\.){0,100}\|(?:[^|\\]|\\.){0,100}\|(?:[^|\\]|\\.){0,50}\|(?:[^|\\]|\\.){0,50}\|(?P<name>(?:[^|\\]|\\.){0,200})\|(?:[^|\\]|\\.){0,20}\|(?P<ext>.*)$")
_CEF_UNESC = re.compile(r"\\([\\|=])")
_CEF_KEY_SPLIT = re.compile(r" (?=[A-Za-z0-9_]+=)")
_AUDIT_RE = re.compile(r"^(?:node=\S{1,64} )?type=(?P<t>[A-Z_]{1,40}) msg=audit\((?P<ts>\d{9,10}\.\d{3}):\d+\):(?P<kv>.{0,4000})$")
_CLF_RE = re.compile(r'^(?P<ip>[\da-fA-F.:]{3,45}) \S{1,64} (?P<u>\S{1,64}) \[(?P<ts>[^\]]{1,40})\] "(?P<req>[^"]{0,2048})" (?P<st>\d{3}) ')
_SQUID_RE = re.compile(r"^(?P<ts>\d{9,10}\.\d{3})\s+\d+\s+(?P<ip>\S{3,45})\s+(?P<code>[A-Z_]+)/(?P<st>\d{3})\s+\d+\s+(?P<m>[A-Z]{3,10})\s+(?P<url>\S{1,2048})\s+(?P<u>\S+)")
_UFW_RE = re.compile(r"\[UFW (?P<act>[A-Z ]{1,12})\]")
_ZEEK_HDR = ("#separator", "#fields", "#types", "#set_separator", "#empty_field", "#unset_field", "#path", "#open", "#close")


def _kv(s: str) -> dict:
    return {k: v.strip("'\"") for k, v in _KV_RE.findall(s)}


def _cef_kv(s: str) -> dict:
    # CEF values run to the next " key=" and may hold spaces; \= and \\ are escapes
    out = {}
    for seg in _CEF_KEY_SPLIT.split(s):
        k, eq, v = seg.partition("=")
        if eq:
            out[k] = _CEF_UNESC.sub(r"\1", v)
    return out


def _port(v) -> Optional[int]:
    return int(v) if v and str(v).isdigit() and int(v) < 65536 else None


def parse_text_line(line: str, state: dict) -> "Event | None | bool":
    """Try the structured plaintext formats; None -> caller falls back to
    parse_syslog_line, False -> header/comment line to skip. `state` is a
    per-file dict (holds the Zeek #fields header).
    shortcut: Windows XML (EVTX export) is not handled; upgrade when a real
    feed needs it."""
    line = line.rstrip("\r")
    if line.startswith("#"):
        if line.startswith("#fields\t"):
            state["zeek"] = line.split("\t")[1:]
        return False if line.startswith(_ZEEK_HDR) else None
    if "CEF:" in line and (m := _CEF_RE.search(line)):
        k = _cef_kv(m["ext"])
        name = _CEF_UNESC.sub(r"\1", m["name"])
        act = k.get("act") or name
        auth = bool(k.get("suser")) and re.search(r"log(?:in|on)|auth", name, re.I)
        return Event(ts=k.get("rt"), source="syslog", category="authentication" if auth else "network",
                     action=act, message=line[:500], user=k.get("suser"), src_ip=k.get("src"),
                     dst_ip=k.get("dst"), src_port=_port(k.get("spt")), dst_port=_port(k.get("dpt")))
    if (m := _AUDIT_RE.match(line)):
        k = _kv(m["kv"])
        auth = m["t"] in ("USER_LOGIN", "USER_AUTH")
        ok = k.get("res", "").lower() in ("success", "yes")
        user = k.get("acct") or k.get("auid")
        return Event(ts=m["ts"], source="syslog", category="authentication" if auth else "process",
                     action=("login_success" if ok else "login_failed") if auth else m["t"].lower(),
                     message=line[:500], severity=0 if ok or not auth else 1,
                     user=None if user in (None, "4294967295", "unset") else user,
                     src_ip=next((k[x] for x in ("addr", "hostname") if _IP_RE.fullmatch(k.get(x, ""))), None),
                     process=k.get("exe"))
    if (m := _SQUID_RE.match(line)):
        try:
            host = urlsplit(m["url"]).hostname
        except ValueError:
            host = None
        denied = "DENIED" in m["code"] or m["st"] in ("403", "407")
        return Event(ts=m["ts"], source="syslog", category="network", action="proxy_denied" if denied else "proxy_request",
                     message=line[:500], severity=1 if denied else 0, src_ip=m["ip"], domain=host, user=m["u"])
    if (m := _CLF_RE.match(line)):
        st = m["st"]
        auth = st in ("401", "403")
        return Event(ts=m["ts"], source="syslog", category="authentication" if auth else "network",
                     action="login_failed" if auth else "http_request", message=line[:500],
                     severity=1 if auth else 0, src_ip=m["ip"], user=m["u"])
    f = line.split()
    if len(f) == 14 and f[0] == "2" and f[12] in ("ACCEPT", "REJECT") and f[9].isdigit():
        return Event(ts=f[10], source="syslog", category="network", action=f[12].lower(), message=line[:500],
                     severity=1 if f[12] == "REJECT" else 0, src_ip=f[3], dst_ip=f[4],
                     src_port=_port(f[5]), dst_port=_port(f[6]))
    cols = state.get("zeek")
    if cols and "\t" in line:
        v = line.split("\t")
        if len(v) == len(cols) and "id.orig_h" in cols:
            r = dict(zip(cols, v))
            return Event(ts=r.get("ts"), source="syslog", category="network", action=r.get("conn_state") or "zeek",
                         message=line[:500], src_ip=r["id.orig_h"], dst_ip=r.get("id.resp_h"),
                         src_port=_port(r.get("id.orig_p")), dst_port=_port(r.get("id.resp_p")))
    if "[UFW " in line and (m := _UFW_RE.search(line)):
        k = _kv(line[m.end():])
        fr = _FRAME_RE.match(line)
        blocked = "BLOCK" in m["act"]
        return Event(ts=fr["ts"] if fr else None, source="syslog", category="network",
                     action="blocked" if blocked else "allowed", message=line[:500], severity=1 if blocked else 0,
                     host=fr["host"] if fr else None, src_ip=k.get("SRC"), dst_ip=k.get("DST"),
                     src_port=_port(k.get("SPT")), dst_port=_port(k.get("DPT")))
    return None
