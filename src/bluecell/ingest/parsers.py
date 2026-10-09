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
from typing import Optional

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
        if v not in (None, "", []):
            return v
    return default


def _clean_ip(val) -> Optional[str]:
    """IP text with control chars, port and brackets removed; None if it is not an IP.

    "1.2.3.4:443" -> "1.2.3.4", "[2001:db8::1]:443" -> "2001:db8::1"; bare IPv6
    ("2001:db8::1", "::ffff:1.2.3.4") is kept intact. Unspecified addresses
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
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    return None if ip.is_unspecified else s


def _ip_field(r: dict, *keys) -> Optional[str]:
    """First of keys whose value is a real IP; placeholders ('-', 'N/A') fall through."""
    for k in keys:
        ip = _clean_ip(_get(r, k))
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
)


def parse_edr(r: dict) -> Optional[Event]:
    """Endpoint / EDR alerts, process telemetry, and Defender Advanced Hunting Device* tables."""
    if _get(r, *_EDR_KEYS) is None:
        return None
    action = _get(r, "action", "event_type", "operation", "activity", "ActionType", default="edr_event")
    # CSV gives "false"/"0" as text, which is truthy; treat those as no alert.
    alert = any(str(v).strip().lower() not in ("false", "0", "no", "none", "")
                for v in (_get(r, "alert"), _get(r, "detection"), _get(r, "threat_name"))
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
    net = _get(r, "RemoteIP", "LocalIP") is not None and not logon
    src_ip = _ip_field(r, "src_ip", "source_ip", "local_ip", "LocalIP")
    dst_ip = _ip_field(r, "dst_ip", "dest_ip", "remote_ip", "RemoteIP")
    if logon:
        # Inbound logon: RemoteIP is the client, so it is the source (INGEST-22).
        # dst_ip falls back to RemoteIP when there is no LocalIP (INGEST-2 asserts it).
        src_ip = _ip_field(r, "RemoteIP") or _ip_field(r, "src_ip", "source_ip")
        dst_ip = _ip_field(r, "LocalIP") or dst_ip
    default_msg = (f"{src_ip or '?'} -> {dst_ip or '?'}:{_get(r, 'RemotePort', default='?')}"
                   if net else action)
    if logon:
        verb = {"logonfailed": "failed", "logonsuccess": "succeeded"}.get(str(action).lower(), "attempted")
        default_msg = f"logon {verb} for {_get(r, 'AccountName', default='?')} from {src_ip or '?'}"
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "eventTime", "TimeGenerated", "TimeGenerated [UTC]", default=None),
        source="edr",
        category="alert" if alert else ("authentication" if logon else "network" if net else "process"),
        action=str(action),
        message=str(_get(r, "message", "description", "threat_name", "name",
                         "ProcessCommandLine", "InitiatingProcessCommandLine", default=default_msg)),
        severity=_severity(_get(r, "severity", "risk", "level")),
        host=_get(r, "host", "hostname", "device", "endpoint", "computer_name", "DeviceName"),
        user=_get(r, "user", "username", "account", "user_name", "AccountName",
                  "InitiatingProcessAccountName"),
        process=proc,
        file_path=_get(r, "file_path", "path", "target_file"),
        file_hash=_get(r, "sha256", "hash", "file_hash", "sha1", "md5"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=_get(r, "RemoteUrl"),
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
        host=_get(r, "host", "client", "source_host"),
        src_ip=_ip_field(r, "src_ip", "client_ip", "source_ip"),
        dst_ip=_ip_field(r, "resolved_ip", "answer_ip"),
        domain=str(domain).rstrip("."),
        raw=r,
    )


def parse_network(r: dict) -> Optional[Event]:
    """Firewall / router / switch / netflow style connection records, and
    Defender DeviceNetworkEvents (routed here by its filename)."""
    src_ip = _ip_field(r, "src_ip", "source_ip", "source", "source_address", "src_addr", "src", "LocalIP")
    dst_ip = _ip_field(r, "dst_ip", "dest_ip", "destination", "destination_address", "dst_addr", "dst",
                       "destination_ip", "RemoteIP")
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "@timestamp", "TimeGenerated", "TimeGenerated [UTC]", default=None),
        source=_log_source(r, "firewall"),
        category="network",
        action=str(_get(r, "action", "verdict", "disposition", "ActionType", default="connection")),
        message=str(_get(
            r, "message",
            default=f"{src_ip or '?'} -> {dst_ip or '?'}:"
                    f"{_get(r, 'dst_port', 'port', 'RemotePort', default='?')}")),
        severity=_severity(_get(r, "severity", "level")),
        host=_get(r, "host", "device", "hostname", "DeviceName"),
        user=_get(r, "user", "AccountName", "InitiatingProcessAccountName"),
        process=_get(r, "InitiatingProcessFileName"),
        src_ip=src_ip,
        dst_ip=dst_ip,
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
                         "methodName", "action", default="cloud_api"))
    # CloudTrail failures: errorCode, or (ConsoleLogin) only errorMessage /
    # responseElements.ConsoleLogin == "Failure". Azure: status.value / result.
    resp = r.get("responseElements") if isinstance(r.get("responseElements"), dict) else {}
    status = str(_value(_get(r, "status", "result", "resultType")) or "").lower()
    failed = bool(_get(r, "errorCode", "errorMessage")) or \
        str(resp.get("ConsoleLogin", "")).lower() == "failure" or \
        any(w in status for w in ("fail", "denied"))
    category = "cloud_api"
    tags = []
    if failed and str(action) == "ConsoleLogin":
        action, category = "login_failed", "authentication"
        tags.append("aws:console-login-failed")
    ev = Event(
        ts=_get(r, "eventTime", "timestamp", "time", "@timestamp", "activityDateTime", "eventTimestamp", "TimeGenerated", "TimeGenerated [UTC]",
                default=None),
        source=str(_get(r, "eventSource", "provider", default="cloud")),
        category=category,
        action=str(action),
        message=str(_get(r, "message", "errorMessage", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if failed else "info"))),
        user=_cloud_user(r),
        # Service principals ("ec2.amazonaws.com") sit in sourceIPAddress too.
        src_ip=_ip_field(r, "sourceIPAddress", "callerIp", "callerIpAddress", "src_ip"),
        raw=r,
    )
    ev.tags.extend(tags)
    return ev


def _cloud_user(r: dict):
    """CloudTrail userIdentity.userName, else a flat user field, else the
    role/session name from the ARN (AssumedRole identities have no userName)."""
    ident = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
    user = ident.get("userName") or _get(r, "userName", "principal", "caller")
    if not user and ident.get("arn"):
        user = str(ident["arn"]).rsplit("/", 1)[-1]
    by = r.get("initiatedBy") if isinstance(r.get("initiatedBy"), dict) else {}
    if not user and by:   # Entra audit log: initiatedBy.user / initiatedBy.app
        who = by.get("user") or by.get("app") or {}
        if isinstance(who, dict):
            user = who.get("userPrincipalName") or who.get("displayName")
    return user


def parse_auth(r: dict) -> Optional[Event]:
    """Generic authentication events (server auth, IdP, VPN)."""
    action = _get(r, "action", "event", default="auth")
    return Event(
        ts=_get(r, "timestamp", "ts", "time", "TimeGenerated", "TimeGenerated [UTC]", default=None),
        source=_log_source(r, "auth"),
        category="authentication",
        action=str(action),
        message=str(_get(r, "message", default=action)),
        severity=_severity(_get(r, "severity", default=("high" if "fail" in str(action).lower() else "info"))),
        host=_get(r, "host", "hostname", "server"),
        user=_get(r, "user", "username", "account"),
        src_ip=_ip_field(r, "src_ip", "source_ip", "source", "client_ip"),
        raw=r,
    )


# ---- syslog (line) parser --------------------------------------------------

# RFC 5424: "<PRI>VER TIMESTAMP HOST APP PROCID MSGID [SD...]|- MSG" ("-" = nil).
_RFC5424_RE = re.compile(
    r"^<\d{1,3}>\d{1,2}\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?:\s+(?P<msg>.*))?$"
)
_SYSLOG_RE = re.compile(
    # BSD "Oct  3 22:00:00" or ISO timestamp "2026-10-03T22:00:00.123+00:00"
    r"^(?:<\d+>\d?\s*)?"
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
# sshd: "Accepted password|publickey|keyboard-interactive/pam|... for USER from IP"
_SSH_ACCEPTED_RE = re.compile(r"\baccepted\s+\S+\s+for\s+", re.I)
# sudo: "jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=..."
_SUDO_RE = re.compile(r"^\s*(?P<u>[\w.\-\\@]+)\s+:\s+.*\bCOMMAND=", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_RHOST_RE = re.compile(r"\brhost=(?P<h>\S+)")
# pam: "authentication failure; logname= uid=0 ... rhost=1.2.3.4  user=root"
_USER_EQ_RE = re.compile(r"(?<![\w])user=(?P<u>[\w.\-\\@]+)")
# rsyslog/journald dedup: "message repeated 5 times: [ Failed password ...]"
_REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$", re.I)
_REPEAT_CAP = 1000
# Processes whose failures are authentication failures.
_AUTH_PROCS = ("sshd", "sshd-session", "login", "su", "sudo", "pam", "gdm-password",
               "polkitd", "vsftpd", "dovecot", "systemd-logind", "passwd", "chage")
# Failure wording that does not itself contain "fail" (sshd probes, PAM, sudo).
_AUTH_FAIL_PHRASES = ("invalid user", "illegal user", "authentication failure",
                      "maximum authentication attempts", "incorrect password")
# "for"/"user"/"account" followed by the account name. Filler words that can sit
# in between ("session closed for user X", "for invalid user X") are skipped so
# they are never taken as the account itself.
_USER_RE = re.compile(
    r"\b(?:user|for|account)\s+"
    r"(?!(?:user|for|account|invalid|illegal|from)\b)(?P<u>[\w.\-\\@]+)", re.I)


def _syslog_ip(msg: str) -> Optional[str]:
    """pam rhost= first, then the first IPv4, then the first valid IPv6."""
    rm = _RHOST_RE.search(msg)
    if rm and _clean_ip(rm.group("h")):
        return _clean_ip(rm.group("h"))
    for cand in _IP_RE.findall(msg) + _IP6_RE.findall(msg):
        if _clean_ip(cand):   # 999.999.999.999 is not an address
            return _clean_ip(cand)
    return None


def parse_syslog_line(line: str) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    m = _RFC5424_RE.match(line) or _SYSLOG_RE.match(line)
    if not m:
        # Not RFC3164-ish; keep the line as an 'other' event so nothing is lost.
        return Event(ts=None, source="syslog", category="other",
                     action="log", message=line[:500], raw={"line": line})
    nil = lambda g: None if m.group(g) in (None, "-") else m.group(g)   # noqa: E731
    msg = (m.group("msg") or "").lstrip("\ufeff")   # RFC 5424 MSG may carry a BOM
    repeat = 0
    rp = _REPEAT_RE.match(msg)
    if rp:
        repeat, msg = min(int(rp.group("n")), _REPEAT_CAP), rp.group("msg")
    proc = nil("proc")
    low = msg.lower()
    sm = _SUDO_RE.match(msg) if "sudo" in (proc or "").lower() else None
    um = sm or _USER_RE.search(msg) or _USER_EQ_RE.search(msg)
    # A failure is only a failed *login* with auth context: an auth process, or
    # password / authentication-failure wording naming a user ("systemd: Failed
    # to start ... User Login Management" is not one).
    auth_proc = (proc or "").lower().rsplit("/", 1)[-1] in _AUTH_PROCS
    auth_ctx = auth_proc or "pam_" in low or \
        (("password" in low or "authentication failure" in low) and um is not None)
    failed = "fail" in low or any(p in low for p in _AUTH_FAIL_PHRASES)
    # In an auth process the failure wording alone is enough (sshd "Failed publickey",
    # "Invalid user"); elsewhere the message must also name password/auth/login.
    if failed and auth_ctx and (auth_proc or "password" in low or "authentication" in low
                                or "login" in low):
        action, category, sev = "login_failed", "authentication", 3
    elif _SSH_ACCEPTED_RE.search(msg):
        action, category, sev = "login_success", "authentication", 1
    elif "sudo" in (proc or "").lower():
        action, category, sev = "sudo", "process", 2
    else:
        action, category, sev = "log", "other", 1
    if action != "sudo":
        # "for/user/account X" names an account only in auth context; elsewhere
        # ("Waiting for network", "for 10.0.0.5") it is not a user.
        auth_user = action in ("login_failed", "login_success") or auth_proc or "pam_" in low
        um = (_USER_RE.search(msg) if auth_user else None) or _USER_EQ_RE.search(msg)
    raw = {"line": line}
    if repeat:
        raw["repeated"] = repeat   # the loader expands this into N events
    return Event(
        ts=nil("ts"),
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


def _azure_is_failure(status, errcode, reason) -> bool:
    s = str(status or "").lower()
    if any(w in s for w in ("fail", "interrupt", "denied", "block")):
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

    failed = _azure_is_failure(status, errcode, reason)
    action = "login_failed" if failed else "login_success"
    sev = 3 if failed else 1
    risky = str(risk_level or "").lower() in ("high", "medium") or \
        str(risk_state or "").lower() in ("atrisk", "at risk", "confirmedcompromised")
    if risky:
        sev = 4

    is_devicecode = "devicecode" in str(transfer or "").lower().replace(" ", "")

    ev = Event(
        ts=_get(r, "Date (UTC)", "Date", "date", "createdDateTime", "Timestamp", "TimeGenerated", "TimeGenerated [UTC]",
                "Date (local)"),
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
    if risky:
        # Risky/valid-account abuse -> Valid Accounts.
        ev.attack.append("T1078")
        ev.tags.append("azure:risky-signin")
    if is_devicecode and not failed:
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