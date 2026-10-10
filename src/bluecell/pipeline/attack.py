# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Rule-based MITRE ATT&CK technique tagging.

This is a deterministic first pass — a curated set of high-signal rules that map
event shapes to ATT&CK technique IDs. It is intentionally conservative and
explainable (each hit records which rule fired), and the LLM stage can enrich
on top of it. It is NOT a replacement for a full detection engine.
"""
from __future__ import annotations

import ipaddress
import re

# Minimal embedded technique catalog (id -> (name, tactic)).
ATTACK_TECHNIQUES = {
    "T1110": ("Brute Force", "credential-access"),
    "T1078": ("Valid Accounts", "defense-evasion/persistence"),
    "T1071": ("Application Layer Protocol (C2)", "command-and-control"),
    "T1071.004": ("DNS C2", "command-and-control"),
    "T1568": ("Dynamic Resolution (DGA)", "command-and-control"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1486": ("Data Encrypted for Impact (Ransomware)", "impact"),
    "T1053": ("Scheduled Task/Job", "persistence"),
    "T1543": ("Create or Modify System Process", "persistence"),
    "T1021": ("Remote Services (Lateral Movement)", "lateral-movement"),
    "T1136": ("Create Account", "persistence"),
    "T1098": ("Account Manipulation", "persistence"),
    "T1562": ("Impair Defenses", "defense-evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "defense-evasion"),
    "T1562.008": ("Disable or Modify Cloud Logs", "defense-evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    "T1490": ("Inhibit System Recovery", "impact"),
    # Identity / M365 cloud techniques
    "T1098.005": ("Device Registration", "persistence"),
    "T1098.003": ("Additional Cloud Roles / App Consent", "persistence"),
    "T1114": ("Email Collection", "collection"),
    "T1564.008": ("Email Hiding Rules (Inbox Rule)", "defense-evasion"),
    "T1566": ("Phishing", "initial-access"),
    "T1534": ("Internal Spearphishing", "lateral-movement"),
    "T1621": ("MFA Request Generation", "credential-access"),
}

# Suspicious TLDs / patterns often seen in C2 and phishing infrastructure.
_SUS_TLDS = (".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".ru", ".su", ".info", ".zip", ".mov")
_LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "certutil", "bitsadmin", "wmic", "psexec")
_RANSOM_EXT = (".locked", ".encrypted", ".crypt", ".enc", ".ryk", ".lockbit")
# In free text the extension must end a token: "foo.encoding", "report.encrypted-pdf"
# and "anti-ransomware" are not ransomware artifacts. Ransom-note wording is matched
# as phrases, not the bare word "ransom".
_RANSOM_EXT_RE = re.compile(r"\.(?:locked|encrypted|crypt|enc|ryk|lockbit)(?![\w-])")
_RANSOM_NOTE_RE = re.compile(r"ransom note|ransom demand|(?:your|all) (?:files|data|documents)"
                             r" (?:have been|were|are|got) (?:encrypted|locked)")
# CDN / cloud parents whose machine-generated hostnames look random by design.
_CDN_PARENTS = ("cloudfront.net", "akamaiedge.net", "akamai.net", "azureedge.net",
                "fastly.net", "edgekey.net", "googleusercontent.com", "amazonaws.com")

# Whole-word rules, so "rdp" in wordpress.com, "smb" in SMBIOS or "at.exe" in
# chat.exe do not fire.
# Scheduled-job *creation* only: a task that merely ran or completed is not persistence.
_SCHED_RE = re.compile(r"scheduled tasks?\b[^.;]{0,80}?\b(?:created|registered|updated)\b"
                       r"|schtasks\s+/create|eventid\D{0,3}470[28]\b|crontab(?!\s+-l)|(?:^|[\\/\s\"'])at\.exe\b"
                       r"|new cron job|cron job created")
_REMOTE_RE = re.compile(r"psexec|\bwmic\s|\brdp(?![a-z0-9])|\bsmb(?!ios|d\b)|\bwinrm\b")
_REMOTE_PORTS = {22, 445, 139, 3389, 5985, 5986}  # SSH, SMB, RDP, WinRM
# Allowlist: only an established/allowed connection is a remote-service hit. Teardown/close
# rows (ASA "connection", FortiGate "close") would double-count the session, so they are skipped.
_ALLOWED_RE = re.compile(r"\b(?:allow(?:ed)?|accept(?:ed)?|permit(?:ted)?|pass(?:ed)?|built|established|success|open|connection)\b")
_TEARDOWN_RE = re.compile(r"teardown|\bclose[ds]?\b")
# Whole-word failure: "failover" is not a failed login; "unsuccessful" is. Auth-only
# wording: denied/rejected/incorrect/lockout, "LogonFailed" (no word boundary in Windows names).
# T1110 gates on category=authentication, so firewall "deny" rows never reach this.
_FAIL_RE = re.compile(
    r"(?:(?<![a-z])(?:fail(?:ed|ure|ures|ing|s)?|unsuccess(?:ful|fully)?|denied|rejected|incorrect"
    r"|invalid[ _](?:password|credentials|user)|bad[ _]password|lock(?:ed[ _])?out"
    r"|authentication[ _]error)(?![a-z])|logonfailed(?![a-z]))")
# "unsuccessful" and "not accepted" are not successes; "logonsuccess" and "login_success" are.
_SUCCESS_RE = re.compile(r"(?<!un)success(?:ful|fully)?(?![a-z])")
_ACCEPTED_RE = re.compile(r"(?<!not )(?<![a-z])accepted(?![a-z])")
_NET_ADD_RE = re.compile(r"\bnet1?\s+user\b.*\s/add\b")  # name (and optional password) sit between "user" and "/add"
# Argument-aware forms: match the invocation, not the bare tool name ("useradd: ..." is an error line).
_USERADD_RE = re.compile(r"\buseradd\b(?!:)")
_SERVICE_RE = re.compile(r"\bnew service (?:was )?(?:installed|created)\b|\bnew service \S+\.service\b"
                         r"|\bsc\s+create\b|\bsystemctl\s+(?:--?\S+\s+)*enable\s+(?:--?\S+\s+)*\S*(?:/|\.service\b)")
_TOOL_DL_RE = re.compile(r"\bcertutil\b[^\n]*-urlcache\b|\bbitsadmin\b[^\n]*/(?:transfer|addfile)\b"
                         r"|\b(?:wget|curl)\s[^\n]*(?:https?|ftp)://|invoke-webrequest")
_PS_EXEC_RE = re.compile(r"-enc(?:odedcommand)?\b|\biex\b")  # not "-Encoding" or "index"
# "upload completed" is a success notice (backup job), not an outbound transfer.
# ...unless it names an outbound destination: "upload completed to <dest>" still tags.
_EXFIL_RE = re.compile(r"exfil|\bupload(?:ed|ing|s)?\b(?!\s+(?:completed?|finished|succeeded)\b(?!\s+to\s+\S))")
# (technique, reason, pattern) — invocation-shaped, so reading/querying the same
# artifact (wevtutil qe, reg query ...\Run, netsh ... show) does not fire.
_RULES = tuple((t, r, re.compile(p)) for t, r, p in (
    ("T1070.001", "log-cleared", r"\bwevtutil(?:\.exe)?\s+(?:/\S+\s+)*(?:cl|clear-log)\b|\bclear-eventlog\b"
                                  r"|eventid\D{0,3}(?:1102|104)\b|\b(?:audit|event|security) log (?:was|has been) cleared\b"),
    ("T1562.004", "firewall-off", r"\bnetsh\s+(?:advfirewall|firewall)\b[^\n]*\bstate\s+off\b"
                                  r"|\bset-netfirewallprofile\b[^\n]*-enabled\s+false\b"),
    ("T1547.001", "run-key", r"\breg(?:\.exe)?\s+add\b[^\n]*\\currentversion\\run(?:once)?\b"),
    ("T1003", "cred-dump", r"(?<!\w)(?<!anti-)mimikatz\b|\b(?:sekurlsa|lsadump)::\w+"),
    ("T1136", "account-created", r"eventid\D{0,3}4720\b|\ba user account was created\b"),
    ("T1562.008", "cloud-logging-off", r"(?<![a-z])(?:stoplogging|deletetrail)(?![a-z])"),
))


def _is_auth_success(ev) -> bool:
    """A sign-in that worked. Shared by map_attack and report/rca so verdict and tags agree."""
    if ev.category != "authentication":
        return False
    act = (ev.action or "").lower()
    if _FAIL_RE.search(act):  # an explicit failure action always wins
        return False
    return bool(_SUCCESS_RE.search(act) or _ACCEPTED_RE.search((ev.message or "").lower()))
_SEC_TOOL = (r"(?:defender|windefend|mpssvc|antivirus|anti-virus|antimalware|"
             r"firewall\w*|edr|sysmon\d*|real-?time (?:protection|monitoring)|"
             r"tamper protection|security (?:service|product|agent|center|software|tool))")
_DISABLE_VERB = r"(?:disabled?|disabling|stop(?:ped|ping|s)?|uninstall(?:ed|ing)?|turned off)"
# The verb must act on the tool: "sc stop WinDefend", "stopped Windows Defender
# service", "Defender real-time protection was disabled", "Set-MpPreference
# -DisableRealtimeMonitoring" — not "firewall session stop" or "account was disabled".
_IMPAIR_RE = re.compile(
    rf"\b{_DISABLE_VERB}\b(?:\s+[\w-]+){{0,2}}?\s+{_SEC_TOOL}\b"
    rf"|\b{_SEC_TOOL}(?:\s+(?:service|agent|protection))?\s+{_DISABLE_VERB}\b"
    rf"|\b{_SEC_TOOL}(?:\s+(?!session|connection|flow|traffic|scan|job|task|log|export|update|rule)[\w-]+){{0,3}}?"
    rf"\s+(?:was|is|has been|got|were)\s+{_DISABLE_VERB}\b"
    r"|set-mppreference\b.*\s-disable\w+")


def _looks_dga(domain: str) -> bool:
    """Very rough DGA heuristic: long label, high consonant ratio, digits mixed."""
    if any(domain == p or domain.endswith("." + p) for p in _CDN_PARENTS):
        return False
    label = domain.split(".")[0]
    if len(label) < 12:
        return False
    vowels = sum(c in "aeiou" for c in label.lower())
    ratio = vowels / max(1, len(label))
    has_digit = any(c.isdigit() for c in label)
    return ratio < 0.30 and (has_digit or len(label) >= 16)


def _is_private(ip) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:  # None or unparseable
        return False


def _tag(ev, tid: str, reason: str) -> None:
    if tid not in ev.attack:
        ev.attack.append(tid)
    ev.tags.append(f"attack:{tid}:{reason}")


def map_attack(events: list) -> list:
    """Annotate each event in-place with ATT&CK technique IDs. Returns events."""
    for ev in events:
        msg = (ev.message or "").lower()
        act = (ev.action or "").lower()
        proc = (ev.process or "").lower()

        # Credential access — failed logins. A success that merely mentions an
        # earlier failure ("accepted ... after 1 failed attempt") is not one.
        success = _is_auth_success(ev)
        if ev.category == "authentication" and not success and (_FAIL_RE.search(act) or _FAIL_RE.search(msg)):
            _tag(ev, "T1110", "auth-failure")
        if success:
            ev.tags.append("auth:success")

        # DNS-based C2 / DGA / suspicious TLD.
        if ev.category == "dns" and ev.domain:
            dom = ev.domain.lower()
            if any(dom.endswith(t) for t in _SUS_TLDS):
                _tag(ev, "T1071.004", "suspicious-tld")
            if _looks_dga(dom):
                _tag(ev, "T1568", "dga-like")

        # Execution via LOLBins / scripting.
        if proc:
            for lol in _LOLBINS:
                if lol in proc:
                    _tag(ev, "T1059", f"lolbin:{lol}")
                    if "powershell" in lol:
                        _tag(ev, "T1059.001", "powershell")
                    break
        if "powershell" in msg and ("downloadstring" in msg or _PS_EXEC_RE.search(msg)):
            _tag(ev, "T1059.001", "encoded-powershell")

        # Ingress tool transfer.
        if _TOOL_DL_RE.search(msg):
            _tag(ev, "T1105", "tool-download")

        # Ransomware impact signals.
        if _RANSOM_EXT_RE.search(msg) or _RANSOM_NOTE_RE.search(msg) or ev.file_path and any(
            (ev.file_path or "").lower().endswith(ext) for ext in _RANSOM_EXT):
            _tag(ev, "T1486", "ransom-artifact")
        if "vssadmin" in msg and "delete" in msg or "shadowcopy" in msg and "delete" in msg:
            _tag(ev, "T1490", "shadow-copy-delete")

        # Persistence.
        # Creating/changing a scheduled job, not the scheduler running one
        # ("CRON[123]: (root) CMD (run-parts /etc/cron.hourly)" is routine).
        if _SCHED_RE.search(msg) or _SCHED_RE.search(act):
            _tag(ev, "T1053", "scheduled-task")
        if _SERVICE_RE.search(msg) or _SERVICE_RE.search(act):
            _tag(ev, "T1543", "new-service")
        if any(t in msg or t in act for t in ("net user /add", "create account", "createuser")) \
                or proc in ("useradd", "adduser") or _USERADD_RE.search(msg) or _USERADD_RE.search(act) \
                or _NET_ADD_RE.search(msg) or _NET_ADD_RE.search(act):
            _tag(ev, "T1136", "account-created")
        if proc == "usermod" and msg.startswith("add "):  # "add 'evil' to group 'sudo'"
            _tag(ev, "T1098", "group-membership")

        # Lateral movement.
        if _REMOTE_RE.search(msg) or _REMOTE_RE.search(proc):
            _tag(ev, "T1021", "remote-service")
        elif ev.category == "network" and ev.dst_port in _REMOTE_PORTS and _ALLOWED_RE.search(act) \
                and not _TEARDOWN_RE.search(act + " " + msg) and _is_private(ev.dst_ip):
            _tag(ev, "T1021", f"remote-port:{ev.dst_port}")

        # Defense evasion — disabling/stopping a security product or service
        # (not "account was disabled" from Microsoft-Windows-Security-Auditing).
        if _IMPAIR_RE.search(msg):
            _tag(ev, "T1562", "impair-defenses")

        # Cloud account manipulation.
        if ev.category == "cloud_api" and any(
            t in act for t in ("createuser", "createaccesskey", "putuserpolicy", "attachuserpolicy")):
            _tag(ev, "T1098", "cloud-account-manip")

        # Exfiltration heuristics.
        if ev.category == "network" and _EXFIL_RE.search(msg) or "large transfer" in msg:
            _tag(ev, "T1048", "possible-exfil")

        for tid, reason, rx in _RULES:
            if rx.search(msg) or rx.search(act):
                _tag(ev, tid, reason)
    return events