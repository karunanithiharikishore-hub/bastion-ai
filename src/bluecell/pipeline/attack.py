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
# CDN / cloud parents whose machine-generated hostnames look random by design.
_CDN_PARENTS = ("cloudfront.net", "akamaiedge.net", "akamai.net", "azureedge.net",
                "fastly.net", "edgekey.net", "googleusercontent.com", "amazonaws.com")

# Whole-word rules, so "rdp" in wordpress.com, "smb" in SMBIOS or "at.exe" in
# chat.exe do not fire.
_SCHED_RE = re.compile(r"scheduled task|schtasks|crontab|(?:^|[\\/\s\"'])at\.exe\b"
                       r"|new cron job|cron job created")
_REMOTE_RE = re.compile(r"psexec|\bwmic\s|\brdp|\bsmb(?!ios)|\bwinrm\b")
_SEC_TOOL = (r"(?:defender|windefend|mpssvc|antivirus|anti-virus|antimalware|"
             r"firewall\w*|edr|sysmon|real-?time (?:protection|monitoring)|"
             r"tamper protection|security (?:service|product|agent|center|software|tool))")
_DISABLE_VERB = r"(?:disabled?|disabling|stop(?:ped|ping|s)?|uninstall(?:ed|ing)?|turned off)"
# The verb must act on the tool: "sc stop WinDefend", "stopped Windows Defender
# service", "Defender real-time protection was disabled", "Set-MpPreference
# -DisableRealtimeMonitoring" — not "firewall session stop" or "account was disabled".
_IMPAIR_RE = re.compile(
    rf"\b{_DISABLE_VERB}\b(?:\s+[\w-]+){{0,2}}?\s+{_SEC_TOOL}\b"
    rf"|\b{_SEC_TOOL}(?:\s+(?:service|agent|protection))?\s+{_DISABLE_VERB}\b"
    rf"|\b{_SEC_TOOL}(?:\s+(?!session|connection|flow|traffic)[\w-]+){{0,3}}?"
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
        success = ev.category == "authentication" and (
            "success" in act or "accepted" in msg or "login_success" in act)
        if ev.category == "authentication" and not success and ("fail" in act or "fail" in msg):
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
        if "powershell" in msg and ("-enc" in msg or "downloadstring" in msg or "iex" in msg):
            _tag(ev, "T1059.001", "encoded-powershell")

        # Ingress tool transfer.
        if any(t in msg for t in ("certutil", "bitsadmin", "wget ", "curl ", "invoke-webrequest")):
            _tag(ev, "T1105", "tool-download")

        # Ransomware impact signals.
        if any(ext in msg for ext in _RANSOM_EXT) or "ransom" in msg or ev.file_path and any(
            (ev.file_path or "").lower().endswith(ext) for ext in _RANSOM_EXT):
            _tag(ev, "T1486", "ransom-artifact")
        if "vssadmin" in msg and "delete" in msg or "shadowcopy" in msg and "delete" in msg:
            _tag(ev, "T1490", "shadow-copy-delete")

        # Persistence.
        # Creating/changing a scheduled job, not the scheduler running one
        # ("CRON[123]: (root) CMD (run-parts /etc/cron.hourly)" is routine).
        if _SCHED_RE.search(msg) or _SCHED_RE.search(act):
            _tag(ev, "T1053", "scheduled-task")
        if any(t in msg or t in act for t in ("new service", "sc create", "systemctl enable")):
            _tag(ev, "T1543", "new-service")
        if any(t in msg or t in act for t in ("useradd", "net user /add", "create account", "createuser")):
            _tag(ev, "T1136", "account-created")

        # Lateral movement.
        if _REMOTE_RE.search(msg) or _REMOTE_RE.search(proc):
            _tag(ev, "T1021", "remote-service")

        # Defense evasion — disabling/stopping a security product or service
        # (not "account was disabled" from Microsoft-Windows-Security-Auditing).
        if _IMPAIR_RE.search(msg):
            _tag(ev, "T1562", "impair-defenses")

        # Cloud account manipulation.
        if ev.category == "cloud_api" and any(
            t in act for t in ("createuser", "createaccesskey", "putuserpolicy", "attachuserpolicy")):
            _tag(ev, "T1098", "cloud-account-manip")

        # Exfiltration heuristics.
        if ev.category == "network" and any(
            t in msg for t in ("upload", "exfil")) or "large transfer" in msg:
            _tag(ev, "T1048", "possible-exfil")
    return events