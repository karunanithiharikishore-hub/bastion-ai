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
}

# Suspicious TLDs / patterns often seen in C2 and phishing infrastructure.
_SUS_TLDS = (".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".ru", ".su", ".info", ".zip", ".mov")
_LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "certutil", "bitsadmin", "wmic", "psexec")
_RANSOM_EXT = (".locked", ".encrypted", ".crypt", ".enc", ".ryk", ".lockbit")


def _looks_dga(domain: str) -> bool:
    """Very rough DGA heuristic: long label, high consonant ratio, digits mixed."""
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

        # Credential access — failed logins.
        if ev.category == "authentication" and ("fail" in act or "fail" in msg):
            _tag(ev, "T1110", "auth-failure")
        if ev.category == "authentication" and ("success" in act or "accepted" in msg or "login_success" in act):
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
        if any(t in msg or t in act for t in ("scheduled task", "schtasks", "cron", "at.exe")):
            _tag(ev, "T1053", "scheduled-task")
        if any(t in msg or t in act for t in ("new service", "sc create", "systemctl enable")):
            _tag(ev, "T1543", "new-service")
        if any(t in msg or t in act for t in ("useradd", "net user /add", "create account", "createuser")):
            _tag(ev, "T1136", "account-created")

        # Lateral movement.
        if any(t in msg or t in proc for t in ("psexec", "wmic ", "rdp", "smb", "winrm")):
            _tag(ev, "T1021", "remote-service")

        # Defense evasion — disabling security tooling.
        if any(t in msg for t in ("disable", "stop", "uninstall")) and any(
            t in msg for t in ("defender", "antivirus", "firewall", "edr", "security")):
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