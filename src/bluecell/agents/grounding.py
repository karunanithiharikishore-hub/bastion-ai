# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Evidence grounding — the ENFORCEMENT behind "no hallucination".

A system-prompt instruction *asks* the model not to invent indicators; it does
not guarantee it. This module verifies it: it extracts concrete indicators
(IPv4/IPv6 addresses, domains, SHA/MD5 hashes, ATT&CK technique ids) from any
LLM-written text and checks each one against the real evidence (the events
actually ingested). Anything the model mentions that is NOT in the evidence is
flagged as UNVERIFIED, so a hallucinated IOC can never be silently presented as
a finding. Bare hostnames and usernames are indexed but NOT checked: they are
too ambiguous to match reliably (FQDN hosts are checked as domains).

This is deterministic, offline, and cheap.
"""
from __future__ import annotations

import ipaddress
import json
import re

_IP_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
# Defang markers analysts use: 1.2.3[.]4, evil(.)ru, evil[dot]ru, hxxp://.
_REFANG_DOT = re.compile(r"[\[({](?:\.|dot)[\])}]", re.I)
# IPv6 candidates (validated with ipaddress, so "10:22:33" is rejected).
_IP6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:]|\.\d)")
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[a-fA-F0-9]{128}|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![0-9a-fA-F])")
_DOMAIN_RE = re.compile(r"(?<![a-zA-Z0-9-])(?:[a-zA-Z0-9-]{1,63}\.){1,10}[a-zA-Z]{2,24}(?![a-zA-Z0-9-])")
# ATT&CK technique ids the model might cite.
_TECH_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# Tokens that look like domains but are noise / self-references we don't verify.
_DOMAIN_STOPWORDS = {"microsoft.com", "office.com", "windows.com"}
# Domain-shaped tokens that are really file names ("certutil.exe", "KB5044284.msu").
_FILE_EXTS = {"exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "js", "hta",
              "msi", "msu", "msp", "cab", "scr", "lnk", "jar", "py", "sh", "so", "bin",
              "log", "txt", "tmp", "dat", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
              "pdf", "iso", "img"}
# Of those, the ones that are also real TLDs: "evil.sh" may be a domain, so these
# count as file names only in a path ("/tmp/run.sh") or when the evidence has them.
_AMBIGUOUS_EXTS = {"sh", "py", "so"}


def _ip6(tok: str) -> str | None:
    """Canonical IPv6 form of `tok`, or None if it is not an IPv6 address."""
    for cand in (tok, tok.rstrip(":")):   # "2001:db8::" is valid; "1:2:3:4:5:6:7:8:" is not
        try:
            return str(ipaddress.IPv6Address(cand))
        except ValueError:
            pass
    return None


def _refang(text: str) -> str:
    return re.sub(r"hxxp", "http", _REFANG_DOT.sub(".", text), flags=re.I)


def _v4(tok: str) -> str | None:
    """Canonical IPv4 (leading zeros stripped, so '010.000.000.001' == '10.0.0.1'), or None."""
    try:
        return str(ipaddress.IPv4Address(".".join(str(int(o)) for o in tok.split("."))))
    except ValueError:
        return None


def _ips(text: str) -> set[str]:
    """All IPv4 and IPv6 addresses in `text`, in canonical form."""
    text = _refang(text)
    out = {ip for ip in map(_v4, _IP_RE.findall(text)) if ip}
    for tok in _IP6_RE.findall(text):
        ip = _ip6(tok)
        if ip and ip != "::":
            out.add(ip)
    return out


def _in_path(text: str, i: int) -> bool:
    """True if the token starting at `i` follows a path separator (not a URL '//')."""
    return i >= 1 and text[i - 1] in "/\\" and text[max(0, i - 2):i] != "//"


# A dotted quad right after a version word or product name ("Chrome 120.0.6.99") is not
# an address. Explicit list: a capitalised noun ("Hosts 203.0.113.250") must still count.
_VERSION_CTX = re.compile(
    # Browsers keep 4-part versions; other product words ("windows 203.0.113.9") could hide a fake IP.
    r"\b(?i:version|ver|v|build|rev|chrome|chromium|firefox|safari|opera)\s+$")
# ATT&CK id followed by a sentence join: "T1059.Then", "T1059.001.Then".
_TECH_JOIN = re.compile(r"t\d{4}(?:\.\d{3})?\.[a-z]{2,}")


def leaf_strings(v):
    """Yield every string leaf (dict keys too) of a nested value; numbers as str.
    Regexes run on these, not json.dumps, whose escapes (\\n, \\t) glue onto IOCs."""
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from leaf_strings(k)
            yield from leaf_strings(x)
    elif isinstance(v, (list, tuple, set)):
        for x in v:
            yield from leaf_strings(x)
    elif v is not None:
        yield str(v)


def evidence_index(events, valid_techniques) -> dict:
    """Build the set of indicators that ACTUALLY appear in the evidence."""
    ips, domains, hashes, hosts, users = set(), set(), set(), set(), set()

    def _note_user_domain(val):
        # A user like "a@corp.com" grounds both the local-part and corp.com so
        # the grounding check never flags the account's own domain/name.
        v = str(val or "").lower()
        if "@" in v:
            local, _, dom = v.partition("@")
            if dom:
                domains.add(dom)
            if local:
                domains.add(local)   # email local-part looks domain-ish to the regex

    for e in events:
        for ip in (getattr(e, "src_ip", None), getattr(e, "dst_ip", None)):
            if ip:
                ips.add(_ip6(str(ip)) or _v4(str(ip)) or str(ip).lower())
        if getattr(e, "domain", None):
            domains.add(str(e.domain).lower())
        if getattr(e, "file_hash", None):
            hashes.add(str(e.file_hash).lower())
        if getattr(e, "host", None):
            hosts.add(str(e.host).lower())
        if getattr(e, "user", None):
            users.add(str(e.user).lower())
            _note_user_domain(e.user)
        # Mine the message text too, so IOCs embedded in messages count as evidence.
        msg = _refang(getattr(e, "message", "") or "")
        ips |= _ips(msg)
        for h in _HASH_RE.findall(msg):
            hashes.add(h.lower())
        for d in _DOMAIN_RE.findall(msg):
            domains.add(d.lower())
        # ...and the raw source record, which agents can read via get_event.
        raw = getattr(e, "raw", None)
        if raw:
            for t in map(_refang, leaf_strings(raw)):
                ips |= _ips(t)
                for h in _HASH_RE.findall(t):
                    hashes.add(h.lower())
                for d in _DOMAIN_RE.findall(t):
                    domains.add(d.lower())
    return {"ips": ips, "domains": domains, "hashes": hashes,
            "hosts": hosts, "users": users,
            "techniques": {t.upper() for t in (valid_techniques or [])}}


def check_text(text: str, index: dict) -> dict:
    """Return {unverified: {...}, ok: bool} for indicators cited in `text`."""
    if not text:
        return {"unverified": {}, "ok": True}
    # IPv4 only if a real address (octets 0-255) and not a version string; IPv6 as before.
    text = _refang(text)
    found_ips = {ip for ip in _ips(text) if ":" in ip}
    for m in _IP_RE.finditer(text):
        ip = _v4(m.group(0))
        if ip and not _VERSION_CTX.search(text[max(0, m.start() - 32):m.start()]):
            found_ips.add(ip)
    found_hashes = {m.lower() for m in _HASH_RE.findall(text)}
    found_domains = set()
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        ext = d.rsplit(".", 1)[-1]
        if d in _DOMAIN_STOPWORDS or _IP_RE.fullmatch(d) or _TECH_JOIN.fullmatch(d):
            continue
        if re.search(r"[a-z]\.[A-Z][a-z]+$", m.group(0)):
            continue   # "shell.Then": a sentence boundary missing its space, not a domain
        if ext in _FILE_EXTS and (ext not in _AMBIGUOUS_EXTS or _in_path(text, m.start())):
            continue   # a file name, not a domain
        found_domains.add(d)
    found_tech = {m.upper() for m in _TECH_RE.findall(text)}

    unverified = {}
    bad_ips = sorted(found_ips - index["ips"])
    bad_hashes = sorted(found_hashes - index["hashes"])
    # A domain counts as grounded if it appears in the evidence (as a domain or
    # an FQDN host) or is a parent of an evidence domain. A subdomain of an
    # evidence domain is NOT grounded: "stage2.evil.top" is not "evil.top".
    known = index["domains"] | index.get("hosts", set())
    bad_domains = sorted(d for d in found_domains
                         if d not in known
                         and not any(kd.endswith("." + d) for kd in known))
    bad_tech = sorted(found_tech - index["techniques"])

    if bad_ips:
        unverified["ips"] = bad_ips
    if bad_hashes:
        unverified["hashes"] = bad_hashes
    if bad_domains:
        unverified["domains"] = bad_domains
    if bad_tech:
        unverified["techniques"] = bad_tech
    return {"unverified": unverified, "ok": not unverified}


def annotate(text: str, index: dict) -> str:
    """Return the text unchanged if grounded, else with an explicit UNVERIFIED
    warning listing the indicators that are NOT in the evidence."""
    result = check_text(text, index)
    if result["ok"]:
        return text
    parts = []
    for kind, vals in result["unverified"].items():
        parts.append(f"{kind}: {', '.join(vals[:10])}")
    warn = ("\n\nGROUNDING CHECK: the following indicators were NOT found in "
            "the ingested evidence and may be model hallucinations; ignore them: "
            + " | ".join(parts))
    return text + warn
