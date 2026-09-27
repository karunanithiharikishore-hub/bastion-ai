# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""Evidence grounding — the ENFORCEMENT behind "no hallucination".

A system-prompt instruction *asks* the model not to invent indicators; it does
not guarantee it. This module verifies it: it extracts concrete indicators
(IPs, domains, SHA/MD5 hashes, hostnames) from any LLM-written text and checks
each one against the real evidence (the events actually ingested). Anything the
model mentions that is NOT in the evidence is flagged as UNVERIFIED, so a
hallucinated IOC can never be silently presented as a finding.

This is deterministic, offline, and cheap.
"""
from __future__ import annotations

import re

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
# ATT&CK technique ids the model might cite.
_TECH_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# Tokens that look like domains but are noise / self-references we don't verify.
_DOMAIN_STOPWORDS = {"microsoft.com", "office.com", "windows.com"}


def evidence_index(events, valid_techniques) -> dict:
    """Build the set of indicators that ACTUALLY appear in the evidence."""
    ips, domains, hashes, hosts, users = set(), set(), set(), set(), set()
    for e in events:
        for ip in (getattr(e, "src_ip", None), getattr(e, "dst_ip", None)):
            if ip:
                ips.add(str(ip).lower())
        if getattr(e, "domain", None):
            domains.add(str(e.domain).lower())
        if getattr(e, "file_hash", None):
            hashes.add(str(e.file_hash).lower())
        if getattr(e, "host", None):
            hosts.add(str(e.host).lower())
        if getattr(e, "user", None):
            users.add(str(e.user).lower())
        # Mine the message text too, so IOCs embedded in messages count as evidence.
        msg = getattr(e, "message", "") or ""
        for ip in _IP_RE.findall(msg):
            ips.add(ip.lower())
        for h in _HASH_RE.findall(msg):
            hashes.add(h.lower())
    return {"ips": ips, "domains": domains, "hashes": hashes,
            "hosts": hosts, "users": users,
            "techniques": {t.upper() for t in (valid_techniques or [])}}


def check_text(text: str, index: dict) -> dict:
    """Return {unverified: {...}, ok: bool} for indicators cited in `text`."""
    if not text:
        return {"unverified": {}, "ok": True}
    found_ips = {m.lower() for m in _IP_RE.findall(text)}
    found_hashes = {m.lower() for m in _HASH_RE.findall(text)}
    found_domains = {m.lower() for m in _DOMAIN_RE.findall(text)
                     if m.lower() not in _DOMAIN_STOPWORDS
                     and not _IP_RE.fullmatch(m)}
    found_tech = {m.upper() for m in _TECH_RE.findall(text)}

    unverified = {}
    bad_ips = sorted(found_ips - index["ips"])
    bad_hashes = sorted(found_hashes - index["hashes"])
    # A domain counts as grounded if it (or a parent) appears in evidence domains.
    bad_domains = sorted(d for d in found_domains
                         if d not in index["domains"]
                         and not any(d.endswith("." + kd) or kd.endswith("." + d)
                                     for kd in index["domains"]))
    bad_tech = sorted(found_tech - index["techniques"]) if index["techniques"] else []

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
    warn = ("\n\n⚠ GROUNDING CHECK — the following indicators were NOT found in "
            "the ingested evidence and may be model hallucinations; ignore them: "
            + " | ".join(parts))
    return text + warn
