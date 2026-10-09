# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""IOC extraction and threat-hunt checklist generation."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")

def is_public_ip(ip) -> bool:
    """True for a globally routable IPv4/IPv6 address. Private, loopback,
    link-local, CGNAT, multicast, reserved and malformed values are not
    useful as external IOCs. RFC 5737/3849 documentation ranges count as
    public so the bundled synthetic samples behave like real external IPs."""
    try:
        addr = ipaddress.ip_address(str(ip).strip().strip("[]").split("%")[0])
    except ValueError:
        return False
    if addr.is_multicast:          # Python counts some multicast as "global"
        return False
    if addr.is_global:
        return True
    doc = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"),
           ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32"))
    return any(addr in net for net in doc if net.version == addr.version)


_is_public_ip = is_public_ip   # backwards-compatible name


def extract_iocs(events: list) -> dict:
    """Collect IOCs across events, prioritizing those tied to ATT&CK hits.

    Returns a dict of ioc-type -> list of {value, count, suspicious, hosts}.
    """
    buckets: dict = {"ip": Counter(), "domain": Counter(), "hash": Counter(),
                     "user": Counter(), "process": Counter()}
    suspicious: dict = {"ip": set(), "domain": set(), "hash": set(),
                        "user": set(), "process": set()}
    host_map: dict = {}

    def note_host(kind, value, host):
        if host:
            host_map.setdefault((kind, value), set()).add(host)

    for ev in events:
        flagged = bool(ev.attack)
        for ip in dict.fromkeys((ev.src_ip, ev.dst_ip)):  # once per event, order kept
            if ip and _is_public_ip(ip):
                buckets["ip"][ip] += 1
                note_host("ip", ip, ev.host)
                if flagged:
                    suspicious["ip"].add(ip)
        if ev.domain:
            dom = ev.domain.lower().rstrip(".")
            buckets["domain"][dom] += 1
            note_host("domain", dom, ev.host)
            if flagged:
                suspicious["domain"].add(dom)
        # Each distinct hash counts once per event, whether it came from the
        # hash field or was mined from the message (and case-insensitively).
        hashes = set(h.lower() for h in _HASH_RE.findall(ev.message or ""))
        if ev.file_hash and _HASH_RE.fullmatch(ev.file_hash):
            hashes.add(ev.file_hash.lower())
        for h in hashes:
            buckets["hash"][h] += 1
            note_host("hash", h, ev.host)
            if flagged:
                suspicious["hash"].add(h)
        if ev.process and flagged:
            buckets["process"][ev.process] += 1
            suspicious["process"].add(ev.process)
        if ev.user and flagged:
            buckets["user"][ev.user] += 1
            suspicious["user"].add(ev.user)

    out: dict = {}
    for kind, counter in buckets.items():
        items = []
        for value, count in counter.most_common():
            items.append({
                "value": value,
                "count": count,
                "suspicious": value in suspicious[kind],
                "hosts": sorted(host_map.get((kind, value), set())),
            })
        # Suspicious first, then by frequency.
        items.sort(key=lambda x: (not x["suspicious"], -x["count"]))
        out[kind] = items
    return out


def hunt_checklist(incidents: list, iocs: dict) -> list:
    """Produce a prioritized list of threat-hunt / verification actions."""
    checks = []

    sus_ips = [i["value"] for i in iocs.get("ip", []) if i["suspicious"]]
    sus_domains = [i["value"] for i in iocs.get("domain", []) if i["suspicious"]]
    sus_hashes = [i["value"] for i in iocs.get("hash", []) if i["suspicious"]]

    if sus_domains:
        checks.append({
            "priority": "high",
            "action": "Block and hunt suspicious domains across all DNS/proxy logs",
            "targets": sus_domains,
            "why": "Flagged as C2/DGA/suspicious-TLD during correlation.",
        })
    if sus_ips:
        checks.append({
            "priority": "high",
            "action": "Search firewall/netflow for any host contacting these IPs",
            "targets": sus_ips,
            "why": "External IPs tied to ATT&CK-flagged activity.",
        })
    if sus_hashes:
        checks.append({
            "priority": "critical",
            "action": "Sweep EDR for these file hashes fleet-wide; isolate matches",
            "targets": sus_hashes,
            "why": "Malicious/suspect binaries observed on affected hosts.",
        })

    for inc in incidents[:5]:
        if inc.score() >= 50:
            checks.append({
                "priority": inc.severity_label(),
                "action": f"Validate incident {inc.id} on hosts {sorted(inc.hosts) or ['n/a']}",
                "targets": sorted(inc.hosts),
                "why": f"Score {inc.score()}/100 across tactics: {sorted(inc.tactics) or ['n/a']}.",
            })

    # Only the accounts on the brute-force events themselves, not every user
    # that happens to share an incident with them.
    bf_users = sorted({e.user for inc in incidents for e in inc.events
                       if e.user and "T1110" in e.attack})
    if bf_users:
        checks.append({
            "priority": "medium",
            "action": "Review accounts targeted by brute force; force password reset + enable MFA",
            "targets": bf_users,
            "why": "Brute-force (T1110) detected.",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    checks.sort(key=lambda c: order.get(c["priority"], 4))
    return checks