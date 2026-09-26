"""IOC extraction and threat-hunt checklist generation."""
from __future__ import annotations

import re
from collections import Counter

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")

# RFC1918 / loopback / link-local — not useful as external IOCs.
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")


def _is_public_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
        except (IndexError, ValueError):
            return True
    return True


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
        for ip in (ev.src_ip, ev.dst_ip):
            if ip and _is_public_ip(ip):
                buckets["ip"][ip] += 1
                note_host("ip", ip, ev.host)
                if flagged:
                    suspicious["ip"].add(ip)
        if ev.domain:
            buckets["domain"][ev.domain] += 1
            note_host("domain", ev.domain, ev.host)
            if flagged:
                suspicious["domain"].add(ev.domain)
        if ev.file_hash and _HASH_RE.fullmatch(ev.file_hash):
            buckets["hash"][ev.file_hash] += 1
            note_host("hash", ev.file_hash, ev.host)
            if flagged:
                suspicious["hash"].add(ev.file_hash)
        if ev.process and flagged:
            buckets["process"][ev.process] += 1
            suspicious["process"].add(ev.process)
        if ev.user and flagged:
            buckets["user"][ev.user] += 1
            suspicious["user"].add(ev.user)
        # Mine free-text messages for hashes/IPs the parser missed.
        for h in _HASH_RE.findall(ev.message or ""):
            buckets["hash"][h] += 1
            if flagged:
                suspicious["hash"].add(h)

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

    if any("T1110" in inc.techniques for inc in incidents):
        checks.append({
            "priority": "medium",
            "action": "Review accounts targeted by brute force; force password reset + enable MFA",
            "targets": sorted({u for inc in incidents for u in inc.users}),
            "why": "Brute-force (T1110) detected.",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    checks.sort(key=lambda c: order.get(c["priority"], 4))
    return checks
