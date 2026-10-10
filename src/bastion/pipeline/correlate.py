# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Cross-source correlation.

Groups related events into Incidents by shared entities (host, user, IP,
domain, file hash) within a sliding time window, then scores each incident by
severity, breadth of ATT&CK tactics, and number of sources involved. This is
the "cross-refer and cross-correlate" stage.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import timedelta

from .attack import ATTACK_TECHNIQUES


def _is_shared_noise_ip(val) -> bool:
    """Loopback/unspecified/link-local IPs are local to each host, not a shared attacker."""
    try:
        a = ipaddress.ip_address(str(val).strip().strip("[]"))
    except ValueError:
        return False
    a = getattr(a, "ipv4_mapped", None) or a  # ::ffff:127.0.0.1 is still loopback
    return a.is_loopback or a.is_unspecified or a.is_link_local


def _is_ip(val) -> bool:
    try:
        ipaddress.ip_address(str(val))
        return True
    except ValueError:
        return False


def _one_spelling(key, values) -> set:
    """Collapse spellings of the same host/user (see _same_entity), keeping the longest (most specific)."""
    best: dict = {}
    for v in values:
        k = _same_entity(key, v)
        if len(v) > len(best.get(k, "")):
            best[k] = v
    return set(best.values())


def _is_public_ip(val) -> bool:
    """Routable IPs are attacker infrastructure; many hosts hitting one is the signal, not noise."""
    try:
        a = ipaddress.ip_address(str(val).strip().strip("[]"))
    except ValueError:
        return False
    a = getattr(a, "ipv4_mapped", None) or a
    return a.is_global


# Shared by many unrelated hosts, so useless (and harmful) as a merge link.
_HUB_VALUES = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222",
               "208.67.220.220", "root", "administrator", "system", "admin",
               "nt authority\\system", "local service", "network service"}
_HUB_MAX_HOSTS = 3  # shortcut: fixed cap, make configurable if real fleets need it


@dataclass
class Incident:
    id: str
    events: list = field(default_factory=list)
    entities: dict = field(default_factory=dict)   # entity -> set of values

    # ---- derived properties -------------------------------------------------
    @property
    def start(self):
        return min(e.ts for e in self.events)

    @property
    def end(self):
        return max(e.ts for e in self.events)

    @property
    def sources(self) -> set:
        return {e.source for e in self.events}

    @property
    def techniques(self) -> list:
        out = []
        for e in self.events:
            for t in e.attack:
                if t not in out:
                    out.append(t)
        return out

    @property
    def tactics(self) -> set:
        tac = set()
        for t in self.techniques:
            meta = ATTACK_TECHNIQUES.get(t)
            if meta:
                for part in meta[1].split("/"):
                    tac.add(part)
        return tac

    @property
    def hosts(self) -> set:
        return _one_spelling("host", (e.host for e in self.events if e.host))

    @property
    def users(self) -> set:
        return _one_spelling("user", (e.user for e in self.events if e.user))

    @property
    def max_severity(self) -> int:
        return max((e.severity for e in self.events), default=0)

    def score(self) -> int:
        """0-100 risk score — explainable weighting."""
        s = 0
        s += min(40, self.max_severity * 10)          # severity weight
        s += min(25, len(self.tactics) * 6)           # kill-chain breadth
        s += min(15, (len(self.sources) - 1) * 5)     # cross-source corroboration
        s += min(20, len(self.techniques) * 3)        # technique volume
        return min(100, s)

    def severity_label(self) -> str:
        sc = self.score()
        return ("critical" if sc >= 75 else "high" if sc >= 50
                else "medium" if sc >= 25 else "low")


class _DSU:
    """Union-Find to merge events sharing entities within the time window."""

    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _same_entity(key, val) -> str:
    """One spelling per host/user: "FIN-SRV01.corp.local" == "fin-srv01", "CORP\\bob" == "bob@corp.local" == "bob".
    shortcut: same short name in two domains merges; keep FQDNs if a fleet reuses short names."""
    v = str(val).strip().lower()
    if key == "host" and not _is_ip(v):
        return v.split(".", 1)[0]
    if key == "user":
        return v.rsplit("\\", 1)[-1].split("@", 1)[0]
    return v


def correlate(events: list, window_minutes: int = 60,
              min_events: int = 2) -> list:
    """Return a list of Incidents, highest score first.

    Two events are linked if they share any entity value AND occur within
    ``window_minutes`` of each other. Connected components become incidents.
    """
    if not events:
        return []
    events = sorted(events, key=lambda e: e.ts)
    n = len(events)
    dsu = _DSU(n)
    window = timedelta(minutes=window_minutes)

    # Index by entity value, but only link within the time window. Because
    # events are time-sorted, for each entity we only need to compare against
    # the most recent prior event carrying that value.
    def _token(key, val):
        # An IP is the same entity whether it is the source or destination
        # (attacker IP as SSH source, then as a firewall destination).
        if key in ("src_ip", "dst_ip"):
            return ("ip", str(val).lower())
        return (key, _same_entity(key, val))

    # One pass: distinct hosts per ip/user value, to spot hubs (shared resolvers, gateways).
    hosts_of: dict = {}
    for ev in events:
        if ev.host:
            for key, val in ev.entities().items():
                if key in ("src_ip", "dst_ip", "user"):
                    hosts_of.setdefault(_token(key, val), set()).add(_same_entity("host", ev.host))

    last_seen: dict = {}  # (entity_key, value) -> index
    for i, ev in enumerate(events):
        for key, val in ev.entities().items():
            if key in ("src_ip", "dst_ip") and _is_shared_noise_ip(val):
                continue
            token = _token(key, val)
            # Degree cap spares public IPs: an attacker spraying many hosts must still link them.
            if key in ("src_ip", "dst_ip", "user") and (
                    token[1] in _HUB_VALUES or (len(hosts_of.get(token, ())) > _HUB_MAX_HOSTS
                                                and not _is_public_ip(val))):
                continue
            j = last_seen.get(token)
            if j is not None and (ev.ts - events[j].ts) <= window:
                dsu.union(j, i)
            last_seen[token] = i

    # Gather components.
    comps: dict = {}
    for i in range(n):
        comps.setdefault(dsu.find(i), []).append(events[i])

    incidents = []
    for root, evs in comps.items():
        if len(evs) < min_events and not any(e.attack for e in evs):
            continue  # drop isolated benign singletons
        ent: dict = {}
        for e in evs:
            for k, v in e.entities().items():
                ent.setdefault(k, set()).add(v)
        inc = Incident(id=f"INC-{events[root].event_id}", events=sorted(evs, key=lambda e: e.ts),
                       entities={k: sorted(v) for k, v in ent.items()})
        incidents.append(inc)

    incidents.sort(key=lambda inc: inc.score(), reverse=True)
    return incidents