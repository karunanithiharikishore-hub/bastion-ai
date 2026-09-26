from conftest import SAMPLES
from bluecell.ingest import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.pipeline.ioc import hunt_checklist
from bluecell.models import Event


def _loaded():
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    return events


def test_normalize_dedup_and_sort():
    e1 = Event(ts="2026-09-26T09:00:05Z", source="edr", category="process",
               action="run", message="dup", host="h")
    e2 = Event(ts="2026-09-26T09:00:05Z", source="edr", category="process",
               action="run", message="dup", host="h")
    e3 = Event(ts="2026-09-26T08:00:00Z", source="edr", category="process",
               action="run", message="earlier", host="h")
    out = normalize([e1, e2, e3])
    assert len(out) == 2                     # dup collapsed
    assert out[0].message == "earlier"       # sorted ascending


def test_attack_maps_bruteforce():
    events = _loaded()
    assert any("T1110" in e.attack for e in events)


def test_attack_maps_dns_c2_and_dga():
    events = _loaded()
    techs = {t for e in events for t in e.attack}
    assert "T1071.004" in techs   # suspicious .xyz / .top TLD
    assert "T1568" in techs       # DGA-like domain


def test_attack_maps_ransomware_and_tooldl():
    techs = {t for e in _loaded() for t in e.attack}
    assert "T1486" in techs       # ransomware
    assert "T1105" in techs       # certutil download
    assert "T1059.001" in techs   # powershell


def test_correlation_groups_by_shared_entity():
    incidents = correlate(_loaded(), window_minutes=120)
    assert incidents, "expected at least one incident"
    top = incidents[0]
    # The web01 attack chain should pull in multiple sources.
    assert len(top.sources) >= 2
    assert top.score() >= 50
    assert top.severity_label() in ("high", "critical")


def test_correlation_respects_time_window():
    a = Event(ts="2026-09-26T09:00:00Z", source="edr", category="process",
              action="a", message="m", host="h1")
    a.attack.append("T1059")
    b = Event(ts="2026-09-26T20:00:00Z", source="edr", category="process",
              action="b", message="m", host="h1")
    b.attack.append("T1486")
    incidents = correlate([a, b], window_minutes=30)
    # 11h apart with a 30m window -> must not merge into one incident.
    assert all(len(inc.events) == 1 for inc in incidents)


def test_ioc_extraction_flags_public_not_private():
    iocs = extract_iocs(_loaded())
    ips = {i["value"] for i in iocs["ip"]}
    assert "203.0.113.90" in ips or "198.51.100.7" in ips
    assert "10.0.0.11" not in ips     # private IPs excluded
    assert any(i["suspicious"] for i in iocs["domain"])


def test_hunt_checklist_prioritized():
    events = _loaded()
    incidents = correlate(events, window_minutes=120)
    checklist = hunt_checklist(incidents, extract_iocs(events))
    assert checklist
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranks = [order.get(c["priority"], 4) for c in checklist]
    assert ranks == sorted(ranks)     # sorted by priority


def test_compress_collapses_bursts_and_estimates_tokens():
    bursts = [
        Event(ts="2026-09-26T09:00:00Z", source="syslog", category="authentication",
              action="login_failed", message="Failed password", host="h", user="admin",
              src_ip="203.0.113.66")
        for _ in range(50)
    ]
    digest = compress(bursts)
    assert "x50" in digest            # 50 identical events collapsed to one line
    assert digest.count("\n") < 5
