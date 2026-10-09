"""BUG-R3-INGEST-2: an IP present as both src_ip and dst_ip was counted twice per event."""
from datetime import datetime

from bluecell.models import Event
from bluecell.pipeline.ioc import extract_iocs


def test_same_ip_as_src_and_dst_counts_once_per_event():
    evs = [Event(ts=datetime(2026, 1, 1), source="edr", category="logon",
                 action="LogonFailed", message="x", src_ip="203.0.113.50",
                 dst_ip="203.0.113.50", host="pc1") for _ in range(40)]
    ip = extract_iocs(evs)["ip"]
    assert [(i["value"], i["count"]) for i in ip] == [("203.0.113.50", 40)]
    assert ip[0]["hosts"] == ["pc1"]


def test_distinct_src_and_dst_still_both_counted():
    ev = Event(ts=datetime(2026, 1, 1), source="fw", category="network",
               action="allow", message="x", src_ip="203.0.113.1", dst_ip="198.51.100.2")
    counts = {i["value"]: i["count"] for i in extract_iocs([ev])["ip"]}
    assert counts == {"203.0.113.1": 1, "198.51.100.2": 1}
