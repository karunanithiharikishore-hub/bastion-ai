"""ITEM-7: the breadth count uses only the failing events' source IPs.

Unrelated log lines from other hosts (DHCP, NTP) must not turn a benign retry
loop from one IP into 'password spray'.
"""
from datetime import datetime, timedelta, timezone

from bluecell.models import Event
from bluecell.pipeline import correlate, map_attack, normalize
from bluecell.report.rca import assess_incident

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _verdict(events):
    events = normalize(events)
    map_attack(events)
    incidents = correlate(events)
    assert incidents, "expected at least one incident"
    return assess_incident(incidents[0])


def _retry_loop(n=30, ip="203.0.113.9"):
    return [Event(ts=T0 + timedelta(seconds=i), source="syslog", category="authentication",
                  action="login_failed", message=f"Failed password for admin from {ip} port {4000 + i} ssh2",
                  severity=3, host="web1", user="admin", src_ip=ip) for i in range(n)]


def _noise():
    return [
        Event(ts=T0 + timedelta(seconds=40), source="syslog", category="network",
              action="dhcp_ack", message="DHCPACK of 10.0.0.12 from 10.0.0.1",
              severity=6, host="web1", src_ip="10.0.0.1"),
        Event(ts=T0 + timedelta(seconds=50), source="syslog", category="system",
              action="ntp_sync", message="synchronized to 10.0.0.77, stratum 2",
              severity=6, host="web1", src_ip="10.0.0.77"),
    ]


def test_unrelated_lines_do_not_widen_the_ip_count():
    v = _verdict(_retry_loop() + _noise())
    assert v["level"] == "likely-benign"
    assert "from 1 IP(s)" in v["why"]
    assert "password spray" not in v["headline"]
