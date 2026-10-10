"""BUG-PIPE-2: only an authentication event counts as a sign-in success.

A firewall "connection accepted" line from the same IP as failed logins is not a
sign-in, so it must not produce the "failed sign-ins followed by a success" verdict.
"""
from datetime import datetime, timedelta, timezone

from bastion.models import Event
from bastion.pipeline import correlate, map_attack, normalize
from bastion.report.rca import assess_incident

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
IP = "203.0.113.9"


def _verdict(events):
    events = normalize(events)
    map_attack(events)
    incidents = correlate(events)
    assert incidents, "expected at least one incident"
    return assess_incident(incidents[0])


def _failed_logins(n):
    return [Event(ts=T0 + timedelta(seconds=i), source="syslog", category="authentication",
                  action="login_failed", message=f"Failed password for admin from {IP}",
                  severity=2, host="web01", user="admin", src_ip=IP) for i in range(n)]


def test_firewall_accepted_is_not_a_sign_in_success():
    fw = Event(ts=T0 + timedelta(seconds=9), source="firewall", category="network",
               action="allow", message="tcp connection accepted on port 22",
               severity=0, src_ip=IP, dst_ip="10.0.0.5")
    v = _verdict(_failed_logins(5) + [fw])
    assert "followed by a success" not in v["headline"]
    assert "at least one SUCCESS" not in v["why"]


def test_real_authentication_success_still_counts():
    ok = Event(ts=T0 + timedelta(seconds=9), source="syslog", category="authentication",
               action="login_success", message=f"Accepted password for admin from {IP}",
               severity=0, host="web01", user="admin", src_ip=IP)
    v = _verdict(_failed_logins(5) + [ok])
    assert "followed by a success" in v["headline"]
