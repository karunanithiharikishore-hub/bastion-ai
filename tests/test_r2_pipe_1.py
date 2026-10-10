"""BUG-PIPE-1: a brute force / password spray must not be called likely-benign.

Benign failed-login noise is one or two source IPs with a bounded failure count.
A spray from many IPs, or a very high count, needs review, and the "stale mail
client" explanation must not be used for an sshd (syslog) spray.
"""
from datetime import datetime, timedelta, timezone

from bastion.models import Event
from bastion.pipeline import correlate, map_attack, normalize
from bastion.report.rca import assess_incident

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _verdict(events):
    events = normalize(events)
    map_attack(events)
    incidents = correlate(events)
    assert incidents, "expected at least one incident"
    return assess_incident(incidents[0])


def _sshd_spray(n, ip_count):
    return [Event(ts=T0 + timedelta(seconds=i), source="syslog", category="authentication",
                  action="login_failed",
                  message=f"Failed password for root from 203.0.113.{i % ip_count + 1} port 22 ssh2",
                  severity=3, host="web01", user="root",
                  src_ip=f"203.0.113.{i % ip_count + 1}") for i in range(n)]


def _entra_retry(n, ip="198.51.100.40"):
    return [Event(ts=T0 + timedelta(minutes=5 * i), source="azure_ad", category="authentication",
                  action="login_failed", message="Error validating credentials",
                  severity=2, host="m365", user="m.chen@northwind.example",
                  src_ip=ip) for i in range(n)]


def test_sshd_spray_from_many_ips_is_not_benign():
    v = _verdict(_sshd_spray(600, 250))
    assert v["level"] == "needs-review"
    assert "mail client" not in (v["why"] + " ".join(v["recommended_checks"])).lower()


def test_high_failure_count_from_one_ip_is_not_benign():
    v = _verdict(_sshd_spray(150, 1))
    assert v["level"] != "likely-benign"


def test_single_ip_stale_credential_retry_stays_benign():
    v = _verdict(_entra_retry(36))
    assert v["level"] == "likely-benign"
    assert "mail client" in v["why"]
