"""ITEM-6: many distinct usernames from one IP is password spray / enumeration, not a mistyped password."""
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


def _enumeration(n_users, ip="203.0.113.9"):
    out = []
    for i in range(n_users):
        ts = T0 + timedelta(seconds=2 * i)
        out.append(Event(ts=ts, source="syslog", category="authentication", action="login_failed",
                         message=f"Invalid user user{i} from {ip} port {4000 + i}",
                         severity=3, host="web01", user=f"user{i}", src_ip=ip))
        out.append(Event(ts=ts, source="syslog", category="authentication", action="login_failed",
                         message=f"Failed password for invalid user user{i} from {ip} port {4000 + i} ssh2",
                         severity=3, host="web01", user=f"user{i}", src_ip=ip))
    return out


def test_one_ip_many_usernames_is_not_a_mistyped_password():
    v = _verdict(_enumeration(45))
    assert v["level"] == "needs-review"
    assert "mistyped password" not in v["why"]


def test_one_ip_two_usernames_retry_still_benign():
    v = _verdict(_enumeration(1))
    assert v["level"] == "likely-benign"
