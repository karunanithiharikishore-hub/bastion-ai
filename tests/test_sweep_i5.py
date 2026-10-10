"""ITEM-5: the auth success predicate must match whole words and respect negation.

'Password not accepted' and 'unsuccessful' used to set auth:success, hiding a
credential spray. A failure must stay a failure; a real sign-in must still count.
"""
from datetime import datetime, timedelta, timezone

import pytest

from bastion.models import Event
from bastion.pipeline import correlate, map_attack, normalize
from bastion.report.rca import assess_incident

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
IP = "203.0.113.7"


def _auth(action, message, i=0):
    return Event(ts=T0 + timedelta(seconds=i), source="syslog", category="authentication",
                 action=action, message=message, severity=2, host="web01", user="bob", src_ip=IP)


@pytest.mark.parametrize("action,message", [
    ("login_failed", "Password not accepted"),
    ("unsuccessful_login", "login attempt"),
    ("auth", "Authentication failed: credentials not accepted"),
])
def test_failure_is_t1110_and_not_success(action, message):
    e = _auth(action, message)
    map_attack([e])
    assert "T1110" in e.attack
    assert "auth:success" not in e.tags


@pytest.mark.parametrize("action,message", [
    ("login_success", "Accepted password for bob from 203.0.113.7"),
    ("successful_login", "login ok"),
])
def test_real_success_still_tagged(action, message):
    e = _auth(action, message)
    map_attack([e])
    assert "auth:success" in e.tags and "T1110" not in e.attack


def test_spray_of_rejected_logins_is_not_followed_by_success():
    events = [_auth("login_failed", "Password not accepted", i) for i in range(6)]
    events.append(_auth("login_failed", "Failed password for bob", 10))
    events.append(_auth("unsuccessful_login", "login attempt", 11))
    events = normalize(events)
    map_attack(events)
    incidents = correlate(events)
    assert incidents, "expected an incident"
    v = assess_incident(incidents[0])
    assert "followed by a success" not in v["headline"]
