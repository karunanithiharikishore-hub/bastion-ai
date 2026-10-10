"""ITEM-13: T1110 must recognise denied/rejected/invalid/incorrect/lockout and 'LogonFailed'
authentication failures, while firewall denies and failover stay out."""
import pytest

from bluecell.models import Event
from bluecell.pipeline.attack import map_attack

_TS = "2026-10-03T22:00:00Z"


def _auth(action, message=""):
    return Event(ts=_TS, source="t", category="authentication", action=action, message=message)


@pytest.mark.parametrize("action,message", [
    ("login_denied", "x"),
    ("auth", "Authentication rejected for bob"),
    ("auth", "Invalid credentials"),
    ("auth", "bad password"),
    ("auth", "Access denied for user 'bob'@'1.2.3.4' (using password: YES)"),
    ("auth", "Login incorrect"),
    ("auth", "user locked out"),
    ("account_lockout", "Account locked out"),
    ("auth", "authentication error"),
    ("LogonFailed", ""),
])
def test_auth_failure_vocabulary_tags_t1110(action, message):
    e = _auth(action, message)
    map_attack([e])
    assert "T1110" in e.attack, (action, message)


def test_firewall_deny_is_not_brute_force():
    e = Event(ts=_TS, source="fw", category="network", action="deny", message="Access denied by policy 12")
    map_attack([e])
    assert "T1110" not in e.attack


def test_failover_and_success_are_not_failures():
    for action, message in (("failover", "cluster failover complete"), ("logonsuccess", "")):
        e = _auth(action, message)
        map_attack([e])
        assert "T1110" not in e.attack, (action, message)
