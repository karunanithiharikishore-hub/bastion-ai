"""ITEM-8 follow-up: parse_auth must not turn a generic row ("service failed") into a
sign-in failure. Only logon/auth wording or an explicit status field does."""
from bluecell.ingest.parsers import parse_auth
from bluecell.pipeline.attack import map_attack

BASE = {"timestamp": "2026-10-03T22:00:00Z", "host": "web01"}


def test_generic_failed_row_is_not_a_sign_in_failure():
    for action in ("service failed", "backup job failed"):
        e = parse_auth({**BASE, "action": action})
        map_attack([e])
        assert e.category == "authentication", action
        assert e.action == "auth_event", action
        assert "T1110" not in e.attack, action


def test_logon_wording_failure_still_tags_t1110():
    for action in ("logon failed", "Sign-in failure", "password rejected", "authentication failed"):
        e = parse_auth({**BASE, "action": action, "user": "bob"})
        map_attack([e])
        assert "T1110" in e.attack, action


def test_explicit_status_decides_even_without_logon_wording():
    e = parse_auth({**BASE, "action": "service failed", "status": "failed"})
    assert e.action == "login_failed"
    map_attack([e])
    assert "T1110" in e.attack
    e = parse_auth({**BASE, "action": "service failed", "status": "success"})
    assert e.action == "login_success"
