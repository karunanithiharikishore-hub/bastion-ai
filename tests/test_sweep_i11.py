"""ITEM-11: parse_auth must read status/result/outcome/success so failed and
successful logins are not identical."""
from bluecell.ingest.parsers import parse_auth
from bluecell.pipeline.attack import map_attack


def test_failed_login_variants_become_login_failed_and_tag_t1110():
    base = {"timestamp": "2026-10-03T22:00:00Z", "user": "bob", "src_ip": "203.0.113.5"}
    for extra in ({"action": "login", "result": "failure"},
                  {"event": "login", "status": "failed"},
                  {"action": "login", "success": False}):
        e = parse_auth({**base, **extra})
        assert e.action == "login_failed", extra
        assert e.severity == 3, extra
        map_attack([e])
        assert "T1110" in e.attack, extra


def test_successful_login_variants_become_login_success():
    base = {"timestamp": "2026-10-03T22:00:00Z", "user": "bob"}
    for extra in ({"action": "login", "outcome": "SUCCESS"},
                  {"action": "login", "success": True},
                  {"action": "login", "result": "success"}):
        e = parse_auth({**base, **extra})
        assert e.action == "login_success", extra
        map_attack([e])
        assert "auth:success" in e.tags and "T1110" not in e.attack, extra


def test_no_verdict_field_keeps_old_behaviour():
    assert parse_auth({"action": "login", "user": "bob"}).action == "login"
    assert parse_auth({"action": "fail", "user": "bob"}).severity == 3
