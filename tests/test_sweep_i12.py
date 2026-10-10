"""ITEM-12: generic EDR and ECS auth failures must be category authentication
with action login_failed, so attack.map_attack tags T1110."""
from bluecell.ingest.parsers import parse_edr
from bluecell.pipeline.attack import map_attack


def _tagged(rec):
    e = parse_edr(rec)
    map_attack([e])
    return e


def test_generic_edr_failed_login_actions_become_authentication_and_t1110():
    base = {"timestamp": "2026-10-03T22:00:00Z", "user": "bob", "host": "h1", "src_ip": "203.0.113.5"}
    for extra in ({"action": "login_failed"},
                  {"event_type": "failed_login"},
                  {"action": "logon_failed"},
                  {"message": "Failed password for bob"}):
        e = _tagged({**base, **extra})
        assert e.category == "authentication", extra
        assert e.action == "login_failed", extra
        assert "T1110" in e.attack, extra


def test_ecs_authentication_outcome_drives_action_and_t1110():
    rec = {"@timestamp": "2026-10-03T22:00:00Z",
           "event": {"category": ["authentication"], "action": "ssh_login", "outcome": "failure"},
           "source": {"ip": "203.0.113.9"}, "user": {"name": "root"}, "host": {"name": "web1"},
           "message": "Failed password for root from 203.0.113.9 port 4000 ssh2"}
    e = _tagged(rec)
    assert e.category == "authentication" and e.action == "login_failed"
    assert "T1110" in e.attack

    ok = _tagged({**rec, "event": {"category": ["authentication"], "action": "ssh_login", "outcome": "success"},
                  "message": "Accepted password for root"})
    assert ok.category == "authentication" and ok.action == "login_success"
    assert "T1110" not in ok.attack


def test_non_auth_edr_records_stay_process():
    assert parse_edr({"action": "proc", "host": "h1", "ProcessCommandLine": "ls"}).category == "process"
    assert parse_edr({"event": {"category": ["process"], "outcome": "failure"}, "host": "h1",
                      "message": "spawn failed"}).category == "process"
