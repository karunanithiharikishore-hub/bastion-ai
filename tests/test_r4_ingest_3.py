"""BUG-R4-INGEST-3: ECS-nested JSON (winlogbeat/filebeat) must resolve host.name,
user.name, source.ip and event.action; a dict must never become a host/user string."""
from bastion.ingest.parsers import _get, parse_dns, parse_edr
from bastion.pipeline.attack import map_attack

ECS = {"@timestamp": "2026-10-03T22:00:00Z",
       "event": {"action": "logon-failed", "outcome": "failure"},
       "host": {"name": "DC01"}, "source": {"ip": "203.0.113.9"},
       "user": {"name": "admin"}, "message": "An account failed to log on."}


def test_ecs_nested_fields_resolve_to_plain_strings():
    ev = parse_edr(dict(ECS))
    assert ev.host == "DC01"
    assert ev.user == "admin"
    assert ev.src_ip == "203.0.113.9"
    assert ev.action == "login_failed"
    assert ev.category == "authentication"


def test_ecs_logon_failure_is_tagged_brute_force():
    ev = map_attack([parse_edr(dict(ECS))])[0]
    assert "T1110" in ev.attack


def test_dict_without_name_is_not_a_host():
    ev = parse_edr({"host": {"ip": "10.0.0.5"}, "action": "x", "user": {"id": 7}})
    assert ev.host is None and ev.user is None


def test_nested_dns_question_name_resolves_and_flat_dotted_key_still_works():
    assert parse_dns({"dns": {"question": {"name": "evil.com."}}, "client": "h1"}).domain == "evil.com"
    assert parse_dns({"dns.question.name": "evil.com"}).domain == "evil.com"


def test_get_prefers_flat_key_then_nested_path():
    assert _get({"a.b": 1, "a": {"b": 2}}, "a.b") == 1
    assert _get({"a": {"B": 2}}, "A.b") == 2
    assert _get({"a": "x"}, "a.b") is None
