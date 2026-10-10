"""ITEM-20 regression: ECS list values yield their first scalar (host "DC01", not "['DC01']"),
and a comma-separated IP string yields its first valid IP instead of being dropped."""
import json
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)

from bluecell.ingest.loader import ingest_file


def load(tmp_path, rec):
    p = tmp_path / "rec.jsonl"
    p.write_text(json.dumps(rec) + "\n")
    evs = ingest_file(str(p))
    assert len(evs) == 1
    return evs[0]


def test_ecs_list_fields_unwrapped(tmp_path):
    ev = load(tmp_path, {"@timestamp": "2026-10-03T22:00:00Z", "event": {"action": "logon-failed"},
                         "host": {"name": ["DC01"]}, "source": {"ip": ["203.0.113.9"]},
                         "user": {"name": ["admin"]}, "message": "An account failed to log on."})
    assert (ev.host, ev.user, ev.src_ip) == ("DC01", "admin", "203.0.113.9")


def test_comma_separated_ip_takes_first(tmp_path):
    ev = load(tmp_path, {"timestamp": "2026-10-03T22:00:00Z", "hostname": "a", "src_ip": "203.0.113.9, 10.0.0.1",
                         "user": "bob", "action": "login_failed"})
    assert ev.src_ip == "203.0.113.9"
