"""BUG-INGEST-10: a JSON record's own `repeated` field must not crash ingest or
expand into events; only the syslog parser's repeat counter expands (capped)."""
import json

from bastion.ingest.loader import ingest_file

TS = "2026-01-01T00:00:00Z"


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj) + "\n")
    return str(p)


def test_string_repeated_in_json_record_does_not_crash(tmp_path):
    p = _write(tmp_path, "j.log", {"timestamp": TS, "host": "a", "repeated": "yes"})
    evs = ingest_file(p)
    assert len(evs) == 1 and evs[0].host == "a"


def test_bool_repeated_in_json_record_is_ignored(tmp_path):
    p = _write(tmp_path, "b.log", {"timestamp": TS, "host": "a", "repeated": True})
    assert len(ingest_file(p)) == 1


def test_huge_int_repeated_in_json_record_is_not_expanded(tmp_path):
    p = _write(tmp_path, "k.log", {"timestamp": TS, "host": "a", "repeated": 200000})
    evs = ingest_file(p)
    assert len(evs) == 1
    assert "repeat_index" not in evs[0].raw


def test_syslog_repeat_still_expands_and_is_capped(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("Oct  3 22:00:00 web01 sshd[1]: message repeated 5000 times: "
                 "[ Failed password for root from 1.2.3.4 port 22 ssh2]\n")
    evs = ingest_file(str(p))
    assert len(evs) == 1000
    assert len({e.event_id for e in evs}) == 1000
