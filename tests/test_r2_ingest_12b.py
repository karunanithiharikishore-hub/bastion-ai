"""BUG-INGEST-12 follow-up: records with only unrecognised keys must not become edr_event noise."""
import json

from bastion.ingest.loader import ingest_file
from bastion.ingest.parsers import parse_edr


def test_parse_edr_returns_none_for_unknown_keys_only():
    assert parse_edr({"a": 1}) is None
    assert parse_edr({"foo": "bar", "baz": None}) is None


def test_parse_edr_keeps_record_with_a_known_field():
    ev = parse_edr({"a": 1, "host": "h1"})
    assert ev is not None and ev.host == "h1"


def test_json_unknown_key_record_is_skipped(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps([{"a": 1}, {"host": "a", "message": "x"}]), encoding="utf-8")
    evs = ingest_file(str(p))
    assert [e.host for e in evs] == ["a"]


def test_csv_unknown_columns_are_skipped(tmp_path):
    p = tmp_path / "unknown.csv"
    p.write_text("foo,bar\n1,2\n3,4\n", encoding="utf-8")
    assert ingest_file(str(p)) == []
