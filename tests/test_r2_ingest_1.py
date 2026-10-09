"""BUG-INGEST-1: concatenated / pretty-printed / wrapped JSON records must all be
ingested, with every Records-style wrapper unwrapped at every level."""
import datetime
import json

from bluecell.ingest.loader import ingest_file

TS = "2026-01-01T00:00:00Z"


def _ct(name):
    return {"Records": [{"eventTime": TS, "eventName": name, "sourceIPAddress": "1.2.3.4"}]}


def test_pretty_printed_concatenated_objects_are_all_ingested(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"timestamp": TS, "host": "a", "message": "x"}, indent=2) + "\n"
                 + json.dumps({"timestamp": TS, "host": "b", "message": "x"}, indent=2))
    evs = ingest_file(str(p))
    assert [e.host for e in evs] == ["a", "b"]


def test_concatenated_cloudtrail_wrappers_are_unwrapped(tmp_path):
    p = tmp_path / "cloudtrail.json"
    p.write_text(json.dumps(_ct("X")) + json.dumps(_ct("Y")))
    evs = ingest_file(str(p))
    assert [(e.action, e.src_ip) for e in evs] == [("X", "1.2.3.4"), ("Y", "1.2.3.4")]


def test_jsonl_line_wrappers_are_unwrapped_with_real_timestamps(tmp_path):
    p = tmp_path / "ct.jsonl"
    p.write_text(json.dumps(_ct("X")) + "\n" + json.dumps(_ct("Y")) + "\n")
    evs = ingest_file(str(p))
    assert len(evs) == 2
    assert all(e.ts == datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc) for e in evs)


def test_array_of_wrapped_records_is_unwrapped(tmp_path):
    p = tmp_path / "cloudtrail_arr.json"
    p.write_text(json.dumps([_ct("X"), _ct("Y")]))
    assert [e.action for e in ingest_file(str(p))] == ["X", "Y"]


def test_records_wrapper_on_log_line_is_unwrapped(tmp_path):
    p = tmp_path / "cloudtrail_wrap.log"
    p.write_text(json.dumps(_ct("L")) + "\n")
    evs = ingest_file(str(p))
    assert [(e.action, e.src_ip) for e in evs] == [("L", "1.2.3.4")]


def test_json_file_with_zero_records_warns_on_stderr(tmp_path, capsys):
    p = tmp_path / "junk.json"
    p.write_text("this is not json")
    assert ingest_file(str(p)) == []
    assert "no JSON records found" in capsys.readouterr().err
