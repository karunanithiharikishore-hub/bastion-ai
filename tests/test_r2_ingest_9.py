"""BUG-INGEST-9: deeply nested JSON must not abort ingest of the file or directory,
and must not crash Event.to_dict() later."""
import json

from bastion.ingest.loader import ingest_file, ingest_path

GOOD = '{"timestamp":"2026-01-01T00:00:00Z","host":"a"}\n'


def _deep_line(depth):
    return ('{"timestamp":"2026-01-01T00:00:00Z","host":"b","x":'
            + "[" * depth + "]" * depth + "}\n")


def test_very_deep_line_skipped_and_directory_ingest_continues(tmp_path):
    (tmp_path / "a_good.jsonl").write_text(GOOD)
    (tmp_path / "b_deep.jsonl").write_text(_deep_line(5000))
    evs = ingest_path(str(tmp_path))
    assert [e.host for e in evs] == ["a"]


def test_moderately_deep_record_skipped_and_export_does_not_crash(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text(_deep_line(900) + GOOD)
    evs = ingest_file(str(p))
    assert [e.host for e in evs] == ["a"]
    json.dumps([e.to_dict() for e in evs])


def test_deep_expected_json_label_does_not_abort_directory(tmp_path):
    (tmp_path / "expected.json").write_text("[" * 5000 + "]" * 5000)
    (tmp_path / "a_good.jsonl").write_text(GOOD)
    assert [e.host for e in ingest_path(str(tmp_path))] == ["a"]
