"""BUG-INGEST-12: blank CSV rows and {} records must not become phantom events."""
import json

from bluecell.ingest.loader import ingest_file


def test_csv_blank_trailing_rows_are_skipped(tmp_path):
    p = tmp_path / "edr.csv"
    p.write_text("timestamp,host,message\n2026-01-01T00:00:00Z,a,x\n,,\n,,\n",
                 encoding="utf-8")
    evs = ingest_file(str(p))
    assert len(evs) == 1
    assert evs[0].host == "a"
    assert evs[0].ts.year == 2026


def test_json_empty_objects_are_skipped(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps([{}, {"host": "a", "message": "x"}, {"host": None}]),
                 encoding="utf-8")
    evs = ingest_file(str(p))
    assert [e.host for e in evs] == ["a"]


def test_jsonl_empty_object_line_is_skipped(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{}\n{"host": "b", "message": "y"}\n', encoding="utf-8")
    assert [e.host for e in ingest_file(str(p))] == ["b"]
