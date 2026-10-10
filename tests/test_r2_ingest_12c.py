"""BUG-INGEST-12 loader warning: unrecognised non-blank records are counted per file on stderr."""
import json

from bastion.ingest.loader import ingest_file


def test_csv_unrecognized_rows_warn_once_per_file(tmp_path, capsys):
    p = tmp_path / "edr.csv"
    p.write_text("foo,bar\n1,2\n3,4\n", encoding="utf-8")
    assert ingest_file(str(p)) == []
    err = capsys.readouterr().err
    assert f"bastion: skipped 2 unrecognized record(s) in {p}" in err


def test_json_unrecognized_record_warns_and_blank_stays_silent(tmp_path, capsys):
    p = tmp_path / "e.json"
    p.write_text(json.dumps([{}, {"a": 1}, {"host": "h", "message": "x"}]), encoding="utf-8")
    evs = ingest_file(str(p))
    assert [e.host for e in evs] == ["h"]
    err = capsys.readouterr().err
    assert err.count("unrecognized record") == 1
    assert "skipped 1 unrecognized record(s)" in err


def test_blank_rows_are_silent(tmp_path, capsys):
    p = tmp_path / "edr.csv"
    p.write_text("timestamp,host,message\n2026-01-01T00:00:00Z,a,x\n,,\n,,\n", encoding="utf-8")
    assert len(ingest_file(str(p))) == 1
    assert capsys.readouterr().err == ""

    q = tmp_path / "b.json"
    q.write_text("[{}, {}]", encoding="utf-8")
    assert ingest_file(str(q)) == []
    assert capsys.readouterr().err == ""
