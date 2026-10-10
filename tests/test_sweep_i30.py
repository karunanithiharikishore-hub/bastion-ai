"""ITEM-30: CSV preamble lines are skipped, duplicate headers warn, and the
delimiter is chosen from the header's field count (a ';' file with a comma in a
header parses)."""
from bastion.ingest.loader import ingest_file


def test_preamble_line_before_header_is_skipped(tmp_path):
    p = tmp_path / "edr.csv"
    p.write_text("Report generated 2026-10-03\n"
                 "timestamp,host,action\n"
                 "2026-10-03T22:00:00Z,a,hello\n")
    events = ingest_file(str(p))
    assert len(events) == 1
    assert events[0].message == "hello"


def test_duplicate_header_warns(tmp_path, capsys):
    p = tmp_path / "edr.csv"
    p.write_text("timestamp,host,host,action\n2026-10-03T22:00:00Z,a,b,hello\n")
    ingest_file(str(p))
    assert "duplicate" in capsys.readouterr().err.lower()


def test_semicolon_file_with_comma_in_header_parses(tmp_path):
    p = tmp_path / "edr.csv"
    p.write_text('timestamp;host;"Process, Name";action\n'
                 '2026-10-03T22:00:00Z;a;cmd.exe;hello\n')
    events = ingest_file(str(p))
    assert len(events) == 1
    assert events[0].message == "hello"
