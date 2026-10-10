"""ITEM-31: non-text inputs must not become garbage events, directory walks must
say what they skipped, and BOM-less UTF-16 CSV must parse.
"""
import gzip
import os

from bluecell.ingest.loader import ingest_file, ingest_path

SYSLOG = ("Oct  3 22:00:00 web1 sshd[1]: Failed password for root from "
          "203.0.113.9 port 4000 ssh2\n") * 5


def test_gzip_log_is_decompressed_not_ingested_as_bytes(tmp_path):
    p = tmp_path / "auth.log.gz"
    p.write_bytes(gzip.compress(SYSLOG.encode()))
    events = ingest_file(str(p))
    assert len(events) == 5
    assert all("Failed password" in e.message for e in events)


def test_binary_file_is_rejected_with_message(tmp_path, capsys):
    p = tmp_path / "e.evtx"
    p.write_bytes(bytes(range(256)) * 2)
    assert ingest_file(str(p)) == []
    assert "binary" in capsys.readouterr().err


def test_explicit_tsv_header_is_not_an_event(tmp_path):
    p = tmp_path / "x.tsv"
    p.write_text("timestamp\thost\tmessage\n2026-10-03T22:00:00Z\ta\thello\n")
    events = ingest_file(str(p))
    assert len(events) == 1
    assert events[0].message == "hello"


def test_bomless_utf16le_csv_parses(tmp_path):
    p = tmp_path / "e.csv"
    p.write_bytes("timestamp,host,message\n2026-10-03T22:00:00Z,a,hello\n".encode("utf-16-le"))
    assert len(ingest_file(str(p))) == 1


def test_directory_walk_reports_skipped_files(tmp_path, capsys):
    d = tmp_path / "dir"
    d.mkdir()
    (d / "auth.log").write_text(SYSLOG)
    (d / "auth.log.1").write_text(SYSLOG)
    (d / "auth.log.2.gz").write_bytes(gzip.compress(SYSLOG.encode()))
    (d / "x.tsv").write_text("timestamp\thost\tmessage\n2026-10-03T22:00:00Z\ta\thello\n")
    (d / "e.evtx").write_bytes(os.urandom(500))
    events = ingest_path(str(d))
    err = capsys.readouterr().err
    assert len(events) == 5 + 5 + 1   # auth.log, auth.log.2.gz, x.tsv
    assert "skipped 2 unsupported file(s)" in err
    assert "auth.log.1" in err and "e.evtx" in err
