"""BUG-WEB-10 -- `bluecell intel` must report bad feeds and unwritable/corrupt stores as a
clean "[bluecell] ..." message with rc 2, never a Python traceback."""
import json

from bluecell.cli import main


def _run(argv, capsys):
    rc = main(argv)
    return rc, capsys.readouterr()


def test_import_non_object_records_skipped_not_crash(tmp_path, capsys):
    feed = tmp_path / "f.json"
    feed.write_text(json.dumps([1, "str", None, {"id": "CVE-1", "title": "ok"}]))
    db = tmp_path / "db.json"
    rc, io = _run(["intel", "--intel-db", str(db), "import", str(feed)], capsys)
    assert rc == 0
    assert "Traceback" not in io.err
    assert "skipped 3 non-object record(s)" in io.err
    assert "imported 1 new intel entries" in io.out


def test_import_object_without_list_is_clean_error(tmp_path, capsys):
    feed = tmp_path / "f.json"
    feed.write_text(json.dumps({"vulnerabilities": "nope"}))
    rc, io = _run(["intel", "--intel-db", str(tmp_path / "db.json"), "import", str(feed)], capsys)
    assert rc == 2
    assert io.err.startswith("[bluecell] expected a JSON list")


def test_add_on_corrupt_store_is_clean_error(tmp_path, capsys):
    db = tmp_path / "db.json"
    db.write_text('{"a":1,}')  # trailing comma: unreadable store
    rc, io = _run(["intel", "--intel-db", str(db), "add", "--id", "N", "--title", "new"], capsys)
    assert rc == 2
    assert "Traceback" not in io.err
    assert io.err.count("[bluecell] intel add failed: refusing to overwrite") == 1
    assert db.read_text() == '{"a":1,}'  # untouched
    assert not (tmp_path / "db.json.tmp").exists()


def test_add_on_directory_store_is_clean_error(tmp_path, capsys):
    store_dir = tmp_path / "adir"
    store_dir.mkdir()
    rc, io = _run(["intel", "--intel-db", str(store_dir), "add", "--id", "N", "--title", "t"],
                  capsys)
    assert rc == 2
    assert "Traceback" not in io.err
    assert "[bluecell] intel add failed" in io.err
    assert not (tmp_path / "adir.tmp").exists()


def test_import_on_corrupt_store_is_clean_error(tmp_path, capsys):
    feed = tmp_path / "f.json"
    feed.write_text(json.dumps([{"id": "CVE-1", "title": "ok"}]))
    db = tmp_path / "db.json"
    db.write_text("not json")
    rc, io = _run(["intel", "--intel-db", str(db), "import", str(feed)], capsys)
    assert rc == 2
    assert "Traceback" not in io.err
    assert "[bluecell] intel import failed: refusing to overwrite" in io.err
    assert db.read_text() == "not json"
