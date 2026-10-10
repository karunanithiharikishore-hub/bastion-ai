"""BUG-PIPE-5: an unreadable intel store must not be silently overwritten.

A corrupt file used to load as empty and the next save() replaced it, losing
every accumulated entry. Now load warns on stderr and save() refuses.
"""
import json

import pytest

from bastion.intel.store import IntelStore


def _good_store(path):
    s = IntelStore(str(path))
    for i in range(3):
        s.add({"id": f"CVE-2026-000{i}", "title": f"t{i}", "summary": "s"})
    s.save()
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", ['{"entries": [ {"id": "A"}, ]', '42', 'null'])
def test_unreadable_store_refuses_save_and_keeps_file(tmp_path, bad):
    p = tmp_path / "intel.json"
    p.write_text(bad, encoding="utf-8")
    store = IntelStore(str(p))
    assert store.load_error
    store.add({"id": "NEW", "title": "n"})
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        store.save()
    assert p.read_text(encoding="utf-8") == bad


def test_corrupt_store_warns_on_stderr(tmp_path, capsys):
    p = tmp_path / "intel.json"
    p.write_text('{"entries": [', encoding="utf-8")
    IntelStore(str(p))
    err = capsys.readouterr().err
    assert "WARNING" in err and str(p) in err


def test_ingest_feed_into_corrupt_store_does_not_clobber(tmp_path):
    p = tmp_path / "intel.json"
    p.write_text("{not json", encoding="utf-8")
    store = IntelStore(str(p))
    with pytest.raises(RuntimeError):
        store.ingest_cve_feed([{"id": "CVE-2026-9999", "title": "x"}])
    assert p.read_text(encoding="utf-8") == "{not json"


def test_valid_store_and_missing_file_still_save(tmp_path, capsys):
    p = tmp_path / "intel.json"
    IntelStore(str(p)).save()  # missing file: no load error, saves fine
    _good_store(tmp_path / "ok.json")
    reloaded = IntelStore(str(tmp_path / "ok.json"))
    assert reloaded.load_error is None
    reloaded.add({"id": "CVE-2026-0009", "title": "more"})
    reloaded.save()
    data = json.loads((tmp_path / "ok.json").read_text(encoding="utf-8"))
    assert len(data["entries"]) == 4
    assert "WARNING" not in capsys.readouterr().err
