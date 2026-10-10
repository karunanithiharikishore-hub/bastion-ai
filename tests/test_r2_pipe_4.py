"""BUG-PIPE-4: IntelStore.save() must not crash for a bare filename.

os.path.dirname("intel.json") is "", which made os.makedirs raise
FileNotFoundError. save() must resolve the path first and write into the
current directory.
"""
import json
import os

from bastion.intel.store import IntelStore


def test_save_bare_filename_writes_into_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = IntelStore("intel_rel.json")
    store.add({"id": "CVE-2026-0001", "title": "t", "summary": "s"})
    store.save()
    out = tmp_path / "intel_rel.json"
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [e["id"] for e in data["entries"]] == ["CVE-2026-0001"]


def test_save_bare_filename_roundtrips(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    IntelStore("mystore.json")  # no file yet: must load empty, not raise
    store = IntelStore("mystore.json")
    store.add({"id": "CVE-2026-0002", "title": "t2", "summary": "s2"})
    store.save()
    reloaded = IntelStore("mystore.json")
    assert [e["id"] for e in reloaded.entries] == ["CVE-2026-0002"]


def test_save_nested_path_still_creates_dirs(tmp_path):
    target = tmp_path / "a" / "b" / "intel.json"
    store = IntelStore(str(target))
    store.add({"id": "CVE-2026-0003", "title": "t3", "summary": "s3"})
    store.save()
    assert target.exists()
