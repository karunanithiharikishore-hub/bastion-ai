"""ITEM-10: store-file keywords are matched case-insensitively.
ITEM-11: save() merges concurrent writers and uses a unique tmp name."""
import json
import os

from bluecell.intel import IntelStore
from bluecell.intel import store as store_mod


def test_store_file_keywords_match_case_insensitively(tmp_path):
    path = str(tmp_path / "intel.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"entries": [{"id": "A", "title": "t", "summary": "",
                                "keywords": ["Mimikatz"]}]}, fh)
    assert [e["id"] for e in IntelStore(path).search(["mimikatz"])] == ["A"]


def test_stale_writer_does_not_drop_other_writers_entries(tmp_path):
    path = str(tmp_path / "intel.json")
    s1 = IntelStore(path)
    s2 = IntelStore(path)          # both loaded the same (empty) file
    s1.add({"id": "A", "title": "a"})
    s1.save()
    s2.add({"id": "B", "title": "b"})
    s2.save()                      # must merge A from disk, not overwrite it
    assert sorted(e["id"] for e in IntelStore(path).entries) == ["A", "B"]


def test_save_uses_unique_tmp_name(tmp_path, monkeypatch):
    path = str(tmp_path / "intel.json")
    used = []
    real_replace = os.replace

    def spy(src, dst):
        used.append(src)
        return real_replace(src, dst)

    monkeypatch.setattr(store_mod.os, "replace", spy)
    s = IntelStore(path)
    s.add({"id": "A", "title": "a"})
    s.save()
    s.add({"id": "B", "title": "b"})
    s.save()
    assert len(used) == 2 and used[0] != used[1]
    assert path + ".tmp" not in used
