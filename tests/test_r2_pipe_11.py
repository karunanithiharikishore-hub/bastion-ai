"""BUG-PIPE-11 -- IntelStore.add() must keep string keywords/techniques whole (not
exploded into characters) and coerce non-string items to str so search() never crashes."""
from bluecell.intel import IntelStore


def test_string_keywords_and_techniques_are_single_items(tmp_path):
    s = IntelStore(str(tmp_path / "q.json"))
    s.add({"id": "A", "title": "t", "keywords": "SSH, Brute", "techniques": "T1110"})
    assert s.entries[0]["keywords"] == ["ssh, brute"]
    assert s.entries[0]["techniques"] == ["T1110"]


def test_non_string_technique_does_not_crash_search(tmp_path):
    s = IntelStore(str(tmp_path / "q.json"))
    s.add({"id": "B", "title": "t", "techniques": [1059, None]})
    assert s.entries[0]["techniques"] == ["1059"]
    assert [e["id"] for e in s.search(["1059"])] == ["B"]


def test_list_keywords_are_lowercased_strings(tmp_path):
    s = IntelStore(str(tmp_path / "q.json"))
    s.add({"id": "C", "title": "t", "keywords": ["SSH", 22, None]})
    assert s.entries[0]["keywords"] == ["ssh", "22"]


def test_empty_or_missing_fields_become_empty_lists(tmp_path):
    s = IntelStore(str(tmp_path / "q.json"))
    s.add({"id": "D", "title": "t", "keywords": "   ", "techniques": None})
    assert s.entries[0]["keywords"] == []
    assert s.entries[0]["techniques"] == []
