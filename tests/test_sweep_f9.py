"""ITEM-9: `intel add --keywords "a, b"` must not store keywords with a leading space."""
from bastion.intel import IntelStore


def test_comma_space_keywords_are_stripped_and_searchable(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    # Same split the CLI does for --keywords "mimikatz, lsass"
    assert store.add({"id": "X1", "title": "t", "keywords": "mimikatz, lsass".split(",")})
    assert store.entries[0]["keywords"] == ["mimikatz", "lsass"]
    assert [e["id"] for e in store.search(["lsass"])] == ["X1"]


def test_list_items_are_stripped_on_search_of_existing_entries(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    store.entries = [{"id": "X2", "title": "t", "summary": "", "keywords": [" lsass "]}]
    assert [e["id"] for e in store.search(["lsass"])] == ["X2"]
