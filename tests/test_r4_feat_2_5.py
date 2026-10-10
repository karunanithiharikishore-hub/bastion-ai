"""BUG-R4-FEAT-5: a store entry with null / non-list keywords or techniques must not
crash search (and so `analyze` / `intel search`).
BUG-R4-FEAT-2: a bare feed list loaded as the intel store must give the same run-cache
fingerprint on every load (the volatile `added` stamp must not be hashed)."""
import json
import time

from bastion import cache
from bastion.intel.store import IntelStore


def _write(tmp_path, data):
    p = tmp_path / "store.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_null_or_non_list_keywords_and_techniques_do_not_crash_search(tmp_path):
    path = _write(tmp_path, {"entries": [
        {"id": "X", "title": "ssh brute force", "keywords": None, "techniques": None},
        {"id": "Y", "title": "unrelated", "keywords": 7, "techniques": [1059]},
    ]})
    store = IntelStore(path)
    assert store.load_error is None
    assert [e["id"] for e in store.search(["ssh"])] == ["X"]
    assert [e["id"] for e in store.search(["1059"])] == ["Y"]


def test_feed_list_intel_store_has_stable_fingerprint_across_loads(tmp_path):
    path = _write(tmp_path, [{"id": "CVE-2026-0001", "title": "ssh brute force",
                              "description": "many failed logins", "cvss": "7.5"}])
    first = cache.intel_fingerprint(IntelStore(path))
    time.sleep(0.01)                  # make the now() stamp in `added` differ between loads
    second = cache.intel_fingerprint(IntelStore(path))
    assert first == second
