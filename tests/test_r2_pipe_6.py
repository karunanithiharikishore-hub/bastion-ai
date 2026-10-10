"""BUG-PIPE-6: intel search must not match generic terms as substrings of free text.

A user "SYSTEM" used to match a summary about a "phone operating system", and
"data" matched "database". Only whole-token summary hits and keyword/technique
matches count now.
"""
import json
import os

from conftest import SAMPLES, FEEDS
from bastion.analyzer import analyze
from bastion.intel.store import IntelStore


def _store(tmp_path):
    return IntelStore(str(tmp_path / "intel.json"))


def test_generic_user_does_not_match_summary_word(tmp_path):
    s = _store(tmp_path)
    s.add({"id": "CVE-X", "title": "Samsung graphics driver flaw",
           "summary": "Samsung phone operating system graphics driver flaw.",
           "keywords": ["samsung", "graphics", "driver"]})
    assert s.search(["SYSTEM", "certutil.exe"]) == []


def test_auto_derived_keywords_do_not_match_generic_user(tmp_path):
    s = _store(tmp_path)
    # No explicit keywords: they are derived from the summary, which contains "system".
    s.add({"id": "CVE-X", "title": "Samsung graphics driver flaw",
           "summary": "Samsung phone operating system graphics driver flaw."})
    assert s.search(["SYSTEM"]) == []


def test_short_term_does_not_match_inside_longer_word(tmp_path):
    s = _store(tmp_path)
    s.add({"id": "CVE-DB", "title": "Engine flaw", "summary": "Remote flaw in the database engine."})
    assert s.search(["data"]) == []
    assert s.search(["db"]) == []


def test_whole_token_summary_hit_still_matches(tmp_path):
    s = _store(tmp_path)
    s.add({"id": "TTP-PSEXEC", "title": "Lateral movement", "summary": "Attackers ran psexec.exe."})
    hits = s.search(["psexec.exe"])
    assert hits and hits[0]["id"] == "TTP-PSEXEC"


def test_attack_sample_still_finds_ssh_bruteforce_intel(tmp_path):
    s = _store(tmp_path)
    with open(os.path.join(FEEDS, "intel_feed.json")) as fh:
        s.ingest_cve_feed(json.load(fh))
    result = analyze([SAMPLES], backbone=None, intel_store=s)
    assert "CVE-2026-12345" in [e["id"] for e in result["intel_used"]]
