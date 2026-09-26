import json
import os

from conftest import SAMPLES, FEEDS
from bluecell.intel import IntelStore
from bluecell.analyzer import analyze
from bluecell.report import render_markdown, render_json
from bluecell.llm import LLMBackbone


def test_intel_add_dedup_and_search(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    assert store.add({"id": "CVE-1", "title": "ssh brute force bug",
                      "keywords": ["ssh", "brute"], "techniques": ["T1110"]})
    assert not store.add({"id": "CVE-1", "title": "dup"})   # dedup
    store.save()
    hits = store.search(["T1110"])
    assert hits and hits[0]["id"] == "CVE-1"


def test_intel_import_feed(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    with open(os.path.join(FEEDS, "intel_feed.json")) as fh:
        records = json.load(fh)
    n = store.ingest_cve_feed(records)
    assert n == 3
    assert store.stats()["total"] == 3
    # persistence round-trip
    store2 = IntelStore(str(tmp_path / "intel.json"))
    assert store2.stats()["total"] == 3


def test_intel_context_for_incident(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    with open(os.path.join(FEEDS, "intel_feed.json")) as fh:
        store.ingest_cve_feed(json.load(fh))
    result = analyze([SAMPLES], backbone=None, intel_store=store)
    # ransomware + brute-force intel should be surfaced
    assert result["intel_used"], "expected intel to be matched to incidents"


def test_end_to_end_deterministic(tmp_path):
    store = IntelStore(str(tmp_path / "intel.json"))
    with open(os.path.join(FEEDS, "intel_feed.json")) as fh:
        store.ingest_cve_feed(json.load(fh))
    result = analyze([SAMPLES], backbone=None, intel_store=store, window_minutes=120)

    assert result["meta"]["events_ingested"] > 15
    assert result["incidents"], "expected incidents"
    top = result["incidents"][0]
    assert top["storyline"]["narrative_source"] == "deterministic"
    assert top["storyline"]["structured"]["phases"]
    assert top["storyline"]["structured"]["likely_objective"] != "unknown"

    # Renders without error and contains key sections.
    md = render_markdown(result)
    assert "Incident Analysis Report" in md
    assert "Threat-Hunt Checklist" in md
    assert "Indicators of Compromise" in md
    # JSON render is valid JSON.
    json.loads(render_json(result))


def test_backbone_availability_smoke():
    # Should never raise; just reports booleans.
    assert isinstance(LLMBackbone.available("cli"), bool)
    assert isinstance(LLMBackbone.available("api"), bool)


def test_analyze_empty_dir(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = analyze([str(empty)], backbone=None)
    assert result["meta"]["events_ingested"] == 0
    assert result["incidents"] == []
    # Report still renders.
    assert "No correlated incidents" in render_markdown(result)
