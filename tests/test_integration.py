"""Cross-feature integration tests: run cache x tracing x evals x injection
defenses x Incident Commander x Tier-2 voting. No real model calls: every
backbone here is a fake."""
import json
import os
import shutil

import pytest

from conftest import SAMPLES
from bluecell import evals
from bluecell.ingest import ingest_paths

ROOT = os.path.join(os.path.dirname(__file__), "..")
CASES = os.path.join(ROOT, "evals", "cases")


# ---------------------------------------------------------------------------
# Evals: the answer key is never ingested as an event
# ---------------------------------------------------------------------------
def test_case_dir_walk_skips_expected_json():
    case = os.path.join(CASES, "vuln_scanner_web")
    walked = ingest_paths([case])
    files = evals.case_files(case)
    assert all(os.path.basename(f) != "expected.json" for f in files)
    assert len(walked) == len(ingest_paths(files))
    assert not any("zgrab UA" in (e.message or "") and e.source == "edr" for e in walked)


def test_expected_json_that_is_a_log_is_still_ingested(tmp_path):
    # Only an eval label (verdict = a BlueCell verdict level) is skipped.
    (tmp_path / "expected.json").write_text(json.dumps(
        {"timestamp": "2026-09-26T09:00:00Z", "source": "edr", "host": "h1",
         "process": "cmd.exe", "message": "process start"}))
    assert len(ingest_paths([str(tmp_path)])) == 1


def test_eval_runner_passes_only_log_files(tmp_path):
    seen = []

    def fake_analyze(paths, **kw):
        seen.extend(paths)
        return {"incidents": [], "meta": {}, "swarm": None}
    evals.run_eval(CASES, names=["vuln_scanner_web"], analyze_fn=fake_analyze, trace=False)
    assert seen and all(os.path.isfile(p) for p in seen)
    assert not any(os.path.basename(p) == "expected.json" for p in seen)


def test_tests_never_write_to_real_home():
    home = os.path.join(os.path.expanduser("~"), ".bluecell")
    for var in ("BLUECELL_CACHE_DIR", "BLUECELL_RUNS_DIR"):
        assert os.environ.get(var)
        assert not os.path.abspath(os.environ[var]).startswith(home)
    from bluecell import cache, tracing
    assert not cache.cache_dir().startswith(home)
    assert not tracing.runs_dir().startswith(home)


# ---------------------------------------------------------------------------
# Run cache x tracing
# ---------------------------------------------------------------------------
def test_cache_hit_is_traced_and_links_the_original_run(tmp_path, monkeypatch):
    from test_repeatability import FakeBackbone
    from bluecell import analyzer, tracing
    from bluecell.report import render_markdown
    monkeypatch.setenv("BLUECELL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    bb = FakeBackbone()
    first = analyzer.analyze([SAMPLES], backbone=bb, intel_store=None, cache="use")
    assert first["meta"]["cache"] == "miss (stored)", first["meta"]["cache"]
    assert first["meta"]["trace"]["llm_calls"] >= 1
    calls = bb.calls
    second = analyzer.analyze([SAMPLES], backbone=bb, intel_store=None, cache="use")
    assert bb.calls == calls
    assert second["meta"]["cache"] == "hit"
    assert second["meta"]["original_run_id"] == first["meta"]["trace"]["run_id"]
    assert second["meta"]["trace"]["run_id"] != first["meta"]["trace"]["run_id"]
    assert second["meta"]["trace"]["llm_calls"] == 0
    listed = {r["run_id"]: r for r in tracing.list_runs()}
    assert listed[second["meta"]["trace"]["run_id"]]["cache"] == "hit"
    assert "Served from the run cache" in render_markdown(second)
