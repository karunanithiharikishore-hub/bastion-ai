"""ITEM-4: a --no-trace run is never saved, so the report must not offer a `runs show` hint."""
from bluecell import tracing
from bluecell.report import render


def _result():
    return {"incidents": [], "iocs": {}, "hunt_checklist": [],
            "meta": {"generated": "now", "events_ingested": 1, "events_normalized": 1,
                     "sources": [], "backbone": "off", "digest_tokens": 0}}


def test_unsaved_run_report_has_no_runs_show_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    t = tracing.Tracer(persist=False)
    result = _result()
    t.finish(result)
    out = render.render_markdown(result)
    assert "bluecell runs show" not in out
    assert "not saved (--no-trace)" in out
    assert not (tmp_path / "runs").exists()


def test_saved_run_report_keeps_runs_show_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    t = tracing.Tracer(persist=True, directory=str(tmp_path / "runs"))
    result = _result()
    t.finish(result)
    out = render.render_markdown(result)
    assert f"`bluecell runs show {t.run_id}`" in out


def test_cache_hit_of_unsaved_original_run_says_not_saved(tmp_path):
    # Entry as cache.store writes it when the original run used --no-trace.
    from bluecell import cache as run_cache
    stored = _result()
    entry = {"key": "k", "stored_at": "2026-01-01T00:00:00+00:00", "origin_run_id": "gone-run",
             "origin_persisted": False, "result": stored}
    stored["meta"]["trace"] = {"run_id": "this-run", "persisted": False}   # this run's trace, set by finish()
    result = run_cache.mark_hit(entry, "k", 5)
    out = render.render_markdown(result)
    assert "original run not saved" in out
    assert "gone-run" not in out
    assert "bluecell runs show" not in out


def test_store_records_origin_persisted_through_to_report(tmp_path, monkeypatch):
    from bluecell import cache as run_cache
    monkeypatch.setenv("BLUECELL_CACHE_DIR", str(tmp_path / "cache"))
    for persisted, key in ((False, "k-unsaved"), (True, "k-saved")):
        assert run_cache.store(key, {}, _result(), origin_run_id="orig-run",
                               origin_persisted=persisted) is not None
        entry = run_cache.load(key)
        assert entry["origin_persisted"] is persisted
        entry["result"]["meta"]["trace"] = {"run_id": "this-run"}   # set by finish() in a real run
        out = render.render_markdown(run_cache.mark_hit(entry, key, 5))
        assert ("original run `orig-run`" in out) is persisted
        assert ("original run not saved" in out) is not persisted


def test_run_summary_facts_carry_original_run_persisted():
    from bluecell import cache as run_cache
    entry = {"stored_at": "t", "origin_run_id": "gone-run", "origin_persisted": False,
             "result": _result()}
    facts = tracing._result_facts(run_cache.mark_hit(entry, "k", 5))
    assert facts["original_run_id"] == "gone-run"
    assert facts["original_run_persisted"] is False
