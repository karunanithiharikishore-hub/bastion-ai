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
