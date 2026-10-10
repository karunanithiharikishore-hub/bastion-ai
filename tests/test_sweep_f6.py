"""ITEM-6: a render crash in observe() must fail must_* checks, not blank the text so they pass vacuously."""
import pytest

from bluecell import evals


def _result():
    return {"incidents": [{"id": "i1", "verdict": {"level": "likely-malicious"}}],
            "swarm": {"findings": []}, "meta": {}}


@pytest.fixture
def broken_renderer(monkeypatch):
    def boom(result):
        raise RuntimeError("renderer crashed")
    # observe() imports render_markdown from the bluecell.report package at call time
    monkeypatch.setattr("bluecell.report.render_markdown", boom)


def test_observe_records_render_error(broken_renderer):
    obs = evals.observe(_result())
    assert obs["render_error"] == "RuntimeError: renderer crashed"


def test_must_not_mention_fails_when_render_crashes(broken_renderer, tmp_path):
    case = {"name": "c", "dir": str(tmp_path), "files": [str(tmp_path / "a.log")],
            "expected": {"verdict": "likely-malicious", "must_not_mention": ["evil"]},
            "problems": []}
    rec = evals.run_case(case, analyze_fn=lambda files, **kw: _result())
    run = rec["runs"][0]
    assert run["checks"]["must_not_mention"] == "fail"
    assert run["passed"] is False
    assert rec["passed"] is False
    assert any("render failed" in f for f in run["failures"])
