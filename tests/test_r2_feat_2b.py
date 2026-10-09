"""BUG-FEAT-2 follow-up -- when the run-cache write fails after a complete run,
meta.cache must say "miss (not stored: <reason>)", matching meta.cache_error,
instead of "miss (stored)". No real model calls: FakeBackbone from test_repeatability."""
import pytest

from conftest import BENIGN_SAMPLES
from test_repeatability import FakeBackbone
from bluecell import analyzer, cache as run_cache


@pytest.fixture
def cacheable(monkeypatch):
    # Isolate the store-failure path: the run is otherwise complete and cacheable.
    monkeypatch.setattr(run_cache, "uncacheable_reason", lambda result, backbone: None)


def _analyze(backbone, **kw):
    kw.setdefault("orchestration", "fixed")
    return analyzer.analyze([BENIGN_SAMPLES], backbone=backbone, intel_store=None,
                            trace=False, **kw)


def test_failed_store_reports_not_stored_with_reason(tmp_path, monkeypatch, capsys, cacheable):
    blocker = tmp_path / "not_a_dir"          # cache dir path is a regular file
    blocker.write_text("x")
    monkeypatch.setenv(run_cache.CACHE_ENV, str(blocker))

    out = _analyze(FakeBackbone(), cache="use")

    assert out["meta"]["cache"] != "miss (stored)"
    assert out["meta"]["cache"] == f"miss (not stored: {out['meta']['cache_error']})"
    assert out["meta"]["cache_error"]
    assert "not stored" in capsys.readouterr().err


def test_failed_refresh_store_is_not_reported_as_refreshed(tmp_path, monkeypatch, cacheable):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv(run_cache.CACHE_ENV, str(blocker))

    out = _analyze(FakeBackbone(), cache="refresh")

    assert out["meta"]["cache"].startswith("miss (not stored: ")
