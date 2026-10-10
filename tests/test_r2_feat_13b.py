"""BUG-FEAT-13 follow-up -- a --refresh run that cannot be stored must remove the
old entry, so the next normal run does not serve it. No real model calls."""
from conftest import BENIGN_SAMPLES
from test_repeatability import FakeBackbone
from bastion import analyzer, cache as run_cache


class Broken(FakeBackbone):
    def messages(self, body):
        raise RuntimeError("boom")


def _analyze(backbone, **kw):
    kw.setdefault("orchestration", "fixed")
    return analyzer.analyze([BENIGN_SAMPLES], backbone=backbone, intel_store=None,
                            trace=False, **kw)


def test_refresh_that_cannot_store_removes_old_entry(tmp_path, monkeypatch):
    monkeypatch.setenv(run_cache.CACHE_ENV, str(tmp_path / "cache"))
    real = run_cache.uncacheable_reason
    monkeypatch.setattr(run_cache, "uncacheable_reason", lambda result, backbone: None)
    assert _analyze(FakeBackbone(), cache="use")["meta"]["cache"] == "miss (stored)"
    monkeypatch.setattr(run_cache, "uncacheable_reason", real)

    out = _analyze(Broken(), cache="refresh")
    assert out["meta"]["cache"].startswith("miss (not stored: ")
    assert out["meta"]["cache"].endswith("; stale entry removed)")

    nxt = _analyze(FakeBackbone(), cache="use")
    assert nxt["meta"]["cache"] != "hit"


def test_refresh_without_old_entry_reports_plain_not_stored(tmp_path, monkeypatch):
    monkeypatch.setenv(run_cache.CACHE_ENV, str(tmp_path / "cache"))
    out = _analyze(Broken(), cache="refresh")
    assert out["meta"]["cache"].startswith("miss (not stored: ")
    assert "stale entry removed" not in out["meta"]["cache"]


def test_use_that_cannot_store_keeps_existing_entry(tmp_path, monkeypatch):
    monkeypatch.setenv(run_cache.CACHE_ENV, str(tmp_path / "cache"))
    real = run_cache.uncacheable_reason
    monkeypatch.setattr(run_cache, "uncacheable_reason", lambda result, backbone: None)
    _analyze(FakeBackbone(), cache="use")
    monkeypatch.setattr(run_cache, "uncacheable_reason", real)

    _analyze(Broken(), cache="use")
    assert _analyze(FakeBackbone(), cache="use")["meta"]["cache"] == "hit"
