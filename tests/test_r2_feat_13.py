"""BUG-FEAT-13 -- a --refresh run that cannot be stored must drop the old entry."""
import pytest

from bluecell import cache as run_cache


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    return d


def test_invalidate_removes_stored_entry(cache_dir):
    run_cache.store("k", {}, {"meta": {}, "incidents": []})
    assert run_cache.load("k") is not None
    assert run_cache.invalidate("k") is True
    assert run_cache.load("k") is None


def test_invalidate_missing_entry_is_harmless(cache_dir):
    assert run_cache.invalidate("never-stored") is False
