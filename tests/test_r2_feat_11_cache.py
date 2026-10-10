"""BUG-FEAT-11 (cache part) -- the run cache must not grow forever: entries orphaned
by a code change are dropped, only the newest BASTION_CACHE_KEEP entries are
kept, stale *.tmp files are swept, and pruning never breaks a store."""
import os

import pytest

from bastion import cache as run_cache


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    monkeypatch.delenv(run_cache.KEEP_ENV, raising=False)
    return d


def _result(i=0):
    return {"meta": {}, "i": i}


def _names(d):
    return sorted(p.name for p in d.glob("*.json"))


def test_entries_from_other_code_are_dropped(cache_dir):
    run_cache.store("old", {"code": "fingerprint-of-older-code"}, _result())
    run_cache.store("new", {"code": run_cache.code_fingerprint()}, _result())
    assert _names(cache_dir) == ["new.json"]


def test_only_newest_keep_entries_are_kept(cache_dir, monkeypatch):
    monkeypatch.setenv(run_cache.KEEP_ENV, "3")
    for i in range(5):
        path = run_cache.store(f"k{i}", {}, _result(i))
        os.utime(path, (1000 + i, 1000 + i))      # make mtimes deterministic
    assert _names(cache_dir) == ["k2.json", "k3.json", "k4.json"]


def test_stale_tmp_is_swept_and_fresh_tmp_is_kept(cache_dir):
    cache_dir.mkdir(parents=True)
    stale = cache_dir / "dead.abc.tmp"
    fresh = cache_dir / "live.def.tmp"
    stale.write_text("x")
    fresh.write_text("y")
    os.utime(stale, (1000, 1000))                 # long past TMP_MAX_AGE_S
    run_cache.store("k", {}, _result())
    assert not stale.exists()
    assert fresh.exists()                         # may be another process's in-flight store


def test_prune_failure_does_not_break_store(cache_dir, monkeypatch, capsys):
    def boom():
        raise OSError("fingerprint unavailable")
    monkeypatch.setattr(run_cache, "code_fingerprint", boom)
    assert run_cache.store("k", {}, _result()) is not None
    assert run_cache.load("k") is not None
    assert "prune skipped" in capsys.readouterr().err
