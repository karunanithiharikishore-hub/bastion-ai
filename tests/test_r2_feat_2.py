"""BUG-FEAT-2 -- run-cache store failures must never crash a finished analysis,
concurrent stores of one key must not collide, and a malformed entry is a miss."""
import json
import threading

import pytest

from bastion import cache as run_cache


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    return d


def _result():
    return {"meta": {"generated": "x"}, "incidents": []}


def test_store_failure_is_non_fatal(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "not_a_dir"          # cache dir path is a regular file
    blocker.write_text("x")
    monkeypatch.setenv(run_cache.CACHE_ENV, str(blocker))
    result = _result()

    assert run_cache.store("k1", {}, result) is None      # no exception
    assert "not stored" in capsys.readouterr().err
    assert result["meta"]["cache_error"]


def test_unserializable_result_is_non_fatal(cache_dir, capsys):
    result = _result()
    result["loop"] = []
    result["loop"].append(result["loop"])                 # circular -> ValueError
    assert run_cache.store("k2", {}, result) is None
    assert "not stored" in capsys.readouterr().err
    assert not cache_dir.exists() or not list(cache_dir.glob("*.tmp"))


def test_successful_store_leaves_no_temp_files(cache_dir):
    path = run_cache.store("k3", {"a": 1}, _result())
    assert path and json.loads(open(path, encoding="utf-8").read())["result"]
    assert not list(cache_dir.glob("*.tmp"))


def test_concurrent_stores_of_one_key_do_not_collide(cache_dir):
    errors = []
    n_threads, rounds = 8, 30
    barrier = threading.Barrier(n_threads)

    def worker(i):
        for r in range(rounds):
            try:
                barrier.wait()
                run_cache.store("same", {}, {"meta": {}, "who": [i, r]})
            except Exception as exc:              # would escape store() before the fix
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    entry = run_cache.load("same")
    assert entry is not None and isinstance(entry["result"], dict)
    assert not list(cache_dir.glob("*.tmp"))


def test_load_treats_non_dict_result_as_miss(cache_dir):
    cache_dir.mkdir(parents=True)
    (cache_dir / "bad.json").write_text(json.dumps({"result": [1, 2]}))
    assert run_cache.load("bad") is None


def test_mark_hit_tolerates_non_dict_meta():
    entry = {"result": {"meta": "garbage", "incidents": []}, "stored_at": "t"}
    result = run_cache.mark_hit(entry, "key", 5)
    assert result["meta"]["cache"] == "hit"
    assert result["meta"]["timing_ms"]["total"] == 5
