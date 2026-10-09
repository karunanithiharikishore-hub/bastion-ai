"""BUG-FEAT-11 (runs part): the runs dir is pruned after each persisted run.
No model calls: a Tracer is driven directly and persisted into tmp_path."""
import os
import time

from bluecell import tracing


def _run(d):
    t = tracing.Tracer(["a.log"], persist=True, directory=str(d))
    t.finish({"meta": {}})
    return t.run_id


def _fake_run(d, i, age_s):
    name = f"20200101T{i:06d}Z-aaaaaa"
    p = d / name
    p.mkdir()
    (p / "summary.json").write_text("{}")
    os.utime(p, (time.time() - age_s, time.time() - age_s))
    return name


def test_runs_pruned_to_env_keep(tmp_path, monkeypatch):
    d = tmp_path / "runs"
    monkeypatch.setenv("BLUECELL_RUNS_KEEP", "5")
    ids = [_run(d) for _ in range(12)]
    left = sorted(os.listdir(d))
    assert len(left) == 5
    assert ids[-1] in left            # the run just written is never deleted


def test_default_keep_is_200(tmp_path, monkeypatch):
    d = tmp_path / "runs"
    d.mkdir()
    monkeypatch.delenv("BLUECELL_RUNS_KEEP", raising=False)
    for i in range(210):
        _fake_run(d, i, age_s=10_000 - i)
    rid = _run(d)
    left = os.listdir(d)
    assert len(left) == tracing.RUNS_KEEP_DEFAULT == 200
    assert rid in left


def test_stale_tmp_swept_and_foreign_dirs_untouched(tmp_path, monkeypatch):
    d = tmp_path / "runs"
    d.mkdir()
    monkeypatch.delenv("BLUECELL_RUNS_KEEP", raising=False)
    old = d / "orphan.tmp"
    old.write_text("x")
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    fresh = d / "inflight.tmp"
    fresh.write_text("x")
    (d / "not-a-run").mkdir()
    rid = _run(d)
    assert not old.exists()
    assert fresh.exists()
    assert (d / "not-a-run").is_dir()
    assert rid in os.listdir(d)


def test_prune_failure_never_breaks_run(tmp_path, monkeypatch):
    d = tmp_path / "runs"

    def boom(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(tracing, "_prune_runs", boom)
    t = tracing.Tracer(["a.log"], persist=True, directory=str(d))
    summ = t.finish({"meta": {}})
    assert summ["run_id"] == t.run_id
    assert (d / t.run_id / "summary.json").exists()
