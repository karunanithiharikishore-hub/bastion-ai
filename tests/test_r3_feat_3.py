"""R3-FEAT-3: non-object summary.json / trace.jsonl lines must be skipped, not crash runs listing."""
import json
import os

from bluecell import tracing


def _mk(base, rid, summary, trace=None):
    os.makedirs(os.path.join(base, rid))
    with open(os.path.join(base, rid, "summary.json"), "w", encoding="utf-8") as fh:
        fh.write(summary)
    if trace is not None:
        with open(os.path.join(base, rid, "trace.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(trace)


def test_list_runs_skips_non_object_summary(tmp_path):
    good = "20260101T000001Z-aaaaaa"
    _mk(tmp_path, "20260101T000000Z-bbbbbb", "[]")
    _mk(tmp_path, "20260101T000002Z-cccccc", "42")
    _mk(tmp_path, good, json.dumps({"run_id": good, "started": "2026-01-01T00:00:01"}))
    runs = tracing.list_runs(directory=str(tmp_path))
    assert [r["run_id"] for r in runs] == [good]


def test_load_run_skips_non_object_trace_lines(tmp_path):
    rid = "20260101T000003Z-dddddd"
    trace = (
        '{"type": "span", "id": "s1", "parent": null, "name": "x"}\n'
        "[1, 2]\n"
        "42\n"
        '{"type": "usage", "span": "s1", "tokens": {"total": 3}}\n'
    )
    _mk(tmp_path, rid, json.dumps({"run_id": rid}), trace)
    run = tracing.load_run(rid, directory=str(tmp_path))
    assert [s["id"] for s in run["spans"]] == ["s1"]
    assert len(run["usage"]) == 1


def test_load_run_non_object_summary_returns_none(tmp_path):
    rid = "20260101T000004Z-eeeeee"
    _mk(tmp_path, rid, "[]")
    assert tracing.load_run(rid, directory=str(tmp_path)) is None


def test_input_label_relative_files_match_dashboard():
    # R3-FEAT-4: relative multi-file inputs were labelled "/ (2 files)".
    from bluecell.tracing import input_label
    assert input_label(["a.log", "b.log"]) == "a.log +1"
    assert input_label(["/x/logs/a.log", "/x/logs/b.log"]) == "logs/ (2 files)"
