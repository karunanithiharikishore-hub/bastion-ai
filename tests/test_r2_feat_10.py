# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-FEAT-10: crashed eval runs count as wrong answers, never as passes."""
import json
import os

from bluecell import evals


def _fake(files, **kw):
    name = os.path.basename(os.path.dirname(files[0]))
    if name.startswith(("boom", "crash")):
        raise RuntimeError("analyzer crashed")
    if name.startswith("mal"):
        return {"incidents": [{"id": "i1", "verdict": {"level": "likely-malicious"}}]}
    return {"incidents": []}


def _suite(tmp_path, names_verdicts):
    for name, verdict in names_verdicts:
        d = tmp_path / name
        d.mkdir()
        (d / "a.log").write_text("x\n")
        (d / "expected.json").write_text(json.dumps({"verdict": verdict}))
    return str(tmp_path)


def test_crashed_malicious_run_is_a_false_negative_not_ignored(tmp_path):
    cases = _suite(tmp_path, [("crash_mal", "likely-malicious"), ("ben_case", "likely-benign")])
    rep = evals.run_eval(cases, analyze_fn=_fake)
    s = rep["summary"]
    assert s["run_errors"] == 1 and s["runs"] == 2
    assert s["malicious"]["fn"] == 1 and s["malicious"]["recall"] == 0.0
    assert s["accuracy"] == 0.5  # the crashed run is wrong, not dropped
    assert "1 run error(s)" in evals.format_report(rep)


def test_crashed_benign_run_lowers_accuracy_but_not_fp_or_tn(tmp_path):
    cases = _suite(tmp_path, [("boom_benign", "likely-benign"), ("mal_case", "likely-malicious")])
    s = evals.run_eval(cases, analyze_fn=_fake)["summary"]
    assert s["run_errors"] == 1
    assert s["accuracy"] == 0.5  # 1 correct (malicious) of 2 runs
    assert s["malicious"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 0,
                              "precision": 1.0, "recall": 1.0}
    assert s["false_positive_rate"] is None


def test_clean_run_prints_no_error_line(tmp_path):
    cases = _suite(tmp_path, [("mal_case", "likely-malicious")])
    rep = evals.run_eval(cases, analyze_fn=_fake)
    assert rep["summary"]["run_errors"] == 0
    assert "run error" not in evals.format_report(rep)
