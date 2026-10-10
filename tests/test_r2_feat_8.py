"""BUG-FEAT-8: a valid-JSON but non-object expected.json is reported as an
invalid case instead of crashing the whole eval run."""
import json

from bastion import evals


def _case(tmp_path, payload_text):
    d = tmp_path / "cases" / "c1"
    d.mkdir(parents=True)
    (d / "expected.json").write_text(payload_text, encoding="utf-8")
    (d / "a.log").write_text("x\n", encoding="utf-8")
    return str(tmp_path / "cases")


def test_non_object_expected_is_a_problem_not_a_crash(tmp_path):
    cases_dir = _case(tmp_path, "[1, 2]")
    cases = evals.load_cases(cases_dir)
    assert cases[0]["expected"] == {}
    assert cases[0]["problems"] == ["expected.json must be a JSON object"]


def test_run_eval_survives_non_object_expected_and_fails_only_that_case(tmp_path):
    cases_dir = _case(tmp_path, "[1, 2]")
    good = tmp_path / "cases" / "c2"
    good.mkdir()
    (good / "expected.json").write_text(json.dumps({"verdict": "likely-benign"}))
    (good / "a.log").write_text("x\n", encoding="utf-8")

    def fake_analyze(files, **kw):
        return {"incidents": [], "meta": {}}

    report = evals.run_eval(cases_dir, analyze_fn=fake_analyze)
    by_name = {c["name"]: c for c in report["cases"]}
    bad = by_name["c1"]
    assert bad["passed"] is False
    assert bad["runs"][0]["error"] == "invalid expected.json: expected.json must be a JSON object"
    assert by_name["c2"]["passed"] is True
    assert report["summary"]["cases"] == 2
    assert report["summary"]["failed_cases"] == ["c1"]
    evals.format_report(report)  # text output must not crash either
