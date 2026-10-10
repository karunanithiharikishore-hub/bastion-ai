"""ITEM-7: all-errored runs must print 'mean duration n/a', not 'None'.
ITEM-8: rules mode skips requires_llm cases and exits 0 when the rest pass."""
import json
import os

from bluecell import evals
from bluecell.cli import main

CASES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "evals", "cases")
LLM_CASES = ["approved_maintenance_chg0042117", "injection_benign_ignore_wording",
             "password_spray_entra", "psexec_change_window", "vuln_scanner_web"]


def test_all_runs_errored_prints_na_duration(tmp_path):
    case = tmp_path / "cases" / "bad"
    case.mkdir(parents=True)
    (case / "a.log").write_text("x\n")
    (case / "expected.json").write_text('{"verdict": "nope"}')
    rep = evals.run_eval(str(tmp_path / "cases"), llm="off")
    assert rep["summary"]["run_errors"] == 1
    text = evals.format_report(rep)
    assert "mean duration n/a ·" in text
    assert "mean duration None" not in text


def test_shipped_llm_cases_are_marked():
    for name in LLM_CASES:
        exp = evals.load_cases(CASES, [name])[0]["expected"]
        assert exp.get("requires_llm") is True, name


def test_rules_mode_skips_llm_cases_and_exits_0(tmp_path, capsys):
    out = tmp_path / "rep.json"
    rc = main(["eval", "--cases", CASES, "--llm", "off", "--no-trace", "--json", str(out)])
    assert rc == 0
    summary = json.loads(out.read_text())["summary"]
    assert summary["cases"] == 7 and summary["cases_failed"] == 0
    assert sorted(summary["skipped_requires_llm"]) == sorted(LLM_CASES)
    assert "skipped" in capsys.readouterr().out


def test_rules_mode_refuses_when_only_llm_cases_selected():
    try:
        evals.run_eval(CASES, names=[LLM_CASES[0]], llm="off", trace=False)
    except FileNotFoundError as exc:
        assert "requires an LLM" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")
