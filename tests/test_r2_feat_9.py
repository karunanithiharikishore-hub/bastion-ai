# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-FEAT-9: an empty suite and a case with a misnamed label file must not pass."""
import json

import pytest

from bluecell import evals
from bluecell.cli import main


def _fake(files, **kw):
    return {"incidents": [], "meta": {}}


def test_misnamed_label_file_is_an_invalid_case(tmp_path):
    d = tmp_path / "typo_case"
    d.mkdir()
    (d / "nginx_access.log").write_text("x\n")
    (d / "expected.jsno").write_text("{}")
    cases = evals.load_cases(str(tmp_path))
    assert [c["name"] for c in cases] == ["typo_case"]
    assert cases[0]["problems"] and "expected.json" in cases[0]["problems"][0]
    rep = evals.run_eval(str(tmp_path), analyze_fn=_fake)
    assert rep["summary"]["cases"] == 1 and rep["summary"]["cases_failed"] == 1
    assert "expected.json" in rep["cases"][0]["runs"][0]["error"]


def test_dir_without_logs_or_label_is_still_ignored(tmp_path):
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyc").write_text("")
    good = tmp_path / "ok"
    good.mkdir()
    (good / "a.log").write_text("x\n")
    (good / "expected.json").write_text(json.dumps({"verdict": "likely-benign"}))
    assert [c["name"] for c in evals.load_cases(str(tmp_path))] == ["ok"]


def test_empty_cases_dir_is_an_error_not_a_pass(tmp_path):
    with pytest.raises(FileNotFoundError, match="no eval cases"):
        evals.run_eval(str(tmp_path), analyze_fn=_fake)


def test_cli_empty_and_misnamed_cases_exit_non_zero(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["eval", "--cases", str(empty), "--llm", "off", "--no-trace"]) != 0
    bad = tmp_path / "bad"
    (bad / "case").mkdir(parents=True)
    (bad / "case" / "a.log").write_text("x\n")
    (bad / "case" / "expected.jsno").write_text("{}")
    assert main(["eval", "--cases", str(bad), "--llm", "off", "--no-trace"]) == 1
