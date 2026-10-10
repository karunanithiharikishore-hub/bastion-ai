"""ITEM-5: an explicit --llm api|cli with no backbone must fail, not score rules and pass."""
import json
import os

import pytest

from bastion import evals
from bastion.cli import main
from bastion.llm.backbone import LLMBackbone

CASES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "evals", "cases")


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("BASTION_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("BASTION_RUNS_DIR", str(tmp_path / "runs"))
    # no `claude` CLI either: the backbone must be genuinely unavailable
    monkeypatch.setattr(LLMBackbone, "_cli_available", lambda self: False)


@pytest.mark.parametrize("mode", ["api", "cli"])
def test_cli_explicit_backbone_missing_exits_2_and_writes_no_report(tmp_path, mode, capsys):
    out = tmp_path / "rep.json"
    rc = main(["eval", "--cases", CASES, "--case", "apt_chain_web01", "--no-trace",
               "--llm", mode, "--json", str(out)])
    assert rc == 2
    assert not out.exists()
    assert "backbone" in capsys.readouterr().err


def test_cli_auto_still_degrades_to_rules(tmp_path):
    out = tmp_path / "rep.json"
    rc = main(["eval", "--cases", CASES, "--case", "apt_chain_web01", "--no-trace",
               "--llm", "auto", "--json", str(out)])
    assert rc == 0
    cfg = json.loads(out.read_text())["config"]
    assert cfg["llm"] == "off"
    assert cfg["backbone"].startswith("none")


def test_report_records_effective_mode_not_requested(tmp_path):
    rep = evals.run_eval(CASES, names=["apt_chain_web01"], llm="api", backbone=None,
                         trace=False)
    assert rep["config"]["llm"] == "off"
    assert rep["config"]["backbone"].startswith("none")
