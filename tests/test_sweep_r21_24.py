"""ITEM-21..24: CLI output encoding, empty-input warning, malformed run summaries,
blank model ids. No real model calls: --llm off and fake summary files only."""
import io
import json
import os

import pytest

from bastion import cli


def _verdict_result():
    return {"incidents": [{
        "verdict": {"level": "likely-malicious", "confidence": 0.9, "headline": "brute force"},
        "storyline": {"structured": {"incident_id": "INC-1"}},
    }]}


def test_item21_verdicts_print_on_ascii_stdout(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii")  # like PYTHONIOENCODING=ascii
    monkeypatch.setattr("sys.stdout", stream)
    cli._print_verdicts(_verdict_result())   # must not raise UnicodeEncodeError
    stream.flush()
    assert b"INC-1" in raw.getvalue()


def test_item22_empty_input_warns_on_stderr(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    args = cli.build_parser().parse_args(
        ["analyze", str(empty), "--llm", "off", "--no-agents", "--no-trace", "--no-cache",
         "--intel-db", str(tmp_path / "intel.json")])
    assert cli.cmd_analyze(args) == 0
    assert "nothing was analysed" in capsys.readouterr().err


def _write_run(runs, run_id, summary):
    d = runs / run_id
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps(summary), encoding="utf-8")


def test_item23_runs_list_survives_scalar_tokens(tmp_path, monkeypatch, capsys):
    runs = tmp_path / "runs"
    monkeypatch.setenv("BASTION_RUNS_DIR", str(runs))
    _write_run(runs, "20260101T000000Z-aaaaaa", {"run_id": "20260101T000000Z-aaaaaa",
               "started": "2026-01-01T00:00:00Z", "inputs": ["a.log"], "tokens": 5})
    _write_run(runs, "20260101T000001Z-bbbbbb", {"run_id": "20260101T000001Z-bbbbbb",
               "started": "2026-01-01T00:00:01Z", "inputs": ["b.log"],
               "tokens": {"total": 7}})
    args = cli.build_parser().parse_args(["runs"])
    assert cli.cmd_runs(args) == 0
    out = capsys.readouterr().out
    assert "20260101T000000Z-aaaaaa" in out and "20260101T000001Z-bbbbbb" in out


def test_item23_runs_show_survives_bad_shapes(tmp_path, monkeypatch, capsys):
    runs = tmp_path / "runs"
    monkeypatch.setenv("BASTION_RUNS_DIR", str(runs))
    rid = "20260101T000000Z-cccccc"
    _write_run(runs, rid, {"run_id": rid, "inputs": [1, 2], "tokens": 5})
    args = cli.build_parser().parse_args(["runs", "show", rid])
    assert cli.cmd_runs(args) == 0
    assert "inputs: 1, 2" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["analyze", "x.log", "--model", ""],
    ["analyze", "x.log", "--model", "   "],
    ["analyze", "x.log", "--model-tier1", "   "],
    ["analyze", "x.log", "--model", "claude sonnet"],
    ["eval", "--model", ""],
    ["eval", "--model-tier1", ""],
    ["serve", "x.log", "--model", ""],
    ["serve", "x.log", "--model-tier1", " "],
])
def test_item24_blank_or_spaced_model_rejected(argv, capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(argv)
    assert "model" in capsys.readouterr().err


def test_item24_real_model_id_still_accepted():
    args = cli.build_parser().parse_args(
        ["analyze", "x.log", "--model", "claude-sonnet-5", "--model-tier1", "claude-haiku-4-5"])
    assert args.model == "claude-sonnet-5" and args.model_tier1 == "claude-haiku-4-5"
