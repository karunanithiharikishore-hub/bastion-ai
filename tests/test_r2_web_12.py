"""BUG-WEB-12 / BUG-WEB-6 (cli part) / BUG-FEAT-6 (runs column): CLI regressions."""
import pytest

from bluecell import cli, tracing

USAGE = {"input_tokens": 1000, "output_tokens": 1000}


def test_eval_zero_cases_exits_2_and_prints_no_none_duration(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BLUECELL_RUNS_DIR", str(tmp_path / "runs"))
    empty = tmp_path / "cases"
    empty.mkdir()
    rc = cli.main(["eval", "--cases", str(empty), "--no-trace", "--llm", "off"])
    out = capsys.readouterr()
    assert rc == 2
    assert "mean duration None" not in out.out + out.err
    assert "no eval cases found" in out.err


@pytest.mark.parametrize("value", ["10000000000000000000", "5270401"])
def test_window_above_bound_is_argparse_error(value, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(["analyze", "x.log", "--window", value])
    assert exc.value.code == 2
    assert "window must be at most" in capsys.readouterr().err


def test_window_at_bound_is_accepted():
    args = cli.build_parser().parse_args(["analyze", "x.log", "--window", "5270400"])
    assert args.window == 5270400


def _runs_output(monkeypatch, capsys, summary):
    monkeypatch.setattr(tracing, "list_runs", lambda limit=20: [summary])
    assert cli.main(["runs"]) == 0
    return capsys.readouterr().out


def test_runs_unknown_cost_shows_na_not_zero(monkeypatch, capsys):
    t = tracing.Tracer(persist=False)
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    out = _runs_output(monkeypatch, capsys, t.summary())
    assert "n/a" in out
    assert "0.0000" not in out


def test_runs_partial_cost_shows_lower_bound(monkeypatch, capsys):
    t = tracing.Tracer(persist=False)
    t.record_usage(USAGE, model="claude-haiku-5-5")
    t.record_usage(None, model="claude-haiku-5-5", source="cli")
    out = _runs_output(monkeypatch, capsys, t.summary())
    assert ">= " in out
    assert "n/a" not in out


def test_runs_known_cost_unchanged(monkeypatch, capsys):
    t = tracing.Tracer(persist=False)
    t.record_usage(USAGE, model="claude-haiku-5-5")
    out = _runs_output(monkeypatch, capsys, t.summary())
    assert "n/a" not in out and ">=" not in out
    assert f"{tracing.estimate_cost(USAGE, 'claude-haiku-5-5'):.4f}" in out
