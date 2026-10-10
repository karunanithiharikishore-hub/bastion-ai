"""ITEM-20: an unwritable --output is rejected before the analysis runs, not after."""
import os

import pytest

from bluecell import cli


@pytest.fixture
def analysis_calls(monkeypatch, tmp_path):
    calls = []

    def fake_analyze(*a, **k):
        calls.append(k)
        raise RuntimeError("analysis ran")

    monkeypatch.setattr(cli, "analyze", fake_analyze)
    log = tmp_path / "in.log"
    log.write_text("x\n")
    return calls, str(log), str(tmp_path / "intel.json")


def _run(log, intel, output):
    args = cli.build_parser().parse_args(
        ["analyze", log, "--llm", "off", "--intel-db", intel, "-o", output])
    return cli.cmd_analyze(args)


def test_sweep_r20_output_is_existing_directory_rejected_before_analysis(tmp_path, analysis_calls):
    calls, log, intel = analysis_calls
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    assert _run(log, intel, str(outdir)) == 2
    assert calls == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write read-only files")
def test_sweep_r20_output_is_read_only_file_rejected_before_analysis(tmp_path, analysis_calls):
    calls, log, intel = analysis_calls
    ro = tmp_path / "report.md"
    ro.write_text("old\n")
    os.chmod(ro, 0o444)
    try:
        assert _run(log, intel, str(ro)) == 2
        assert calls == []
    finally:
        os.chmod(ro, 0o644)
