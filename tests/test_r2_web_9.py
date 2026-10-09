"""BUG-WEB-9 -- `serve` must reject out-of-range --port and --max-upload-mb < 1 at argparse
time (exit 2, clean message) instead of a bind traceback or a silent coercion to 1 MB."""
import pytest

from bluecell.cli import build_parser

SAMPLES = "samples"


@pytest.mark.parametrize("bad", ["0", "-1", "65536", "99999"])
def test_serve_port_out_of_range_rejected(bad, capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["serve", SAMPLES, "--port", bad])
    assert exc.value.code == 2
    assert "port must be 1-65535" in capsys.readouterr().err


@pytest.mark.parametrize("ok", ["1", "8787", "65535"])
def test_serve_port_in_range_accepted(ok):
    args = build_parser().parse_args(["serve", SAMPLES, "--port", ok])
    assert args.port == int(ok)


@pytest.mark.parametrize("bad", ["0", "-5"])
def test_serve_max_upload_mb_below_one_rejected(bad, capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["serve", SAMPLES, "--max-upload-mb", bad])
    assert exc.value.code == 2
    assert "must be at least 1" in capsys.readouterr().err


def test_serve_max_upload_mb_default_and_valid():
    assert build_parser().parse_args(["serve", SAMPLES]).max_upload_mb == 256
    assert build_parser().parse_args(["serve", SAMPLES, "--max-upload-mb", "2"]).max_upload_mb == 2
