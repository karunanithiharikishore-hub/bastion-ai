"""BUG-WEB-11 -- `analyze` and `plan` must reject unknown --source values with an
argparse error (rc 2) that lists the valid names, including the aliases."""
import pytest

from bastion.cli import build_parser, main


@pytest.mark.parametrize("cmd", ["analyze", "plan"])
def test_unknown_source_is_rejected_with_valid_list(cmd, tmp_path, capsys):
    (tmp_path / "x.log").write_text("hello\n")
    with pytest.raises(SystemExit) as exc:
        main([cmd, str(tmp_path), "--llm", "off", "--source", "bogus"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice: 'bogus'" in err
    for name in ("edr", "endpoint", "router", "cloudtrail", "syslog"):
        assert f"'{name}'" in err


@pytest.mark.parametrize("name", ["edr", "endpoint", "dns", "network", "firewall",
                                  "router", "switch", "cloud", "cloudtrail", "auth",
                                  "syslog", "signins", "ual"])
def test_known_sources_parse_and_are_lowercased(name):
    parser = build_parser()
    for cmd in ("analyze", "plan"):
        args = parser.parse_args([cmd, "samples", "--source", name.upper()])
        assert args.source == name
