"""BUG-WEB-8 -- `eval --json <unwritable path>` must fail fast with "[bastion] ..." and rc 2,
not print a traceback after the whole eval has already run."""
from bastion.cli import main


def test_eval_json_missing_dir_fails_before_running(tmp_path, capsys):
    bad = tmp_path / "no_such_dir" / "x.json"
    rc = main(["eval", "--case", "stale_credential_activesync", "--json", str(bad),
               "--no-trace", "--llm", "off"])
    out, err = capsys.readouterr()
    assert rc == 2
    assert "[bastion] cannot write eval JSON" in err
    assert "Traceback" not in err
    assert out == ""  # precheck fires before the eval table is printed


def test_eval_json_write_oserror_returns_2(tmp_path, capsys):
    target = tmp_path / "is_a_dir"
    target.mkdir()  # parent exists, but the target cannot be opened for writing
    rc = main(["eval", "--case", "stale_credential_activesync", "--json", str(target),
               "--no-trace", "--llm", "off"])
    _, err = capsys.readouterr()
    assert rc == 2
    assert "[bastion] cannot write eval JSON" in err
    assert "Traceback" not in err
