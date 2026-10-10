"""R3-FEAT-5/6: intel search --limit must be positive; intel add --id must not be empty."""
import pytest

from bastion import cli


def test_negative_limit_rejected(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["intel", "--intel-db", str(tmp_path / "i.json"), "search", "x", "--limit", "-1"])


def test_empty_id_rejected(tmp_path, capsys):
    db = tmp_path / "i.json"
    rc = cli.main(["intel", "--intel-db", str(db), "add", "--id", "", "--title", "T"])
    assert rc == 2 and "must not be empty" in capsys.readouterr().err
    assert not db.exists()
