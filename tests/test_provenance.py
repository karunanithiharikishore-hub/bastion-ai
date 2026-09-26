# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
import importlib

import pytest

from bluecell import provenance


def test_author_is_correct():
    assert provenance.AUTHOR == "Harikishore Karunanithi"
    assert "Harikishore-Karunanithi" in provenance.WATERMARK


def test_integrity_ok_on_pristine_tree():
    ok, reason = provenance.verify_integrity()
    assert ok, reason


def test_signature_matches_expected():
    assert provenance.signature() == provenance.EXPECTED_SIGNATURE


def test_tamper_author_detected(monkeypatch):
    monkeypatch.setattr(provenance, "AUTHOR", "Someone Else")
    ok, reason = provenance.verify_integrity()
    assert not ok
    assert "AUTHOR" in reason or "signature" in reason.lower()


def test_enforce_halts_on_tamper(monkeypatch, capsys):
    monkeypatch.setattr(provenance, "AUTHOR", "Someone Else")
    with pytest.raises(SystemExit) as exc:
        provenance.enforce(strict=False)
    assert exc.value.code == 3
    err = capsys.readouterr().err
    assert "HALTED" in err
    # It must point the owner to where the watermark lives.
    assert "provenance.py" in err


def test_scan_repo_finds_author_in_source():
    # On a pristine checkout, no watermark files should be missing the author.
    assert provenance.scan_repo() == []


def test_banner_contains_author():
    assert "Harikishore Karunanithi" in provenance.banner()
