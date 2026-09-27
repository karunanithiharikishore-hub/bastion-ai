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


def test_enforce_is_non_fatal_and_warns_on_tamper(monkeypatch, capsys):
    # Attribution is enforced by the LICENSE, not a runtime kill-switch:
    # enforce() must NOT exit; it only warns.
    monkeypatch.setattr(provenance, "AUTHOR", "Someone Else")
    provenance.enforce(strict=True)   # must not raise
    err = capsys.readouterr().err
    assert "attribution" in err.lower()


def test_enforce_silent_when_intact(capsys):
    provenance.enforce(strict=True)
    assert capsys.readouterr().err == ""


def test_scan_repo_finds_author_in_source():
    # On a pristine checkout, no watermark files should be missing the author.
    assert provenance.scan_repo() == []


def test_banner_contains_author():
    assert "Harikishore Karunanithi" in provenance.banner()
