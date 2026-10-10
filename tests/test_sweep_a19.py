# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-19 regression: SHA-224 (56 hex) and SHA-384 (96 hex) digests must be
extracted and grounded like the other hash lengths."""
from bastion.agents.grounding import check_text, evidence_index
from bastion.models import Event


def _idx():
    e = Event(ts="2026-10-01T00:00:00Z", source="s", category="process",
              action="a", message="ran payload " + "d" * 64)
    return evidence_index([e], [])


def test_fake_sha224_and_sha384_flagged():
    res = check_text("dropper hash " + "a" * 56 + " and " + "b" * 96, _idx())
    assert res["ok"] is False
    assert res["unverified"]["hashes"] == sorted(["a" * 56, "b" * 96])


def test_grounded_sha384_passes():
    e = Event(ts="2026-10-01T00:00:00Z", source="s", category="process",
              action="a", message="file " + "c" * 96)
    idx = evidence_index([e], [])
    assert check_text("hash " + "c" * 96, idx)["ok"] is True


def test_existing_hash_lengths_still_handled():
    idx = _idx()
    assert check_text("x " + "d" * 64, idx)["ok"] is True          # grounded SHA-256
    res = check_text("x " + "e" * 32 + " " + "f" * 40 + " " + "1" * 128, idx)
    assert set(res["unverified"]["hashes"]) == {"e" * 32, "f" * 40, "1" * 128}
