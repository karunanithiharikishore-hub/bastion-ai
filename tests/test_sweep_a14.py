# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-14 regression: defanged / Unicode-dot indicators must be checked, while
ordinary prose that uses the word "dot" must not create IOCs."""
import pytest

from bluecell.agents.grounding import check_text, evidence_index


def _unverified(text):
    return check_text(text, evidence_index([], []))["unverified"]


@pytest.mark.parametrize("text, kind", [
    ("from 203.0.113 dot 99", "ips"),
    ("from 203[ . ]0[ . ]113[ . ]9", "ips"),
    ("beacon to c2 dot badsite dot ru", "domains"),
    ("beacon to c2．badsite．ru", "domains"),   # fullwidth full stop
    ("from 203。0。113。9", "ips"),         # ideographic full stop
    ("beacon to bad%2Eru", "domains"),
    ("beacon to bad\\.ru", "domains"),
    ("beacon to c2[dot]badsite[dot]ru", "domains"),     # existing forms still work
])
def test_defanged_variants_are_checked(text, kind):
    assert kind in _unverified(text), text


@pytest.mark.parametrize("text", [
    "the dot product is red",
    "click dot in the menu",
    "the dot is red",
    "step 2 dot release notes",
])
def test_prose_dot_creates_no_indicator(text):
    assert _unverified(text) == {}, text
