# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-15: a title-cased known TLD after a lowercase label is a domain, not a sentence join."""
from bastion.models import Event
from bastion.agents.grounding import evidence_index, check_text


def _idx():
    e = Event(ts="2026-10-03T22:00:00Z", source="dns", category="dns",
              action="dns_query", message="DNS query evil-c2.example.com from 10.0.0.5",
              domain="evil-c2.example.com", src_ip="10.0.0.5", host="web01")
    return evidence_index([e], ["T1059"])


def test_title_cased_tld_is_flagged():
    assert check_text("beacon to c2.badsite.Com", _idx())["unverified"] == {"domains": ["c2.badsite.com"]}


def test_title_cased_tld_matches_lowercase_result():
    idx = _idx()
    assert check_text("beacon to c2.badsite.Com", idx)["unverified"] == check_text("beacon to c2.badsite.com", idx)["unverified"]


def test_sentence_word_after_period_still_skipped():
    assert check_text("Process spawned a shell.Then it beaconed.", _idx())["ok"]
