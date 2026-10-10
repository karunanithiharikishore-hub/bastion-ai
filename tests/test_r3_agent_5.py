# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""BUG-R3-AGENT-5: grounding must not reject legitimate finding text.

A version string ("Chrome 120.0.6.99") was read as an IPv4 address, and a missing
space after a period ("shell.Then", "T1059.Then") as a domain.
"""
from bastion.models import Event
from bastion.agents.grounding import evidence_index, check_text


def _idx():
    e = Event(ts="2026-10-03T22:00:00Z", source="dns", category="dns",
              action="dns_query", message="DNS query evil-c2.example.com from 10.0.0.5",
              domain="evil-c2.example.com", src_ip="10.0.0.5", host="web01")
    return evidence_index([e], ["T1059"])


def test_version_string_is_not_an_ip():
    assert check_text("Browser Chrome 120.0.6.99 used", _idx())["ok"]


def test_sentence_join_is_not_a_domain():
    assert check_text("Process spawned a shell.Then it beaconed.", _idx())["ok"]


def test_technique_id_join_is_not_a_domain():
    assert check_text("Kerberos ticket; see T1059.Then follow up", _idx())["ok"]


def test_real_iocs_are_still_flagged():
    res = check_text("Hosts 8.8.8.8 via evil.ru; Chrome 120.0.6.99 used.", _idx())
    assert res["unverified"] == {"ips": ["8.8.8.8"], "domains": ["evil.ru"]}


def test_real_evidence_ioc_is_still_grounded():
    assert check_text("Beacon to evil-c2.example.com from 10.0.0.5.", _idx())["ok"]
