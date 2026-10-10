# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-16: IDN and punycode-TLD domains are grounded; common-word TLDs after a period are not domains."""
from bluecell.agents.grounding import evidence_index, check_text

PUNY = "xn--80ak6aa92e.xn--p1ai"      # an analyst-pasted punycode domain, no Unicode anywhere
IDN = "пример.рф"
IDN_PUNY = "xn--e1afmkfd.xn--p1ai"    # IDNA form of IDN


def _empty():
    return evidence_index([], [])


def test_punycode_tld_domain_is_flagged():
    assert check_text(f"beacon to {PUNY} every minute", _empty())["unverified"] == {"domains": [PUNY]}


def test_unicode_idn_domain_is_flagged_as_punycode():
    assert check_text(f"beacon to {IDN} every minute", _empty())["unverified"] == {"domains": [IDN_PUNY]}


def test_grounded_idn_domain_passes():
    from bluecell.models import Event
    e = Event(ts="2026-10-03T22:00:00Z", source="dns", category="dns",
              action="dns_query", message=f"DNS query {IDN} from 10.0.0.5", src_ip="10.0.0.5")
    idx = evidence_index([e], [])
    assert check_text(f"beacon to {IDN}", idx)["ok"]
    assert check_text(f"beacon to {IDN_PUNY}", idx)["ok"]


def test_capitalised_common_word_tld_after_period_is_not_a_domain():
    assert check_text("The check ends here.Top priority was the beacon.", _empty())["ok"]
    assert check_text("the note was sent.Cc the team", _empty())["ok"]


def test_lowercase_common_word_tld_is_still_a_domain():
    assert check_text("beacon to evil.top", _empty())["unverified"] == {"domains": ["evil.top"]}
