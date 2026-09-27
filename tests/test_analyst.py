# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
from bluecell.models import Event
from bluecell.agents.analyst import build_evidence_brief, _extract_json, ai_analyze
from bluecell.agents.grounding import evidence_index, check_text
from bluecell.pipeline import extract_iocs


def _events():
    e1 = Event(ts="2026-08-27T00:20:00Z", source="azure_ad", category="authentication",
               action="login_success", message="Azure AD sign-in Success for a@corp.com from 85.209.87.73 transfer=deviceCodeFlow device=d95",
               user="a@corp.com", src_ip="85.209.87.73")
    e1.tags.append("azure:devicecode-success"); e1.attack.append("T1078")
    e2 = Event(ts="2026-08-28T00:00:00Z", source="m365_ual", category="other",
               action="mailbox_access", message="UAL MailItemsAccessed by a@corp.com from 85.209.87.73",
               user="a@corp.com", src_ip="85.209.87.73"); e2.attack.append("T1114")
    e3 = Event(ts="2026-08-28T00:05:00Z", source="m365_ual", category="other",
               action="inbox_rule_created", message="UAL New-InboxRule by a@corp.com from 85.209.87.73",
               user="a@corp.com", src_ip="85.209.87.73"); e3.attack.append("T1564.008")
    return [e1, e2, e3]


def test_brief_surfaces_key_signals():
    ev = _events()
    brief = build_evidence_brief(ev, extract_iocs(ev))
    assert "DEVICE-CODE-FLOW SUCCESSES" in brief
    assert "MAILBOX ACCESS" in brief
    assert "INBOX RULE" in brief
    assert "85.209.87.73" in brief


def test_extract_json_from_noisy_text():
    assert _extract_json('blah {"verdict":"likely-malicious"} tail')["verdict"] == "likely-malicious"
    assert _extract_json("no json here") is None


def test_grounding_allows_user_email_domain():
    ev = _events()
    idx = evidence_index(ev, ["T1114"])
    # The account's own domain must NOT be flagged as hallucinated.
    res = check_text("Compromise of a@corp.com via corp.com tenant.", idx)
    assert "domains" not in res["unverified"]


def test_ai_analyze_without_backbone_is_safe():
    ev = _events()
    out = ai_analyze(ev, extract_iocs(ev), backbone=None)
    assert out["available"] is False
