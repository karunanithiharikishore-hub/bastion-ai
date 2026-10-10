# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
from bastion.models import Event
from bastion.agents.analyst import build_evidence_brief, _extract_json, ai_analyze
from bastion.agents.grounding import evidence_index, check_text
from bastion.pipeline import extract_iocs


def _events():
    e1 = Event(ts="2026-08-27T00:20:00Z", source="azure_ad", category="authentication",
               action="login_success", message="Azure AD sign-in Success for analyst@example.com from 203.0.113.10 transfer=deviceCodeFlow device=d95",
               user="analyst@example.com", src_ip="203.0.113.10")
    e1.tags.append("azure:devicecode-success"); e1.attack.append("T1078")
    e2 = Event(ts="2026-08-28T00:00:00Z", source="m365_ual", category="other",
               action="mailbox_access", message="UAL MailItemsAccessed by analyst@example.com from 203.0.113.10",
               user="analyst@example.com", src_ip="203.0.113.10"); e2.attack.append("T1114")
    e3 = Event(ts="2026-08-28T00:05:00Z", source="m365_ual", category="other",
               action="inbox_rule_created", message="UAL New-InboxRule by analyst@example.com from 203.0.113.10",
               user="analyst@example.com", src_ip="203.0.113.10"); e3.attack.append("T1564.008")
    return [e1, e2, e3]


def test_brief_surfaces_key_signals():
    ev = _events()
    brief = build_evidence_brief(ev, extract_iocs(ev))
    assert "DEVICE-CODE-FLOW SUCCESSES" in brief
    assert "MAILBOX ACCESS" in brief
    assert "INBOX RULE" in brief
    assert "203.0.113.10" in brief


def test_extract_json_from_noisy_text():
    assert _extract_json('blah {"verdict":"likely-malicious"} tail')["verdict"] == "likely-malicious"
    assert _extract_json("no json here") is None


def test_grounding_allows_user_email_domain():
    ev = _events()
    idx = evidence_index(ev, ["T1114"])
    # The account's own domain must NOT be flagged as hallucinated.
    res = check_text("Compromise of analyst@example.com via example.com tenant.", idx)
    assert "domains" not in res["unverified"]


def test_ai_analyze_without_backbone_is_safe():
    ev = _events()
    out = ai_analyze(ev, extract_iocs(ev), backbone=None)
    assert out["available"] is False


class _CapturingBackbone:
    def __init__(self):
        self.prompts = []

    def complete(self, prompt, system=None, max_tokens=0):
        self.prompts.append(prompt)
        if "LEAD ANALYST JSON" in prompt:
            return '{"agree": true, "corrected_verdict": "likely-benign", "confidence": 0.8, "notes": "ok"}'
        return ('{"verdict": "likely-benign", "confidence": 0.8, "headline": "h", '
                '"tier2_assessment": "agree"}')


def test_ai_analyze_shows_tier2_verdict_with_cited_events():
    ev = _events()
    verdict = {"incident_id": "INC-1", "status": "dismissed", "confidence": 0.9,
               "rationale": "Approved change window.", "evidence": [ev[2].event_id, "bogus"]}
    bb = _CapturingBackbone()
    out = ai_analyze(ev, extract_iocs(ev), bb, tier2_verdicts=[verdict])
    lead_prompt, review_prompt = bb.prompts
    for p in (lead_prompt, review_prompt):
        assert "TIER-2 ANALYST VERDICTS" in p and "NOT evidence" in p
        assert "INC-1: DISMISSED (confidence 0.9)" in p
        assert "Approved change window." in p
        assert ev[2].event_id in p and "New-InboxRule" in p   # the cited event line
        assert "bogus" not in p                               # unknown ids are dropped
    assert out["tier2_verdicts_seen"] == 1
    assert out["final_verdict"] == "likely-benign"


def test_ai_analyze_without_tier2_has_no_tier2_section():
    ev = _events()
    bb = _CapturingBackbone()
    out = ai_analyze(ev, extract_iocs(ev), bb)
    assert all("TIER-2 ANALYST VERDICTS" not in p for p in bb.prompts)
    assert out["tier2_verdicts_seen"] == 0
