# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
from bluecell.models import Event
from bluecell.agents.grounding import evidence_index, check_text, annotate


def _events():
    e = Event(ts="2026-09-26T09:00:00Z", source="dns", category="dns",
              action="dns_query", message="DNS query evil.top", domain="evil.top",
              src_ip="203.0.113.9", host="web01",
              file_hash="a" * 64)
    e.attack.append("T1071.004")
    return [e]


def test_grounded_text_passes():
    idx = evidence_index(_events(), ["T1071.004"])
    txt = "Host web01 queried evil.top from 203.0.113.9 (T1071.004)."
    assert check_text(txt, idx)["ok"] is True
    assert annotate(txt, idx) == txt   # unchanged


def test_hallucinated_ip_flagged():
    idx = evidence_index(_events(), ["T1071.004"])
    txt = "The attacker exfiltrated to 8.8.8.8 and 203.0.113.9."
    res = check_text(txt, idx)
    assert res["ok"] is False
    assert "8.8.8.8" in res["unverified"]["ips"]
    assert "203.0.113.9" not in res["unverified"].get("ips", [])  # real one not flagged
    assert "GROUNDING CHECK" in annotate(txt, idx)


def test_hallucinated_hash_flagged():
    idx = evidence_index(_events(), ["T1071.004"])
    fake = "b" * 64
    txt = f"Malware hash {fake} seen fleet-wide."
    res = check_text(txt, idx)
    assert fake in res["unverified"]["hashes"]


def test_hallucinated_technique_flagged():
    idx = evidence_index(_events(), ["T1071.004"])
    txt = "This shows ransomware T1486."
    res = check_text(txt, idx)
    assert "T1486" in res["unverified"]["techniques"]


def test_domain_subdomain_is_not_grounded():
    idx = evidence_index(_events(), ["T1071.004"])
    # a fabricated subdomain of an evidence domain is NOT grounded...
    res = check_text("Beacon to sub.evil.top observed.", idx)
    assert res["unverified"] == {"domains": ["sub.evil.top"]}
    # ...but a parent of an evidence domain still is.
    idx = evidence_index(_events(), ["T1071.004"])
    idx["domains"] = {"cdn.evil.top"}
    assert check_text("Beacon to evil.top observed.", idx)["ok"]


def test_file_names_are_not_treated_as_domains():
    from bluecell.models import Event
    from bluecell.agents.grounding import evidence_index, check_text
    e = Event(ts="2026-10-03T22:11:02Z", source="edr", category="process",
              action="process_create", message="wusa C:\\Installers\\KB5044284.msu /quiet",
              host="win-app02")
    idx = evidence_index([e], [])
    res = check_text("Installed via wusa.exe and verified with certutil.exe; "
                     "KB5044284.msu applied. Beacon to evil-c2.top.", idx)
    assert res["unverified"] == {"domains": ["evil-c2.top"]}   # only the real fake


def test_domains_mentioned_in_log_messages_are_grounded():
    from bluecell.models import Event
    from bluecell.agents.grounding import evidence_index, check_text
    e = Event(ts="2026-10-03T22:00:00Z", source="syslog", category="other",
              action="log", message="apt fetched from archive.ubuntu.com", host="app01")
    assert check_text("Patched from archive.ubuntu.com", evidence_index([e], []))["ok"]


def test_technique_flagged_even_when_logs_have_none():
    from bluecell.models import Event
    from bluecell.agents.grounding import evidence_index, check_text
    e = Event(ts="2026-10-03T22:00:00Z", source="syslog", category="other",
              action="log", message="routine", host="h1")
    res = check_text("Credential dumping via T1003 on h1", evidence_index([e], []))
    assert res["unverified"] == {"techniques": ["T1003"]}
