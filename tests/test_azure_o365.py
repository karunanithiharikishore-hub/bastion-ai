# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
from bluecell.ingest import ingest_path, detect_source
from bluecell.ingest.parsers import parse_azure_signin, parse_o365_message
from bluecell.pipeline import normalize, map_attack, correlate
from bluecell.report.rca import deterministic_storyline


def test_detect_azure_signin_by_filename():
    assert detect_source("InteractiveSignIns_2026-08-24_2026-09-22.csv") == "signins"
    assert detect_source("NonInteractiveSignIns_2026.csv") == "signins"
    assert detect_source("MSISignIns_2026.csv") == "signins"


def test_detect_o365_by_filename():
    assert detect_source("MessageTraceResult.csv") == "messagetrace"
    assert detect_source("MTSummary_Message trace report.csv") == "messagetrace"


def test_azure_signin_failure_maps_bruteforce():
    ev = parse_azure_signin({
        "Date (UTC)": "2026-09-20T08:00:00Z", "User": "admin@corp.com",
        "IP address": "203.0.113.9", "Status": "Failure",
        "Sign-in error code": "50126", "Failure reason": "Invalid username or password",
        "Location": "RU", "Application": "Office 365",
    })
    assert ev.category == "authentication"
    assert ev.action == "login_failed"
    assert ev.user == "admin@corp.com"
    assert ev.src_ip == "203.0.113.9"
    map_attack([ev])
    assert "T1110" in ev.attack


def test_azure_signin_success_and_risky_tags_valid_accounts():
    ev = parse_azure_signin({
        "Date (UTC)": "2026-09-20T08:05:00Z", "User": "admin@corp.com",
        "IP address": "203.0.113.9", "Status": "Success", "Sign-in error code": "0",
        "Risk level during sign-in": "high", "Risk state": "atRisk",
    })
    assert ev.action == "login_success"
    assert ev.severity == 4
    assert "T1078" in ev.attack


def test_azure_column_shape_detection_without_source_field():
    rec = {"Date (UTC)": "x", "User": "a", "IP address": "1.2.3.4", "Status": "Success"}
    assert detect_source("random_export.csv", rec) == "signins"


def test_o365_message_parses():
    ev = parse_o365_message({
        "origin_timestamp_utc": "2026-09-20T08:00:00Z",
        "sender_address": "attacker@evil.com", "recipient_address": "cfo@corp.com",
        "subject": "Invoice", "status": "Delivered",
    })
    assert ev.source == "o365"
    assert ev.user == "attacker@evil.com"
    assert "cfo@corp.com" in ev.message


def test_azure_end_to_end_incident_and_summary(tmp_path):
    # Brute force burst then a successful risky login from same IP/user.
    rows = ["Date (UTC),User,IP address,Status,Sign-in error code,Failure reason,Risk level during sign-in"]
    for i in range(6):
        rows.append(f"2026-09-20T08:0{i}:00Z,admin@corp.com,203.0.113.9,Failure,50126,Invalid password,")
    rows.append("2026-09-20T08:07:00Z,admin@corp.com,203.0.113.9,Success,0,,high")
    p = tmp_path / "InteractiveSignIns_test.csv"
    p.write_text("\n".join(rows), encoding="utf-8")

    events = normalize(ingest_path(str(p)))
    assert len(events) == 7
    map_attack(events)
    incs = correlate(events, window_minutes=120)
    assert incs, "expected an incident from the brute-force + success"
    story = deterministic_storyline(incs[0])
    # attack_summary present and populated
    a = story["attack_summary"]
    assert a["how_they_got_in"]
    assert isinstance(a["what_they_did"], list) and a["what_they_did"]
    # phases expose per-phase events for the clickable drawer
    assert story["phases"] and story["phases"][0]["events"]


def test_verdict_benign_for_failed_logins_only(tmp_path):
    from bluecell.report.rca import assess_incident
    rows = ["Date (UTC),User,IP address,Status,Sign-in error code"]
    for i in range(20):
        rows.append(f"2026-09-20T08:{i:02d}:00Z,user@corp.com,203.0.113.9,Failure,50126")
    p = tmp_path / "NonInteractiveSignIns_x.csv"
    p.write_text("\n".join(rows), encoding="utf-8")
    events = normalize(ingest_path(str(p))); map_attack(events)
    inc = correlate(events, window_minutes=1440)[0]
    v = assess_incident(inc)
    assert v["level"] == "likely-benign"
    assert "noise" in v["headline"].lower()


def test_verdict_review_when_success_follows_failures(tmp_path):
    from bluecell.report.rca import assess_incident
    rows = ["Date (UTC),User,IP address,Status,Sign-in error code"]
    for i in range(10):
        rows.append(f"2026-09-20T08:{i:02d}:00Z,user@corp.com,203.0.113.9,Failure,50126")
    rows.append("2026-09-20T08:11:00Z,user@corp.com,203.0.113.9,Success,0")
    p = tmp_path / "InteractiveSignIns_x.csv"
    p.write_text("\n".join(rows), encoding="utf-8")
    events = normalize(ingest_path(str(p))); map_attack(events)
    inc = correlate(events, window_minutes=1440)[0]
    v = assess_incident(inc)
    assert v["level"] == "needs-review"


def test_verdict_malicious_for_multistage(tmp_path):
    # reuse the bundled samples multi-stage incident
    import os
    from conftest import SAMPLES
    from bluecell.report.rca import assess_incident
    events = normalize(ingest_path(SAMPLES)); map_attack(events)
    inc = correlate(events, window_minutes=120)[0]
    v = assess_incident(inc)
    assert v["level"] == "likely-malicious"
