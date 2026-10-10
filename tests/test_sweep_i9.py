"""ITEM-9: Azure MFA/KMSI interrupts (50074, 50140, ...) are not password
failures: no login_failed, no T1110, tagged azure:mfa-interrupt."""
from bluecell.ingest.parsers import parse_azure_signin
from bluecell.pipeline.attack import map_attack


def test_mfa_interrupt_codes_are_not_login_failed_or_t1110():
    for code in ("50074", "50076", "50072", "50140", "50058"):
        row = {"Date (UTC)": "2026-10-03T09:00:00Z", "User": "a@x.com",
               "IP address": "198.51.100.7", "Status": "Interrupted",
               "Sign-in error code": code, "Failure reason": "Strong Authentication is required."}
        e = parse_azure_signin(row)
        map_attack([e])
        assert e.action != "login_failed", code
        assert "T1110" not in e.attack, code
        assert "azure:mfa-interrupt" in e.tags, code


def test_interrupt_then_success_yields_no_failed_login():
    rows = [{"Date (UTC)": "2026-10-03T09:00:00Z", "User": "a@x.com", "IP address": "198.51.100.7",
             "Status": "Interrupted", "Sign-in error code": "50074"},
            {"Date (UTC)": "2026-10-03T09:00:30Z", "User": "a@x.com", "IP address": "198.51.100.7",
             "Status": "Success", "Sign-in error code": "0"}]
    events = [parse_azure_signin(r) for r in rows]
    assert [e.action for e in events if e.action == "login_failed"] == []
    assert events[1].action == "login_success"


def test_real_password_failure_still_login_failed_t1110():
    row = {"Date (UTC)": "2026-10-03T09:00:00Z", "User": "a@x.com", "IP address": "198.51.100.7",
           "Status": "Failure", "Sign-in error code": "50126", "Failure reason": "Invalid username or password."}
    e = parse_azure_signin(row)
    map_attack([e])
    assert e.action == "login_failed"
    assert "T1110" in e.attack
