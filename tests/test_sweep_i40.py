"""ITEM-40: Windows 4776 (NTLM) / 4768 / 4769 outcomes come from Status; 4740 is a lockout (T1110)."""
from bluecell.ingest.loader import ingest_file
from bluecell.ingest.parsers import parse_edr
from bluecell.pipeline.attack import map_attack

HDR = "TimeGenerated [UTC],Computer,EventID,Account,Activity,IpAddress,Status,LogonType"


def _load(tmp_path, rows):
    p = tmp_path / "SecurityEvent.csv"
    p.write_text("\n".join([HDR] + rows) + "\n")
    return map_attack(ingest_file(str(p)))


def test_six_4776_failures_from_one_ip_are_authentication_and_t1110(tmp_path):
    rows = [f"2026-10-03T22:00:0{i}Z,DC01,4776,CORP\\admin,4776 - The computer attempted to validate the credentials for an account,203.0.113.7,0xC000006A,3"
            for i in range(6)]
    evs = _load(tmp_path, rows)
    assert len(evs) == 6
    for e in evs:
        assert (e.category, e.action, e.src_ip) == ("authentication", "login_failed", "203.0.113.7")
        assert "T1110" in e.attack


def test_4776_success_is_login_success_not_t1110(tmp_path):
    ev = _load(tmp_path, ["2026-10-03T22:00:00Z,DC01,4776,CORP\\admin,4776 - credentials validated,203.0.113.7,0x0,3"])[0]
    assert (ev.category, ev.action) == ("authentication", "login_success")
    assert "T1110" not in ev.attack


def test_4740_lockout_is_authentication_and_t1110(tmp_path):
    ev = _load(tmp_path, ["2026-10-03T22:00:00Z,DC01,4740,CORP\\bob,4740 - A user account was locked out,203.0.113.7,,3"])[0]
    assert ev.category == "authentication"
    assert "lockout" in ev.action
    assert "T1110" in ev.attack


def test_4768_and_4769_failure_status_is_login_failed():
    for eid in ("4768", "4769"):
        ev = parse_edr({"TimeGenerated": "2026-10-03T22:00:00Z", "Computer": "DC01", "EventID": eid,
                        "Account": "CORP\\bob", "Status": "0x6", "IpAddress": "203.0.113.7"})
        map_attack([ev])
        assert (ev.category, ev.action) == ("authentication", "login_failed"), eid
        assert "T1110" in ev.attack, eid


def test_4769_success_is_not_a_sign_in():
    ev = parse_edr({"TimeGenerated": "2026-10-03T22:00:00Z", "Computer": "DC01", "EventID": "4769",
                    "Account": "CORP\\bob", "Status": "0x0", "IpAddress": "203.0.113.7"})
    assert ev.category != "authentication"
