"""ITEM-1: a Sentinel SecurityEvent export with Status/IpAddress columns must not be parsed as Azure sign-ins."""
from bastion.ingest.loader import ingest_file
from bastion.pipeline.attack import map_attack


def test_securityevent_with_status_column_is_windows_event_not_azure_signin(tmp_path):
    rows = ["TimeGenerated [UTC],Computer,EventID,Account,TargetUserName,Activity,IpAddress,Status,SubStatus,LogonType"]
    rows += [f"2026-10-03T22:0{i}:00Z,DC1,4625,CORP\\admin,admin,4625 - An account failed to log on,203.0.113.9,"
             "0xC000006D,0xC000006A,3" for i in range(4)]
    p = tmp_path / "SecurityEvent.csv"
    p.write_text("\n".join(rows) + "\n")
    evs = map_attack(ingest_file(str(p)))
    assert len(evs) == 4
    for e in evs:
        assert e.source != "azure_ad"
        assert (e.action, e.category, e.host, e.src_ip) == ("login_failed", "authentication", "DC1", "203.0.113.9")
        assert "T1110" in str(e.attack)
