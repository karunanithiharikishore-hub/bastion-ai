"""BUG-R4-INGEST-2: Sentinel SecurityEvent 4625, Get-WinEvent TimeCreated and SecurityAlert fields."""
import json

from bastion.ingest.loader import ingest_file
from bastion.pipeline.attack import map_attack


def _load(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return ingest_file(str(p))


def test_4625_spray_is_authentication_with_host_ip_and_t1110(tmp_path):
    rows = ["TimeGenerated [UTC],Computer,EventID,Account,Activity,IpAddress,LogonType"]
    rows += [f"2026-10-03T22:0{i}:00Z,DC01.corp.local,4625,CORP\\admin,4625 - An account failed to log on.,203.0.113.5,3"
             for i in range(8)]
    evs = map_attack(_load(tmp_path, "SecurityEvent.csv", "\n".join(rows)))
    assert len(evs) == 8
    for e in evs:
        assert (e.category, e.host, e.src_ip) == ("authentication", "DC01.corp.local", "203.0.113.5")
        assert e.attack and "T1110" in str(e.attack)


def test_get_winevent_timecreated_and_machinename(tmp_path):
    ev = _load(tmp_path, "winevt.json", json.dumps({"TimeCreated": "2026-10-03T22:00:00Z", "Id": 4625,
                                                    "MachineName": "DC01", "Message": "An account failed to log on."}))[0]
    assert ev.ts.isoformat()[:19] == "2026-10-03T22:00:00" and ev.host == "DC01"
    assert ev.category == "authentication"


def test_security_alert_fields_kept(tmp_path):
    ev = _load(tmp_path, "SecurityAlert.csv", "TimeGenerated [UTC],AlertName,AlertSeverity,CompromisedEntity,Description\n"
                                              "2026-10-03T22:00:00Z,Mimikatz detected,High,WKS1,Credential dumping\n")[0]
    assert (ev.message, ev.host) == ("Mimikatz detected", "WKS1") and ev.severity > 0


def test_security_alert_row_is_an_alert():
    from bastion.ingest.parsers import parse_edr
    ev = parse_edr({"TimeGenerated": "2026-10-03T22:00:00Z", "AlertName": "Mimikatz detected",
                    "AlertSeverity": "High", "CompromisedEntity": "WKS-7"})
    assert ev.category == "alert"
