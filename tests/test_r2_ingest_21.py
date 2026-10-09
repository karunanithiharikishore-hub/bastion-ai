"""BUG-INGEST-21: Defender DeviceLogonEvents rows were parsed as network (RemoteIP)
or process, so attack.py never saw a sign-in and no brute-force rule fired."""
import json

from bluecell.ingest.loader import ingest_file
from bluecell.ingest.parsers import parse_edr
from bluecell.pipeline.attack import map_attack


def _logon(action, ip="8.8.8.8", ts="00"):
    return {"Timestamp": f"2026-01-01T00:00:{ts}Z", "DeviceName": "pc1",
            "ActionType": action, "AccountName": "alice", "RemoteIP": ip,
            "LogonType": "Network"}


def test_failed_logons_then_success_tag_t1110_and_auth_success(tmp_path):
    p = tmp_path / "DeviceLogonEvents.json"
    rows = [_logon("LogonFailed", ts=str(i)) for i in range(6)]
    rows.append(_logon("LogonSuccess", ts="10"))
    p.write_text(json.dumps(rows))
    evs = map_attack(ingest_file(str(p)))
    assert all(e.category == "authentication" for e in evs)
    assert sum("T1110" in e.attack for e in evs[:6]) == 6
    assert "auth:success" in evs[6].tags and not evs[6].attack


def test_logon_attempted_is_authentication_not_network():
    ev = parse_edr(_logon("LogonAttempted"))
    assert ev.category == "authentication"
    assert ev.user == "alice" and ev.dst_ip == "8.8.8.8"


def test_device_network_stays_network():
    ev = parse_edr({"DeviceName": "pc1", "ActionType": "ConnectionSuccess",
                    "RemoteIP": "8.8.8.8", "RemotePort": 443, "LocalIP": "10.0.0.5"})
    assert ev.category == "network"
