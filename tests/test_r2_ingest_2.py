"""BUG-INGEST-2: Defender Advanced Hunting exports (DeviceNetworkEvents,
DeviceProcessEvents, DeviceLogonEvents, DeviceFileEvents) parsed to empty
events. Also: Sentinel SigninLogs IPAddress -> src_ip (already served by the case-insensitive
"ipAddress" alias; guard test only)."""
import json

from bastion.ingest.loader import ingest_file
from bastion.ingest.parsers import parse_azure_signin

_NET = {"Timestamp": "2026-01-01T00:00:00Z", "DeviceName": "pc1",
        "ActionType": "ConnectionSuccess", "RemoteIP": "8.8.8.8", "RemotePort": 443,
        "LocalIP": "10.0.0.5", "RemoteUrl": "dns.google",
        "InitiatingProcessFileName": "powershell.exe",
        "InitiatingProcessAccountName": "bob"}


def test_device_network_json_maps_columns(tmp_path):
    p = tmp_path / "DeviceNetworkEvents.json"
    p.write_text(json.dumps([_NET]))
    ev = ingest_file(str(p))[0]
    assert ev.category == "network"
    assert (ev.host, ev.user, ev.process) == ("pc1", "bob", "powershell.exe")
    assert (ev.src_ip, ev.dst_ip, ev.domain) == ("10.0.0.5", "8.8.8.8", "dns.google")
    assert ev.action == "ConnectionSuccess"
    assert ev.message.startswith("10.0.0.5 -> 8.8.8.8:443")  # full RemoteUrl may follow (sweep I38)


def test_device_process_csv_uses_filename_as_process_and_command_line(tmp_path):
    p = tmp_path / "DeviceProcessEvents.csv"
    p.write_text("Timestamp,DeviceName,ActionType,FileName,ProcessCommandLine,"
                 "InitiatingProcessFileName,AccountName,SHA256\n"
                 "2026-01-01T00:00:00Z,pc1,ProcessCreated,cmd.exe,cmd /c whoami,"
                 "explorer.exe,bob,abc123\n")
    ev = ingest_file(str(p))[0]
    assert ev.action == "ProcessCreated"
    assert (ev.host, ev.user, ev.file_hash) == ("pc1", "bob", "abc123")
    assert ev.process == "cmd.exe"          # the process itself, not its parent
    assert ev.message == "cmd /c whoami"


def test_device_logon_and_file_events_map_common_columns(tmp_path):
    p = tmp_path / "DeviceLogonEvents.csv"
    p.write_text("Timestamp,DeviceName,ActionType,AccountName,RemoteIP,LogonType\n"
                 "2026-01-01T00:00:00Z,pc2,LogonFailed,alice,1.2.3.4,Network\n")
    ev = ingest_file(str(p))[0]
    assert (ev.action, ev.host, ev.user, ev.dst_ip) == ("LogonFailed", "pc2", "alice", "1.2.3.4")

    p = tmp_path / "DeviceFileEvents.json"
    p.write_text(json.dumps([{"Timestamp": "2026-01-01T00:00:00Z", "DeviceName": "pc3",
                              "ActionType": "FileCreated", "FileName": "x.exe",
                              "InitiatingProcessFileName": "chrome.exe",
                              "SHA1": "deadbeef", "AccountName": "carol"}]))
    ev = ingest_file(str(p))[0]
    assert (ev.action, ev.host, ev.user, ev.process) == ("FileCreated", "pc3", "carol", "chrome.exe")
    assert ev.file_hash == "deadbeef"


def test_sentinel_signin_ipaddress_maps_to_src_ip():
    ev = parse_azure_signin({"TimeGenerated": "2026-01-01T00:00:00Z",
                             "UserPrincipalName": "a@b.com", "IPAddress": "1.2.3.4",
                             "ResultType": "0", "AppDisplayName": "Teams"})
    assert ev.src_ip == "1.2.3.4"
