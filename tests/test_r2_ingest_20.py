"""BUG-INGEST-20 / BUG-INGEST-2 follow-up: one source per file, column-shape rules
for CloudTrail, Azure Activity and Defender/Sentinel Advanced Hunting, and the
Sentinel IPAddress header."""
import json

from bluecell.ingest import detect_source
from bluecell.ingest.loader import ingest_file

TS = "2026-01-01T00:00:00Z"


def test_empty_cell_in_one_row_does_not_flip_source(tmp_path):
    p = tmp_path / "export.csv"
    p.write_text("Date (UTC),User,IP address,Status,Application\n"
                 f"{TS},a@b.com,1.2.3.4,Failure,Teams\n"
                 f"{TS},c@b.com,,Failure,Teams\n")
    evs = ingest_file(str(p))
    assert [e.action for e in evs] == ["login_failed", "login_failed"]
    assert evs[0].source == evs[1].source


def test_empty_first_row_does_not_flip_source(tmp_path):
    p = tmp_path / "export.csv"
    p.write_text("Date (UTC),User,IP address,Status,Application\n"
                 f"{TS},c@b.com,,Failure,Teams\n"
                 f"{TS},a@b.com,1.2.3.4,Failure,Teams\n")
    evs = ingest_file(str(p))
    assert [e.action for e in evs] == ["login_failed", "login_failed"]


def test_cloudtrail_shape_detected_without_filename_hint(tmp_path):
    p = tmp_path / "trail_export.json"
    p.write_text(json.dumps({"Records": [{
        "eventTime": TS, "eventName": "DeleteTrail",
        "eventSource": "cloudtrail.amazonaws.com", "sourceIPAddress": "1.2.3.4",
        "awsRegion": "us-east-1"}]}))
    ev = ingest_file(str(p))[0]
    assert ev.source == "cloudtrail.amazonaws.com"
    assert ev.action == "DeleteTrail"
    assert ev.src_ip == "1.2.3.4"


def test_column_shape_beats_misleading_filename(tmp_path):
    p = tmp_path / "firewall_export.json"
    p.write_text(json.dumps([{
        "eventTime": TS, "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com", "awsRegion": "us-east-1"}]))
    ev = ingest_file(str(p))[0]
    assert ev.source == "cloudtrail.amazonaws.com" and ev.action == "StopLogging"


def test_azure_activity_shape_routes_to_cloud(tmp_path):
    rec = {"time": TS, "operationName": "Microsoft.Compute/virtualMachines/write",
           "caller": "alice@contoso.com", "callerIpAddress": "1.2.3.4",
           "correlationId": "abc"}
    assert detect_source("export.json", rec) == "cloud"
    p = tmp_path / "export.json"
    p.write_text(json.dumps([rec]))
    ev = ingest_file(str(p))[0]
    assert ev.action == "Microsoft.Compute/virtualMachines/write"
    assert ev.src_ip == "1.2.3.4"


def test_defender_advanced_hunting_shape_beats_network_filename(tmp_path):
    p = tmp_path / "firewall_DeviceNetworkEvents.csv"
    p.write_text("Timestamp,DeviceName,ActionType,RemoteIP,LocalIP,"
                 "InitiatingProcessFileName,InitiatingProcessAccountName\n"
                 f"{TS},pc1,ConnectionSuccess,8.8.8.8,10.0.0.5,powershell.exe,bob\n")
    assert detect_source(str(p), {"DeviceName": "pc1", "ActionType": "x"}) == "edr"
    ev = ingest_file(str(p))[0]
    assert ev.source == "edr"
    assert (ev.host, ev.user, ev.process) == ("pc1", "bob", "powershell.exe")
    assert ev.dst_ip == "8.8.8.8" and ev.src_ip == "10.0.0.5"


def test_sentinel_signin_ipaddress_without_filename_hint(tmp_path):
    p = tmp_path / "export.csv"
    p.write_text("TimeGenerated,UserPrincipalName,IPAddress,ResultType,ResultDescription,"
                 "AppDisplayName\n"
                 f"{TS},a@b.com,1.2.3.4,50126,Invalid username or password,Teams\n")
    ev = ingest_file(str(p))[0]
    assert ev.action == "login_failed"
    assert ev.src_ip == "1.2.3.4"
