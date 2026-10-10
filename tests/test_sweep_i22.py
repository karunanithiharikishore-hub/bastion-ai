"""ITEM-22 regression: Sysmon JSON and Event Viewer CSV keep timestamp, command
line, hash, destination IP/port, file path and DNS query through parse_edr."""
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from datetime import datetime, timezone

from bluecell.ingest.parsers import parse_edr

SYSMON_1 = {"UtcTime": "2026-10-03 22:00:00.123", "EventID": 1, "Computer": "wks1",
            "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c net user evil /add",
            "User": "CORP\\bob", "Hashes": "SHA256=9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"}
SYSMON_3 = {"UtcTime": "2026-10-03 22:00:01.123", "EventID": 3, "Computer": "wks1", "Image": "C:\\x.exe",
            "SourceIp": "10.0.0.5", "SourcePort": 4444, "DestinationIp": "203.0.113.9",
            "DestinationPort": 443, "DestinationHostname": "evil.example.com", "User": "CORP\\bob"}
SYSMON_11 = {"UtcTime": "2026-10-03 22:00:02.123", "EventID": 11, "Computer": "wks1", "Image": "C:\\x.exe",
             "TargetFilename": "C:\\Users\\bob\\a.docx.locked"}
SYSMON_22 = {"UtcTime": "2026-10-03 22:00:03.123", "EventID": 22, "Computer": "wks1", "Image": "C:\\x.exe",
             "QueryName": "abcdefghijklmnop12.xyz", "QueryResults": "203.0.113.9"}
EVT_4625 = {"Level": "Information", "Date and Time": "10/3/2026 10:00:00 PM",
            "Source": "Microsoft-Windows-Security-Auditing", "Event ID": "4625", "Task Category": "Logon"}


def test_sysmon_process_create_keeps_ts_command_line_hash_and_image():
    ev = parse_edr(SYSMON_1)
    assert ev.ts == datetime(2026, 10, 3, 22, 0, 0, 123000, tzinfo=timezone.utc)
    assert ev.message == "cmd /c net user evil /add"
    assert ev.process == "C:\\Windows\\System32\\cmd.exe"
    assert ev.file_hash == "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
    assert "ts-unparsed" not in ev.tags


def test_sysmon_network_connect_keeps_dst_ip_port_and_hostname():
    ev = parse_edr(SYSMON_3)
    assert ev.category == "network"
    assert ev.dst_ip == "203.0.113.9" and ev.dst_port == 443
    assert ev.src_ip == "10.0.0.5" and ev.src_port == 4444
    assert ev.domain == "evil.example.com"


def test_sysmon_file_create_keeps_target_filename_as_file_and_message():
    ev = parse_edr(SYSMON_11)
    assert ev.file_path == "C:\\Users\\bob\\a.docx.locked"
    assert ev.message == "C:\\Users\\bob\\a.docx.locked"


def test_sysmon_dns_query_is_the_domain_and_message():
    ev = parse_edr(SYSMON_22)
    assert ev.domain == "abcdefghijklmnop12.xyz"
    assert ev.message == "abcdefghijklmnop12.xyz"


def test_event_viewer_csv_uses_date_time_and_event_id_for_4625():
    ev = parse_edr(EVT_4625)
    assert ev.ts == datetime(2026, 10, 3, 22, 0, 0, tzinfo=timezone.utc)
    assert ev.action == "login_failed"
    assert "ts-unparsed" not in ev.tags
