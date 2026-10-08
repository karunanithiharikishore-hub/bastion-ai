"""Regression tests for ingest / model bugs I1-I17 and P2."""
import json
import os
import sys
from datetime import datetime, timezone

import pytest

from bluecell.ingest import detect_source, ingest_path
from bluecell.ingest.loader import ingest_file
from bluecell.ingest.parsers import (
    _azure_is_failure, parse_azure_signin, parse_cloud, parse_edr,
    parse_o365_message, parse_syslog_line, parse_ual,
)
from bluecell.models import Event


def _write(tmp_path, name, text, encoding="utf-8"):
    p = tmp_path / name
    p.write_bytes(text.encode(encoding))
    return str(p)


# I1 ------------------------------------------------------------------------
def test_i1_azure_nested_status_success_not_failure():
    ev = parse_azure_signin({
        "createdDateTime": "2024-01-15T10:22:33Z", "userPrincipalName": "a@b",
        "ipAddress": "1.2.3.4", "status": {"errorCode": 0, "failureReason": None},
    })
    assert ev.action == "login_success"
    fail = parse_azure_signin({
        "createdDateTime": "2024-01-15T10:22:33Z", "userPrincipalName": "a@b",
        "ipAddress": "1.2.3.4",
        "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
    })
    assert fail.action == "login_failed"


# I2 ------------------------------------------------------------------------
def test_i2_ual_operation_trailing_period():
    ev = parse_ual({"Operation": "Consent to application.", "UserId": "a@b",
                    "CreationDate": "2024-01-15T10:00:00Z"})
    assert ev.action == "app_consent"
    assert "T1098.003" in ev.attack


# I3 ------------------------------------------------------------------------
def test_i3_graph_value_wrapper(tmp_path):
    path = _write(tmp_path, "signins_graph.json", json.dumps({
        "@odata.context": "x",
        "value": [
            {"createdDateTime": "2024-01-15T10:22:33Z", "userPrincipalName": "a@b",
             "ipAddress": "1.2.3.4", "status": {"errorCode": 0}},
            {"createdDateTime": "2024-01-15T10:23:33Z", "userPrincipalName": "c@b",
             "ipAddress": "1.2.3.5", "status": {"errorCode": 50126}},
        ]}))
    evs = ingest_file(path)
    assert len(evs) == 2
    assert sorted(e.user for e in evs) == ["a@b", "c@b"]


# I4 ------------------------------------------------------------------------
def test_i4_flat_ual_json_keeps_ts_and_ip(tmp_path):
    ev = parse_ual({"CreationTime": "2024-01-15T10:00:00", "Operation": "New-InboxRule",
                    "UserId": "a@b", "ClientIP": "1.2.3.4:5555", "Workload": "Exchange"})
    assert ev.ts == datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)
    assert ev.src_ip == "1.2.3.4"
    assert "Exchange" in ev.message


def test_i4_auditlog_filename_hints_route_to_ual():
    assert detect_source("o365_auditlog.json") == "ual"
    assert detect_source("m365_unifiedaudit_export.json") == "ual"


# I5 ------------------------------------------------------------------------
def test_i5_classic_purview_ual_csv(tmp_path):
    audit = json.dumps({"Operation": "Consent to application.", "ClientIP": "1.2.3.4",
                        "Workload": "AzureActiveDirectory"}).replace('"', '""')
    path = _write(tmp_path, "export.csv",
                  "CreationDate,UserIds,Operations,AuditData\n"
                  f'2024-01-15T10:00:00Z,a@b,Consent to application.,"{audit}"\n')
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.source == "m365_ual"
    assert ev.action == "app_consent"
    assert ev.user == "a@b"
    assert ev.src_ip == "1.2.3.4"


# I6 ------------------------------------------------------------------------
@pytest.mark.parametrize("raw_ip,expected", [
    ("2001:db8::1", "2001:db8::1"),
    ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("1.2.3.4:443", "1.2.3.4"),
])
def test_i6_ual_ip_cleanup_keeps_ipv6(raw_ip, expected):
    ev = parse_ual({"Operation": "UserLoggedIn", "UserId": "a@b",
                    "AuditData": json.dumps({"ClientIP": raw_ip})})
    assert ev.src_ip == expected


# I7 ------------------------------------------------------------------------
def test_i7_rfc5424_syslog():
    ev = parse_syslog_line("<34>1 2024-01-15T10:22:33.003Z web01 sshd 1234 - - "
                           "Failed password for root from 1.2.3.4 port 22 ssh2")
    assert ev.action == "login_failed"
    assert ev.host == "web01"
    assert ev.process == "sshd"
    assert ev.user == "root"
    assert ev.src_ip == "1.2.3.4"
    assert ev.ts.year == 2024 and ev.ts.month == 1 and ev.ts.day == 15


# I8 ------------------------------------------------------------------------
def test_i8_failure_reason_without_code_is_failure():
    assert _azure_is_failure(None, None, "Invalid username or password") is True
    assert _azure_is_failure(None, 0, "Invalid username or password") is False
    assert _azure_is_failure(None, None, "Other.") is False
    assert _azure_is_failure(None, None, None) is False


# I9 ------------------------------------------------------------------------
def test_i9_csv_huge_field(tmp_path):
    blob = json.dumps({"Operation": "MailItemsAccessed", "ClientIP": "1.2.3.4",
                       "Folders": [{"Path": "x" * 200_000}]}).replace('"', '""')
    path = _write(tmp_path, "ual_big.csv",
                  "CreationDate,RecordType,Operation,UserId,AuditData\n"
                  f'2024-01-15T10:00:00Z,50,MailItemsAccessed,a@b,"{blob}"\n'
                  '2024-01-15T10:01:00Z,50,UserLoggedIn,a@b,"{}"\n')
    evs = ingest_file(path)
    assert len(evs) == 2
    assert evs[0].src_ip == "1.2.3.4"


# I10 -----------------------------------------------------------------------
def test_i10_azure_activity_routed_to_cloud(tmp_path):
    path = _write(tmp_path, "azure_activity.json", json.dumps([{
        "time": "2024-01-15T10:00:00Z",
        "operationName": "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE",
        "caller": "a@b", "callerIpAddress": "1.2.3.4", "status": {"value": "Succeeded"}}]))
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.category == "cloud_api"
    assert ev.action == "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"
    assert ev.user == "a@b" and ev.src_ip == "1.2.3.4"
    assert ev.ts == datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)


def test_i10_entra_audit_routed_to_cloud(tmp_path):
    path = _write(tmp_path, "entra_audit.json", json.dumps([{
        "activityDateTime": "2024-01-15T10:00:00Z",
        "activityDisplayName": "Add member to role", "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "a@b"}}}]))
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.action == "Add member to role"
    assert ev.user == "a@b"
    assert ev.ts == datetime(2024, 1, 15, 10, 0, tzinfo=timezone.utc)


def test_i10_parser_none_falls_back_instead_of_dropping(tmp_path):
    # Filename says message trace, but the record has no mail fields.
    path = _write(tmp_path, "o365_stuff.json", json.dumps([
        {"timestamp": "2024-01-15T10:00:00Z", "action": "something", "host": "h1"}]))
    evs = ingest_file(path)
    assert len(evs) == 1
    assert evs[0].host == "h1"


# I11 -----------------------------------------------------------------------
def test_i11_mtsummary_columns(tmp_path):
    path = _write(tmp_path, "MTSummary_report.csv",
                  "origin_timestamp_utc,sender_address,Recipient_status,message_subject,"
                  "total_bytes,message_id,original_client_ip,directionality\n"
                  "2024-01-15T10:22:33.1234567Z,evil@x.com,"
                  "\"victim@corp.com##Receive, Deliver\",Invoice overdue,1234,<id>,"
                  "1.2.3.4,Incoming\n")
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.user == "evil@x.com"
    assert "-> victim@corp.com " in ev.message
    assert "subj='Invoice overdue'" in ev.message
    assert ev.action == "email_deliver"
    assert ev.src_ip == "1.2.3.4"


def test_i11_get_messagetrace_export_csv(tmp_path):
    path = _write(tmp_path, "trace.csv",
                  '"Received","SenderAddress","RecipientAddress","Subject","Status",'
                  '"ToIP","FromIP","Size","MessageId","MessageTraceId"\n'
                  '"1/15/2024 10:22:33 AM","evil@x.com","victim@corp.com","Invoice",'
                  '"Delivered","","1.2.3.4","1234","<id>","guid"\n')
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert detect_source("trace.csv", {"SenderAddress": "evil@x.com"}) == "messagetrace"
    assert ev.user == "evil@x.com"
    assert "evil@x.com -> victim@corp.com" in ev.message
    assert "subj='Invoice'" in ev.message
    assert ev.action == "email_delivered"
    assert ev.src_ip == "1.2.3.4"
    assert ev.ts == datetime(2024, 1, 15, 10, 22, 33, tzinfo=timezone.utc)


# I12 -----------------------------------------------------------------------
def test_i12_us_date_and_leap_day():
    ev = Event(ts="1/15/2024 10:22:33 AM", source="x", category="other",
               action="a", message="m")
    assert ev.ts == datetime(2024, 1, 15, 10, 22, 33, tzinfo=timezone.utc)
    ev = Event(ts="1/15/2024 10:22:33 PM", source="x", category="other",
               action="a", message="m")
    assert ev.ts.hour == 22
    leap = Event(ts="Feb 29 10:00:00", source="x", category="other",
                 action="a", message="m")
    assert (leap.ts.month, leap.ts.day, leap.ts.hour) == (2, 29, 10)
    assert leap.ts <= datetime.now(timezone.utc)


# I13 -----------------------------------------------------------------------
def test_i13_long_numeric_timestamps():
    want = datetime(2024, 1, 15, 10, 22, 33, tzinfo=timezone.utc)
    for v in ("1705314153000000", "1705314153000000000", 1705314153000000):
        ev = Event(ts=v, source="x", category="other", action="a", message="m")
        assert ev.ts == want, v
    ev = Event(ts="20261003221500", source="x", category="other", action="a", message="m")
    assert ev.ts == datetime(2026, 10, 3, 22, 15, tzinfo=timezone.utc)


# I14 -----------------------------------------------------------------------
def test_i14_csv_whitespace_headers_and_values(tmp_path):
    path = _write(tmp_path, "firewall_sp.csv",
                  "timestamp, src_ip, dst_ip, action\n"
                  "2024-01-15T10:00:00Z, 10.0.0.1, 1.2.3.4, deny\n")
    evs = ingest_file(path)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.src_ip == "10.0.0.1" and ev.dst_ip == "1.2.3.4"
    assert ev.action == "deny"


def test_i14_edr_alert_false_is_not_alert():
    assert parse_edr({"alert": "false", "action": "proc"}).category == "process"
    assert parse_edr({"alert": "0", "action": "proc"}).category == "process"
    assert parse_edr({"alert": "true", "action": "proc"}).category == "alert"


# I15 -----------------------------------------------------------------------
def test_i15_systemd_failed_start_not_login_failure():
    ev = parse_syslog_line("Oct  3 22:00:00 web01 systemd[1]: Failed to start "
                           "systemd-logind.service - User Login Management.")
    assert ev.action != "login_failed"


def test_i15_pam_rhost_and_user():
    ev = parse_syslog_line(
        "Oct  3 22:00:00 web01 sshd[99]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root")
    assert ev.action == "login_failed"
    assert ev.user == "root"
    assert ev.src_ip == "1.2.3.4"


def test_i15_ipv6_source():
    ev = parse_syslog_line("Oct  3 22:00:00 web01 sshd[1]: Failed password for root "
                           "from 2001:db8::5 port 22 ssh2")
    assert ev.action == "login_failed"
    assert ev.src_ip == "2001:db8::5"


def test_i15_message_repeated_expands(tmp_path):
    path = _write(tmp_path, "auth.log",
                  "Oct  3 22:00:00 web01 sshd[1]: message repeated 5 times: "
                  "[ Failed password for root from 1.2.3.4 port 22 ssh2]\n")
    evs = ingest_file(path)
    assert len(evs) == 5
    assert all(e.action == "login_failed" and e.src_ip == "1.2.3.4" for e in evs)
    assert len({e.event_id for e in evs}) == 5


# I16 -----------------------------------------------------------------------
def test_i16_cloudtrail_console_login_failure_without_errorcode():
    ev = parse_cloud({"eventTime": "2024-01-15T10:00:00Z", "eventSource": "signin.amazonaws.com",
                      "eventName": "ConsoleLogin",
                      "userIdentity": {"type": "IAMUser", "userName": "bob"},
                      "sourceIPAddress": "1.2.3.4", "errorMessage": "Failed authentication",
                      "responseElements": {"ConsoleLogin": "Failure"}})
    assert ev.severity >= 3
    assert ev.action == "login_failed"
    ev2 = parse_cloud({"eventTime": "2024-01-15T10:00:00Z", "eventName": "ConsoleLogin",
                       "userIdentity": {"userName": "bob"}, "sourceIPAddress": "1.2.3.4",
                       "responseElements": {"ConsoleLogin": "Failure"}})
    assert ev2.severity >= 3


def test_i16_service_hostname_not_src_ip():
    ev = parse_cloud({"eventTime": "2024-01-15T10:00:00Z", "eventSource": "kms.amazonaws.com",
                      "eventName": "Decrypt",
                      "userIdentity": {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"},
                      "sourceIPAddress": "ec2.amazonaws.com"})
    assert ev.src_ip is None


# I17 -----------------------------------------------------------------------
@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0,
                    reason="needs POSIX permissions as non-root")
def test_i17_unreadable_file_does_not_abort_dir(tmp_path):
    line = "Oct  3 22:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    good = _write(tmp_path, "a.log", line)
    bad = _write(tmp_path, "b.log", line)
    os.chmod(bad, 0)
    try:
        evs = ingest_path(str(tmp_path))
    finally:
        os.chmod(bad, 0o644)
    assert len(evs) == 1
    assert good


def test_i17_utf16_bom_file(tmp_path):
    rec = {"timestamp": "2024-01-15T10:00:00Z", "query": "evil.example.com", "src_ip": "10.0.0.5"}
    path = _write(tmp_path, "dns_u16.json", "﻿" + json.dumps([rec]), encoding="utf-16-le")
    evs = ingest_file(path)
    assert len(evs) == 1
    assert evs[0].domain == "evil.example.com"


# P2 ------------------------------------------------------------------------
def test_p2_event_id_includes_raw_digest():
    def mk(port):
        return Event(ts="2024-01-15T10:00:00Z", source="firewall", category="network",
                     action="deny", message="10.0.0.1 -> 1.2.3.4",
                     src_ip="10.0.0.1", dst_ip="1.2.3.4",
                     raw={"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4", "dst_port": port})
    ids = {mk(p).event_id for p in (22, 23, 80, 443)}
    assert len(ids) == 4
    # Deterministic: same content -> same id; raw key order does not matter.
    assert mk(22).event_id == mk(22).event_id
    a = Event(ts="2024-01-15T10:00:00Z", source="s", category="other", action="a",
              message="m", raw={"x": 1, "y": 2})
    b = Event(ts="2024-01-15T10:00:00Z", source="s", category="other", action="a",
              message="m", raw={"y": 2, "x": 1})
    assert a.event_id == b.event_id
