"""ITEM-39 / ITEM-29 regression: an unquoted comma in MTSummary Subject must not
shift Status/Recipient_status, and a mixed JSONL file is detected per record."""
import json

from bastion.ingest.loader import ingest_file


def test_unquoted_comma_in_subject_does_not_shift_status(tmp_path):
    p = tmp_path / "MTSummary.csv"
    p.write_text("origin_timestamp_utc,sender_address,recipient_address,subject,status,Recipient_status\n"
                 "2026-10-03T10:00:00Z,a@x.com,b@y.com,Invoice, urgent,Quarantined,"
                 "b@y.com##Receive, Deliver\n")
    (ev,) = ingest_file(str(p))
    assert ev.raw["subject"] == "Invoice, urgent"
    assert ev.raw["status"] == "Quarantined"
    assert ev.raw["Recipient_status"] == "b@y.com##Receive, Deliver"
    assert ev.action == "email_quarantined"
    assert ev.severity == 2


def test_mixed_jsonl_is_detected_per_record(tmp_path):
    recs = [
        {"eventTime": "2026-10-03T22:00:00Z", "eventName": "ConsoleLogin",
         "eventSource": "signin.amazonaws.com", "sourceIPAddress": "203.0.113.5",
         "userIdentity": {"userName": "bob"}},
        {"timestamp": "2026-10-03T22:00:01Z", "host": "wks1",
         "process": "powershell.exe", "message": "powershell -enc AAA", "user": "bob"},
    ]
    p = tmp_path / "siem_export.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    cloud, edr = ingest_file(str(p))
    assert cloud.source != "edr"
    assert edr.host == "wks1" and edr.process == "powershell.exe"
