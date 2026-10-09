"""BUG-INGEST-3: Sentinel SigninLogs TimeGenerated / ResultType / ResultDescription.
Also BUG-INGEST-6 follow-up: Azure Activity eventTimestamp is read as ts."""
import datetime as dt

from bluecell.ingest.loader import ingest_file
from bluecell.ingest.parsers import parse_azure_signin, parse_cloud


def _sentinel_csv(tmp_path, result_type, desc):
    p = tmp_path / "SigninLogs.csv"
    p.write_text(
        "TimeGenerated,UserPrincipalName,IPAddress,ResultType,ResultDescription,AppDisplayName\n"
        f"2026-01-01T00:00:00Z,a@b.com,1.2.3.4,{result_type},{desc},Teams\n")
    return str(p)


def test_sentinel_failed_signin_is_failure_with_real_ts(tmp_path):
    ev = ingest_file(_sentinel_csv(tmp_path, "50126", "Invalid username or password"))[0]
    assert ev.ts == dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert ev.action == "login_failed"
    assert ev.severity == 3
    assert "Invalid username or password" in ev.message


def test_sentinel_success_stays_success(tmp_path):
    ev = ingest_file(_sentinel_csv(tmp_path, "0", ""))[0]
    assert ev.action == "login_success"
    assert ev.severity == 1


def test_timegenerated_utc_bracket_key_is_read():
    ev = parse_azure_signin({"TimeGenerated [UTC]": "2026-01-01T00:00:00Z",
                             "UserPrincipalName": "a@b.com", "ResultType": 0})
    assert ev.ts == dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def test_azure_activity_event_timestamp_is_read():
    ev = parse_cloud({"eventTimestamp": "2026-01-01T00:00:00Z",
                      "operationName": "Microsoft.Compute/virtualMachines/write",
                      "status": {"value": "Succeeded"}})
    assert ev.ts == dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
