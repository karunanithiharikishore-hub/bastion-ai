"""Sweep follow-up (ITEM-38, ITEM-34): EDR RemoteUrl becomes a hostname domain
with the full URL kept in the message; Azure local-only time is tagged ts-local."""
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from datetime import datetime, timezone

from bastion.ingest.parsers import parse_azure_signin, parse_edr


def test_edr_remote_url_domain_is_hostname_and_url_kept_in_message():
    ev = parse_edr({
        "ActionType": "ConnectionSuccess", "RemoteUrl": "https://update.microsoft.com/path?x=1",
        "RemoteIP": "203.0.113.5", "RemotePort": 443, "DeviceName": "h1",
    })
    assert ev.domain == "update.microsoft.com"
    assert "https://update.microsoft.com/path?x=1" in ev.message


def test_edr_bare_host_remote_url_domain_is_host():
    ev = parse_edr({"ActionType": "ConnectionSuccess", "RemoteUrl": "evil.example.net", "DeviceName": "h1"})
    assert ev.domain == "evil.example.net"


def test_azure_local_only_time_is_tagged_ts_local_and_not_guessed_utc_silently():
    ev = parse_azure_signin({
        "Date (local)": "2026-10-03T22:00:00", "User": "a@corp.com",
        "IP address": "203.0.113.9", "Status": "Success",
    })
    assert "ts-local" in ev.tags
    assert ev.ts == datetime(2026, 10, 3, 22, 0, tzinfo=timezone.utc)


def test_azure_prefers_utc_column_when_both_present():
    ev = parse_azure_signin({
        "Date (UTC)": "2026-10-03T05:00:00Z", "Date (local)": "2026-10-02T22:00:00",
        "User": "a@corp.com", "IP address": "203.0.113.9", "Status": "Success",
    })
    assert ev.ts == datetime(2026, 10, 3, 5, 0, tzinfo=timezone.utc)
    assert "ts-local" not in ev.tags


def test_azure_utc_only_has_no_ts_local_tag():
    ev = parse_azure_signin({
        "Date (UTC)": "2026-10-03T05:00:00Z", "User": "a@corp.com",
        "IP address": "203.0.113.9", "Status": "Success",
    })
    assert "ts-local" not in ev.tags
