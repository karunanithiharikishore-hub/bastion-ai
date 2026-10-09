"""BUG-INGEST-6: common timestamp formats must parse, and unparseable ones must
be tagged instead of silently becoming now(). A zone name we do not know
(PST) must not be read as UTC.
"""
from datetime import datetime, timezone

from bluecell.models import Event, _parse_ts

JAN1 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_common_formats_parse_to_their_real_instant():
    cases = {
        "2026-01-01 00:00:00 UTC": JAN1,
        "Thu, 01 Jan 2026 00:00:00 GMT": JAN1,
        "10/Oct/2026:13:55:36 +0000": datetime(2026, 10, 10, 13, 55, 36, tzinfo=timezone.utc),
        "1/15/2024, 10:22:33 AM": datetime(2024, 1, 15, 10, 22, 33, tzinfo=timezone.utc),
        "4/5/2026 1:02 PM": datetime(2026, 4, 5, 13, 2, tzinfo=timezone.utc),
    }
    for raw, expected in cases.items():
        assert _parse_ts(raw) == expected, raw


def test_fractional_seconds_keep_their_offset():
    assert _parse_ts("2026-01-01T00:00:00.123+05:00") == datetime(
        2025, 12, 31, 19, 0, 0, 123000, tzinfo=timezone.utc)


def test_unknown_zone_name_is_not_read_as_utc():
    ev = Event(ts="2026-01-01T00:00:00.123 PST", source="s", category="other",
               action="a", message="m")
    assert "ts-unparsed" in ev.tags


def test_unparseable_timestamp_is_tagged():
    ev = Event(ts="not-a-date", source="s", category="other", action="a", message="m")
    assert "ts-unparsed" in ev.tags
    assert isinstance(ev.ts, datetime) and ev.ts.tzinfo is not None


def test_parsed_timestamp_is_not_tagged():
    ev = Event(ts="2026-01-01 00:00:00 UTC", source="s", category="other",
               action="a", message="m")
    assert "ts-unparsed" not in ev.tags
    assert ev.ts == JAN1
