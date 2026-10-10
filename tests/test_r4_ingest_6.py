"""BUG-R4-INGEST-6: a PM time must not be read 12 hours early, and any AM/PM
string we cannot honour must be unparsed (None), not silently wrong.
"""
from datetime import datetime, timezone

from bluecell.models import _parse_ts_or_none


def test_month_name_pm_timestamp_keeps_pm():
    assert _parse_ts_or_none("Oct  3, 2026 10:00:00 PM") == datetime(
        2026, 10, 3, 22, 0, 0, tzinfo=timezone.utc)


def test_rfc2822_style_pm_timestamp_keeps_pm():
    assert _parse_ts_or_none("Sat, 03 Oct 2026 10:00:00 PM") == datetime(
        2026, 10, 3, 22, 0, 0, tzinfo=timezone.utc)


def test_ampm_string_we_cannot_parse_is_unparsed_not_guessed():
    assert _parse_ts_or_none("Oct 3 2026 10:00 PM ZZZ") is None
