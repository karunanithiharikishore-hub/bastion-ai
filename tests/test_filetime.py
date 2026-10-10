"""Windows FILETIME integers (100ns since 1601) parse to the right date, not 1974."""
from datetime import datetime, timezone

from bastion.models import _parse_ts


def test_filetime_int_and_text():
    want = datetime(2026, 10, 3, 22, 0, tzinfo=timezone.utc)
    ft = 116444736000000000 + int(want.timestamp()) * 10_000_000
    assert _parse_ts(ft) == want
    assert _parse_ts(str(ft)) == want


def test_epoch_nanoseconds_still_work():
    want = datetime(2026, 10, 3, 22, 0, tzinfo=timezone.utc)
    assert _parse_ts(int(want.timestamp()) * 1_000_000_000) == want
