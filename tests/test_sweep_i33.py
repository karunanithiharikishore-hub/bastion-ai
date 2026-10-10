"""ITEM-33 regression: file_hash placeholders ('-', 'N/A', 'NULL', 'none', zeros) and
non-hex values are dropped, so they cannot link unrelated events in correlate()."""
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from datetime import datetime, timedelta, timezone

import pytest

from bluecell.models import Event
from bluecell.pipeline.correlate import correlate

T0 = datetime(2026, 10, 3, 22, 0, tzinfo=timezone.utc)


def _ev(host, minutes, file_hash):
    return Event(ts=T0 + timedelta(minutes=minutes), source="edr", category="file",
                 action="FileCreated", message=f"create on {host}", host=host,
                 file_hash=file_hash)


@pytest.mark.parametrize("placeholder", ["-", "N/A", "NULL", "none", "0" * 64, "0" * 32])
def test_placeholder_file_hash_is_dropped(placeholder):
    assert _ev("hostA", 0, placeholder).file_hash is None
    assert "file_hash" not in _ev("hostA", 0, placeholder).entities()


def test_non_hex_file_hash_is_dropped():
    assert _ev("hostA", 0, "not-a-hash!").file_hash is None


def test_real_file_hash_is_kept():
    h = "a" * 64
    assert _ev("hostA", 0, h).file_hash == h
    assert _ev("hostA", 0, h).entities()["file_hash"] == h


def test_placeholder_hash_does_not_link_unrelated_hosts():
    events = [_ev("hostA", 0, "-"), _ev("hostB", 5, "-")]
    assert correlate(events) == []
