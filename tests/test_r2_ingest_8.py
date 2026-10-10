"""BUG-INGEST-8: extreme dates with a non-UTC offset must not raise.

.NET DateTime.MinValue / MaxValue written with an offset overflow when
converted to UTC; _parse_ts must clamp instead of raising, and the record
must survive ingestion.
"""
import json
from datetime import datetime, timezone

from bastion.models import Event, _parse_ts
from bastion.ingest.loader import ingest_file


def test_parse_ts_extreme_low_with_positive_offset_clamps():
    dt = _parse_ts("0001-01-01T00:00:00+05:00")
    assert dt.tzinfo is not None
    assert dt == datetime.min.replace(tzinfo=timezone.utc)


def test_parse_ts_extreme_high_with_negative_offset_clamps():
    dt = _parse_ts("9999-12-31T23:59:59-05:00")
    assert dt.tzinfo is not None
    assert dt == datetime.max.replace(tzinfo=timezone.utc)


def test_event_with_extreme_offset_timestamp_does_not_raise():
    ev = Event(ts="9999-12-31T23:59:59-05:00", source="s", category="other",
               action="a", message="m")
    assert ev.ts.tzinfo is not None


def test_ingest_keeps_record_with_extreme_offset_timestamp(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text(
        json.dumps({"timestamp": "0001-01-01T00:00:00+05:00", "host": "a"}) + "\n"
        + json.dumps({"timestamp": "2026-01-01T00:00:00Z", "host": "b"}) + "\n",
        encoding="utf-8",
    )
    events = ingest_file(str(p))
    assert len(events) == 2
    assert {e.host for e in events} == {"a", "b"}
