from datetime import datetime, timezone

from bluecell.models import Event, _parse_ts, CATEGORIES


def test_parse_ts_iso_z():
    dt = _parse_ts("2026-09-26T09:01:12Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026 and dt.hour == 9


def test_parse_ts_epoch_seconds_and_millis():
    a = _parse_ts(1700000000)
    b = _parse_ts(1700000000000)
    assert abs((a - b).total_seconds()) < 1


def test_parse_ts_bad_falls_back_to_now():
    dt = _parse_ts("not-a-date")
    assert isinstance(dt, datetime)
    assert dt.tzinfo is not None


def test_category_coerced_to_valid():
    e = Event(ts=None, source="x", category="bogus", action="a", message="m")
    assert e.category == "other"
    assert e.category in CATEGORIES


def test_severity_clamped():
    assert Event(ts=None, source="x", category="alert", action="a", message="m", severity=99).severity == 4
    assert Event(ts=None, source="x", category="alert", action="a", message="m", severity=-5).severity == 0


def test_event_id_stable_and_dedups():
    kw = dict(ts="2026-09-26T09:00:00Z", source="edr", category="process",
              action="run", message="same", host="h1")
    assert Event(**kw).event_id == Event(**kw).event_id


def test_compact_includes_attack_and_entities():
    e = Event(ts="2026-09-26T09:00:00Z", source="dns", category="dns",
              action="dns_query", message="m", domain="evil.xyz")
    e.attack.append("T1071.004")
    line = e.compact()
    assert "dns_query" in line and "dom=evil.xyz" in line and "att=T1071.004" in line


def test_to_dict_excludes_raw_includes_event_id():
    e = Event(ts=None, source="x", category="other", action="a", message="m",
              raw={"secret": 1})
    d = e.to_dict()
    assert "raw" not in d and "event_id" in d
