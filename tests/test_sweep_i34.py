"""ITEM-34 / ITEM-35: numeric epochs outside 1990-2100 are unparsed, the common
text formats parse to their real instant, and _port accepts float/proto forms."""
from datetime import datetime, timezone

from bastion.models import Event, _parse_ts_or_none, _port

UTC = timezone.utc


def test_small_or_out_of_range_numbers_are_unparsed_not_1970():
    for bad in (1500, 5, 86400, 0, -1, float("nan"), float("inf")):
        assert _parse_ts_or_none(bad) is None, bad


def test_common_formats_parse_to_real_instant():
    cases = {
        "2026-10-03 22:00:00.000 -0700": datetime(2026, 10, 4, 5, 0, tzinfo=UTC),
        "03-Oct-2026 22:00:00": datetime(2026, 10, 3, 22, 0, tzinfo=UTC),
        "Oct 3, 2026 @ 22:00:00.000": datetime(2026, 10, 3, 22, 0, tzinfo=UTC),
        "10/03/2026 22:00": datetime(2026, 10, 3, 22, 0, tzinfo=UTC),
    }
    for raw, want in cases.items():
        assert _parse_ts_or_none(raw) == want, raw


def test_ports_float_suffix_and_protocol_forms():
    assert _port("443.0") == 443
    assert _port("22/tcp") == 22
    assert _port("tcp/22") == 22
    assert _port("8,080") is None
    e = Event(ts=datetime(2026, 1, 1, tzinfo=UTC), source="s", category="network", action="a",
              message="m", dst_port="443.0")
    assert e.dst_port == 443
