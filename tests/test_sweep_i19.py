"""ITEM-19: IP text is canonicalised in _clean_ip so spellings of one address correlate.

IPv4-mapped IPv6 unwraps to dotted IPv4, IPv6 is the ipaddress compressed lowercase
form, and the zone id (fe80::1%eth0) is dropped."""
import pytest

from bluecell.ingest.parsers import _clean_ip, parse_ual
from bluecell.models import Event
from bluecell.pipeline.correlate import correlate


@pytest.mark.parametrize("raw,expected", [
    ("::ffff:203.0.113.9", "203.0.113.9"),
    ("::FFFF:203.0.113.9", "203.0.113.9"),
    ("[::ffff:203.0.113.9]:443", "203.0.113.9"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("2001:db8:0000::1", "2001:db8::1"),
    ("[2001:DB8::1]:443", "2001:db8::1"),
    ("fe80::1%eth0", "fe80::1"),
    ("203.0.113.9", "203.0.113.9"),
])
def test_clean_ip_canonical_form(raw, expected):
    assert _clean_ip(raw) == expected


@pytest.mark.parametrize("raw", ["::ffff:0.0.0.0", "::", "0.0.0.0"])
def test_unspecified_still_dropped_after_unwrap(raw):
    assert _clean_ip(raw) is None


def test_mapped_and_plain_v4_correlate():
    def ev(i, ip):
        return Event(ts=f"2026-10-03T22:00:0{i}Z", source="s", category="other",
                     action="a", message=f"m{i}", src_ip=ip)
    assert len(correlate([ev(1, _clean_ip("::ffff:203.0.113.9")),
                          ev(2, _clean_ip("203.0.113.9"))])) == 1


def test_parser_output_is_canonical():
    e = parse_ual({"Operation": "UserLoggedIn", "UserId": "a@b",
                   "AuditData": '{"ClientIP": "::ffff:203.0.113.9"}'})
    assert e.src_ip == "203.0.113.9"
