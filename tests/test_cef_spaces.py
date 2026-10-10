"""ITEM-24 follow-up: CEF extension values may contain spaces; `\\=`, `\\\\` and header `\\|` are escapes."""
import time

from bluecell.ingest.parsers import parse_text_line

HDR = "CEF:0|Acme|IDS|1.0|100|Login|8|"


def _parse(line):
    return parse_text_line(line, {})


def test_cef_value_with_spaces_runs_to_next_key():
    ev = _parse(HDR + "act=Failed login for admin suser=bob src=203.0.113.5")
    assert (ev.action, ev.user, ev.src_ip) == ("Failed login for admin", "bob", "203.0.113.5")


def test_cef_escaped_equals_and_backslash_in_value():
    ev = _parse(HDR + r"act=a\=b c\\d suser=bob")
    assert ev.action == r"a=b c\d"
    assert ev.user == "bob"


def test_cef_header_pipe_escape():
    ev = _parse("CEF:0|Acme|IDS|1.0|100|Port \\| scan|8|src=203.0.113.5 dst=10.0.0.5 dpt=22")
    assert (ev.action, ev.src_ip, ev.dst_ip, ev.dst_port) == ("Port | scan", "203.0.113.5", "10.0.0.5", 22)


def test_cef_long_line_50kb_parses_fast():
    filler = "x y " * 13000  # ~52KB of spaced text with no ' key=' inside
    line = HDR + "act=Blocked by rule suser=bob src=203.0.113.5 pad=" + filler + " dst=10.0.0.5 dpt=22"
    assert len(line) > 50_000
    t0 = time.perf_counter()
    ev = _parse(line)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5
    assert (ev.action, ev.user, ev.src_ip, ev.dst_ip, ev.dst_port) == (
        "Blocked by rule", "bob", "203.0.113.5", "10.0.0.5", 22)


def test_ufw_trailing_non_key_word_not_swallowed():
    ev = _parse("Oct  3 22:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 "
                "PROTO=TCP SPT=4444 DPT=22 trailing")
    assert (ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port) == ("203.0.113.5", "10.0.0.5", 4444, 22)
