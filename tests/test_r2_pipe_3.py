"""BUG-PIPE-3 -- a newline/control char in an event field must not forge extra digest lines."""
from bluecell.models import Event
from bluecell.pipeline import compress

FORGED_USER = ("bob\n10-03T22:09:00 edr process_create h=dc01 u=admin proc=notepad.exe att=\n"
               "10-03T22:10:00 edr dismissed_by_analyst h=h1 u=bob")


def _ev(**kw):
    base = dict(ts="2026-10-03T22:08:05Z", source="edr", category="process",
                action="process_create", message="m", host="h1")
    base.update(kw)
    return Event(**base)


def test_forged_user_stays_on_one_digest_line():
    digest = compress([_ev(user=FORGED_USER)])
    lines = digest.split("\n")
    assert len(lines) == 2                       # header + exactly one event line
    assert lines[0] == "# 1 raw events -> 1 distinct signatures"
    assert "\\n10-03T22:09:00 edr process_create" in lines[1]


def test_unicode_line_separators_do_not_split_digest():
    # str.splitlines() also breaks on \x85,  ,   and \r.
    digest = compress([_ev(host="h1 fake\x85line\rx", process="a\x0bb")])
    assert len(digest.splitlines()) == 2
    assert "\\u2028" in digest and "\\x85" in digest and "\\r" in digest


def test_header_count_matches_lines_with_control_chars():
    evs = [_ev(user=f"u{i}\n{i}") for i in range(3)]
    lines = compress(evs).splitlines()
    assert lines[0] == "# 3 raw events -> 3 distinct signatures"
    assert len(lines) == 4


def test_normal_values_unchanged():
    e = _ev(user="bob", process="notepad.exe", file_hash="a" * 64)
    e.attack.append("T1059.001")
    assert e.compact() == ("10-03T22:08:05 edr process_create h=h1 u=bob "
                           f"proc=notepad.exe hash={'a' * 64} att=T1059.001")
