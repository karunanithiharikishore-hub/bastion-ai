"""Sweep ITEM-25 (syslog header variants) and ITEM-26 (ASA regex ReDoS)."""
import time

from bluecell.ingest.parsers import parse_syslog_line

ATTACK = "Failed password for root from 203.0.113.9 port 4000 ssh2"


def _check_bruteforce(ev, host="web1"):
    assert ev is not None
    assert ev.category == "authentication"
    assert ev.action == "login_failed"
    assert ev.host == host
    assert ev.user == "root"
    assert ev.src_ip == "203.0.113.9"


def test_bsd_fractional_seconds_stamp():
    ev = parse_syslog_line(f"Oct  3 22:00:06.123 web1 sshd[1]: {ATTACK}")
    _check_bruteforce(ev)
    assert (ev.ts.month, ev.ts.day, ev.ts.hour, ev.ts.minute, ev.ts.second) == (10, 3, 22, 0, 6)
    assert "ts-unparsed" not in ev.tags


def test_bsd_year_in_stamp():
    ev = parse_syslog_line(f"Oct  3 2019 22:00:03 web1 sshd[1]: {ATTACK}")
    _check_bruteforce(ev)
    assert ev.ts.year == 2019 and ev.ts.hour == 22
    assert "ts-unparsed" not in ev.tags


def test_journalctl_short_full_stamp():
    ev = parse_syslog_line(f"Sat 2026-10-03 22:00:02 UTC web1 sshd[1]: {ATTACK}")
    _check_bruteforce(ev)
    assert (ev.ts.year, ev.ts.month, ev.ts.day, ev.ts.hour) == (2026, 10, 3, 22)


def test_cisco_star_prefix_login_failed():
    # Cisco IOS has no host field; the user and source come from the bracketed fields.
    ev = parse_syslog_line("*Oct  3 22:00:07.123: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] "
                           "[Source: 203.0.113.9] [localport: 22] [Reason: Login Authentication Failed] "
                           "at 22:00:07 UTC Sat Oct 3 2026")
    assert ev is not None
    assert ev.category == "authentication"
    assert ev.action == "login_failed"
    assert ev.user == "admin"
    assert ev.src_ip == "203.0.113.9"
    assert (ev.ts.month, ev.ts.day, ev.ts.hour) == (10, 3, 22)


def test_tag_with_parens_pam_unix():
    ev = parse_syslog_line("Oct  8 22:00:08 web1 sshd(pam_unix)[1]: authentication failure; logname= uid=0 "
                           "euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root")
    _check_bruteforce(ev)


def test_long_asa_line_parses_fast():
    # ITEM-26: ~40 KB %ASA line used to take seconds (quadratic backtracking in _ASA_RE).
    line = "Oct  3 22:00:00 fw %ASA-4-106023: Deny " + "src x:1/2 " * 4000
    t0 = time.perf_counter()
    ev = parse_syslog_line(line)
    elapsed = time.perf_counter() - t0
    assert ev is not None
    assert elapsed < 0.5, f"parse took {elapsed:.2f}s"
