"""BUG-R4-INGEST-4: a successful sshd login must not be classified as a failure
just because the username or host contains "fail"."""
import pytest

from bluecell.ingest.parsers import parse_syslog_line


@pytest.mark.parametrize("user", ["failover", "testfail", "failsafe", "failed"])
def test_accepted_login_with_fail_in_username_is_success(user):
    ev = parse_syslog_line(
        "Oct  3 22:00:00 web1 sshd[1]: Accepted password for %s from 10.0.0.5 port 5555 ssh2" % user)
    assert ev.action == "login_success" and ev.severity == 1
    assert ev.user == user


def test_accepted_publickey_with_fail_user_is_success():
    ev = parse_syslog_line(
        "Oct  3 22:00:01 web1 sshd[1]: Accepted publickey for testfail from 10.0.0.5 port 22 ssh2")
    assert ev.action == "login_success"


def test_real_failure_still_login_failed():
    ev = parse_syslog_line(
        "Oct  3 22:00:02 web1 sshd[1]: Failed password for failover from 10.0.0.5 port 22 ssh2")
    assert ev.action == "login_failed" and ev.severity == 3
