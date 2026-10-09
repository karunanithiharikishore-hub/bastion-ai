"""BUG-INGEST-14: syslog 'for/user/account X' takes a user only in auth context,
so non-auth lines do not get a bogus user that correlates unrelated hosts."""
import pytest

from bluecell.ingest.parsers import parse_syslog_line


@pytest.mark.parametrize("msg", [
    "db1 systemd[1]: Waiting for network to come online",
    "mail1 postfix/qmgr[1]: warning: queue file for network is old",
    "web1 dhclient[1]: DHCPREQUEST for 10.0.0.5 on eth0 to 10.0.0.1 port 67",
    "web1 cron[1]: account for backup is locked",
])
def test_non_auth_lines_have_no_user(msg):
    assert parse_syslog_line("Oct  3 22:00:00 " + msg).user is None


def test_non_auth_lines_do_not_correlate_hosts():
    from bluecell.pipeline.correlate import correlate
    ev = [parse_syslog_line("Oct  3 22:00:%02d %s" % (i, m)) for i, m in enumerate([
        "db1 systemd[1]: Waiting for network to come online",
        "mail1 postfix/qmgr[1]: warning: queue file for network is old",
        "db2 systemd[1]: Waiting for network to come online",
    ])]
    assert all(e.user is None for e in ev)


@pytest.mark.parametrize("msg,user", [
    ("sshd[1]: pam_unix(sshd:session): session closed for user jsmith", "jsmith"),
    ("sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", "root"),
    ("myapp[1]: Failed password for bob from 1.2.3.4 port 22", "bob"),
    ("sshd[1]: Accepted publickey for jsmith from 10.0.5.20 port 51026 ssh2", "jsmith"),
    ("myapp[1]: authentication failure; logname= uid=0 rhost=1.2.3.4  user=carol", "carol"),
])
def test_auth_context_still_extracts_user(msg, user):
    assert parse_syslog_line("Oct  3 22:00:00 h " + msg).user == user
