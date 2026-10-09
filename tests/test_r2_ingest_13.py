"""BUG-INGEST-13: key-based / PAM-interactive sshd failures, invalid-user probes
and failed su must classify as login_failed (severity 3)."""
import pytest

from bluecell.ingest.parsers import parse_syslog_line


@pytest.mark.parametrize("msg", [
    "sshd[1]: Failed publickey for root from 1.2.3.4 port 22 ssh2: RSA SHA256:abc",
    "sshd[1]: Failed none for invalid user bob from 1.2.3.4 port 22 ssh2",
    "sshd[1]: Failed keyboard-interactive/pam for root from 1.2.3.4 port 22 ssh2",
    "sshd[1]: Invalid user admin from 1.2.3.4 port 5555",
    "sshd[1]: error: maximum authentication attempts exceeded for root from 1.2.3.4 port 22 ssh2 [preauth]",
    "su[1]: FAILED su for root by bob",
])
def test_auth_failures_classified_as_login_failed(msg):
    ev = parse_syslog_line("Oct  3 22:00:00 h " + msg)
    assert ev.action == "login_failed" and ev.severity == 3 and ev.category == "authentication"


def test_invalid_user_probe_keeps_source_ip():
    ev = parse_syslog_line("Oct  3 22:00:00 h sshd[1]: Invalid user admin from 1.2.3.4 port 5555")
    assert ev.src_ip == "1.2.3.4"


def test_negative_controls_unchanged():
    # Non-auth process with failure wording but no password/auth/login keyword stays benign.
    assert parse_syslog_line("Oct  3 22:00:00 h myapp[1]: Invalid user x").action == "log"
    # Non-auth systemd failure is not a login failure (existing guard).
    assert parse_syslog_line(
        "Oct  3 22:00:00 h systemd[1]: Failed to start User Login Management").action != "login_failed"
    # Successful key login is still login_success.
    assert parse_syslog_line(
        "Oct  3 22:00:00 h sshd[1]: Accepted publickey for jsmith from 10.0.5.20 port 51026 ssh2"
    ).action == "login_success"
