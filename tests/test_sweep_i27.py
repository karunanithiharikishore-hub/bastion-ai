"""Sweep ITEM-27: syslog auth gaps (sudo/su/vsftpd/dropbear/sshd 'not allowed', 'for directory')."""
from bluecell.ingest.parsers import parse_syslog_line

PFX = "Oct  3 22:00:01 web1 "
ATTACKER = "203.0.113.9"


def _login_failed(ev, user):
    assert ev is not None
    assert ev.category == "authentication"
    assert ev.action == "login_failed"
    assert ev.user == user
    assert ev.src_ip == ATTACKER


def test_sudo_auth_failure_keeps_actor():
    ev = parse_syslog_line(PFX + "sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; "
                                 "PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")
    assert ev.action == "login_failed" and ev.user == "bob"


def test_su_failure_keeps_actor():
    ev = parse_syslog_line(PFX + "su: FAILED SU (to root) bob on pts/0")
    assert ev.action == "login_failed" and ev.user == "bob"


def test_vsftpd_fail_login_keeps_bracketed_user():
    ev = parse_syslog_line(PFX + f'vsftpd[88]: [bob] FAIL LOGIN: Client "{ATTACKER}"')
    _login_failed(ev, "bob")


def test_pam_uppercase_user_eq_is_read():
    ev = parse_syslog_line(PFX + f"sshd[9]: pam_unix(sshd:auth): authentication failure; "
                                 f"logname= uid=0 euid=0 tty=ssh ruser= rhost={ATTACKER} USER=root")
    _login_failed(ev, "root")


def test_for_directory_is_not_a_user():
    ev = parse_syslog_line(PFX + "sshd[1]: Authentication refused: bad ownership or modes "
                                 "for directory /home/bob")
    assert ev.user is None


def test_sshd_not_allowed_is_failed_login():
    ev = parse_syslog_line(PFX + f"sshd[2]: User bob from {ATTACKER} not allowed because "
                                 "not listed in AllowUsers")
    _login_failed(ev, "bob")


def test_sshd_not_allowed_locked_account_is_failed_login():
    ev = parse_syslog_line(PFX + "sshd[3]: User root not allowed because account is locked")
    assert ev.action == "login_failed" and ev.user == "root"


def test_dropbear_bad_password_is_failed_login():
    ev = parse_syslog_line(PFX + f"dropbear[4]: Bad password attempt for 'root' from {ATTACKER}:5555")
    _login_failed(ev, "root")


def test_dropbear_nonexistent_user_is_failed_login_without_user():
    ev = parse_syslog_line(PFX + f"dropbear[5]: Login attempt for nonexistent user from {ATTACKER}:5555")
    assert ev.action == "login_failed"
    assert ev.user is None
    assert ev.src_ip == ATTACKER


def test_dropbear_password_auth_succeeded_is_login_success():
    ev = parse_syslog_line(PFX + f"dropbear[6]: Password auth succeeded for 'bob' from {ATTACKER}:5555")
    assert ev.category == "authentication"
    assert ev.action == "login_success"
    assert ev.user == "bob"
