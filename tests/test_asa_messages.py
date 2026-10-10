"""Cisco ASA message ids beyond 106023/302013 parse to network or authentication events."""
import pytest

from bluecell.ingest.parsers import parse_syslog_line
from bluecell.pipeline.attack import map_attack

PFX = "Oct 10 10:00:00 fw01 "

# (ASA line, category, action, src_ip, dst_ip, dst_port, user)
CASES = [
    ("%ASA-2-106001: Inbound TCP connection denied from 203.0.113.5/4444 to 10.0.0.5/22 flags SYN  on interface outside",
     "network", "deny", "203.0.113.5", "10.0.0.5", "22", None),
    ("%ASA-2-106006: Deny inbound UDP from 203.0.113.5/53 to 10.0.0.5/5353 on interface outside",
     "network", "deny", "203.0.113.5", "10.0.0.5", "5353", None),
    ("%ASA-2-106007: Deny inbound UDP from 203.0.113.5/53 to 10.0.0.5/5353 due to DNS Response",
     "network", "deny", "203.0.113.5", "10.0.0.5", "5353", None),
    ("%ASA-3-106014: Deny inbound icmp src outside:203.0.113.5 dst inside:10.0.0.5 (type 8, code 0)",
     "network", "deny", "203.0.113.5", "10.0.0.5", None, None),
    ("%ASA-6-106015: Deny TCP (no connection) from 203.0.113.5/4444 to 10.0.0.5/22 flags RST  on interface outside",
     "network", "deny", "203.0.113.5", "10.0.0.5", "22", None),
    ("%ASA-1-106021: Deny ICMP reverse path check from 203.0.113.5 to 10.0.0.5 on interface outside",
     "network", "deny", "203.0.113.5", "10.0.0.5", None, None),
    ("%ASA-4-106100: access-list outside_in denied tcp outside/203.0.113.5(4444) -> inside/10.0.0.5(22) hit-cnt 1 first hit",
     "network", "deny", "203.0.113.5", "10.0.0.5", "22", None),
    ("%ASA-3-710003: TCP access denied by ACL from 203.0.113.5/4444 to outside:10.0.0.1/22",
     "network", "deny", "203.0.113.5", "10.0.0.1", "22", None),
    ("%ASA-6-302014: Teardown TCP connection 12345 for outside:203.0.113.5/4444 to inside:10.0.0.5/22 duration 0:00:01 bytes 123 TCP FINs",
     "network", "connection", "203.0.113.5", "10.0.0.5", "22", None),
    ("%ASA-6-302015: Built outbound UDP connection 1 for outside:203.0.113.5/53 (203.0.113.5/53) to inside:10.0.0.5/5353 (10.0.0.5/5353)",
     "network", "allow", "203.0.113.5", "10.0.0.5", "5353", None),
    ("%ASA-6-302016: Teardown UDP connection 1 for outside:203.0.113.5/53 to inside:10.0.0.5/5353 duration 0:00:02 bytes 80",
     "network", "connection", "203.0.113.5", "10.0.0.5", "5353", None),
    ("%ASA-6-305011: Built dynamic TCP translation from inside:10.0.0.5/5000 to outside:198.51.100.7/5000",
     "network", "allow", "10.0.0.5", "198.51.100.7", "5000", None),
    ("%ASA-6-305012: Teardown dynamic TCP translation from inside:10.0.0.5/5000 to outside:198.51.100.7/5000 duration 0:00:30",
     "network", "connection", "10.0.0.5", "198.51.100.7", "5000", None),
    ("%ASA-6-113004: AAA user authentication Successful : local database : user = admin",
     "authentication", "login_success", None, None, None, "admin"),
    ("%ASA-6-113005: AAA user authentication Rejected : reason = Invalid password : local database : user = admin : user IP = 203.0.113.5",
     "authentication", "login_failed", "203.0.113.5", None, None, "admin"),
    ("%ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = admin : user IP = 203.0.113.5",
     "authentication", "login_failed", "203.0.113.5", None, None, "admin"),
    ("%ASA-6-605004: Login denied from 203.0.113.5/4444 to inside:10.0.0.5/ssh for user \"admin\"",
     "authentication", "login_failed", "203.0.113.5", None, None, "admin"),
    ("%ASA-6-605005: Login permitted from 203.0.113.5/4444 to inside:10.0.0.5/ssh for user \"admin\"",
     "authentication", "login_success", "203.0.113.5", None, None, "admin"),
    ("%ASA-6-611101: User authentication succeeded: IP address: 203.0.113.5, Uname: admin",
     "authentication", "login_success", "203.0.113.5", None, None, "admin"),
    ("%ASA-6-611102: User authentication failed: IP address: 203.0.113.5, Uname: admin",
     "authentication", "login_failed", "203.0.113.5", None, None, "admin"),
]


@pytest.mark.parametrize("body,category,action,src,dst,port,user", CASES, ids=[c[0][:12] for c in CASES])
def test_asa_id_fields(body, category, action, src, dst, port, user):
    ev = parse_syslog_line(PFX + body)
    assert (ev.category, ev.action, ev.src_ip, ev.dst_ip, ev.user) == (category, action, src, dst, user)
    assert ev.host == "fw01"
    if port:   # Event has no port field; the port survives in the message text
        assert f"/{port}" in ev.message or f"({port})" in ev.message or f" {port} " in ev.message


def test_unknown_asa_id_stays_plain_log():
    ev = parse_syslog_line(PFX + "%ASA-6-110002: Failed to locate egress interface for protocol ICMP from outside:203.0.113.5")
    assert (ev.category, ev.action) == ("other", "log")


def test_six_113015_failures_from_one_ip_are_t1110():
    line = next(c[0] for c in CASES if "%ASA-6-113015" in c[0])
    events = [parse_syslog_line(PFX + line) for _ in range(6)]
    map_attack(events)
    assert all("T1110" in ev.attack for ev in events)
    assert all(ev.src_ip == "203.0.113.5" for ev in events)
