"""ITEM-24: CEF/auditd/CLF/Squid/VPC/Zeek/UFW lines yield real IPs, ts and categories."""
import pytest

from bluecell.ingest.loader import ingest_file

TAB = "\t"
CASES = {
    "cef.log": ("CEF:0|Acme|IDS|1.0|100|SSH brute force login|8|src=203.0.113.5 dst=10.0.0.5 spt=4444 dpt=22 act=blocked suser=bob rt=1791064800000",
                "authentication", "203.0.113.5", "10.0.0.5", 22, "bob"),
    "audit.log": ("type=USER_AUTH msg=audit(1791064800.123:501): pid=88 uid=0 auid=1000 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=203.0.113.5 addr=203.0.113.5 terminal=ssh res=failed'",
                  "authentication", "203.0.113.5", None, None, "root"),
    "access.log": ('203.0.113.5 - - [03/Oct/2026:22:00:00 +0000] "GET /admin HTTP/1.1" 401 512 "-" "curl/8"',
                   "authentication", "203.0.113.5", None, None, None),
    "squid.log": ("1791064800.123    150 203.0.113.5 TCP_DENIED/403 3500 CONNECT evil.example.com:443 - HIER_NONE/- -",
                  "network", "203.0.113.5", None, None, None),
    "vpc.log": ("2 123456789010 eni-0a1b2c3d 203.0.113.5 10.0.0.5 4444 22 6 20 4249 1791064800 1791064860 REJECT OK",
                "network", "203.0.113.5", "10.0.0.5", 22, None),
    "ufw.log": ("Oct  3 22:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=4444 DPT=22",
                "network", "203.0.113.5", "10.0.0.5", 22, None),
}


@pytest.mark.parametrize("name", CASES)
def test_line(tmp_path, name):
    line, cat, src, dst, dport, user = CASES[name]
    p = tmp_path / name
    p.write_text(line + "\n")
    (ev,) = ingest_file(str(p))
    assert (ev.category, ev.src_ip, ev.dst_ip, ev.dst_port, ev.user) == (cat, src, dst, dport, user)
    assert "ts-unparsed" not in ev.tags


def test_zeek(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text(TAB.join(["#fields", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "conn_state"]) + "\n"
                 "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\n"
                 + TAB.join(["1791064800.1", "C1", "203.0.113.5", "4444", "10.0.0.5", "22", "S0"]) + "\n")
    (ev,) = ingest_file(str(p))
    assert (ev.src_ip, ev.dst_ip, ev.dst_port) == ("203.0.113.5", "10.0.0.5", 22)


def test_sshd_syslog_unchanged(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("Oct  3 22:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 4444 ssh2\n")
    (ev,) = ingest_file(str(p))
    assert ev.category == "authentication" and ev.src_ip == "203.0.113.5" and ev.user == "root"
