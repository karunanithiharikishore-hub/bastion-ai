"""BUG-INGEST-4: src_ip/dst_ip must be a real IP or None in every parser.

NUL bytes and placeholders ('-', 'N/A') used to survive, and correlate() then
linked unrelated events through them. Unparseable syslog IPs were kept as-is."""
from bastion.ingest.loader import ingest_file
from bastion.ingest.parsers import (
    _clean_ip, parse_auth, parse_azure_signin, parse_dns, parse_edr,
    parse_network, parse_syslog_line, parse_ual,
)
from bastion.pipeline.correlate import correlate


def test_clean_ip_strips_nul_and_rejects_placeholders_and_junk():
    assert _clean_ip("1.2.3.4\x00") == "1.2.3.4"
    assert _clean_ip(" 1.2.3.4:443 ") == "1.2.3.4"
    assert _clean_ip("[2001:db8::1]:443") == "2001:db8::1"
    for bad in ("-", "N/A", "", None, "999.999.999.999", "unknown", "0.0.0.0", "::"):
        assert _clean_ip(bad) is None, bad


def test_firewall_placeholder_ips_do_not_link_unrelated_events(tmp_path):
    p = tmp_path / "firewall.csv"
    p.write_text("timestamp,src_ip,dst_ip,action\n"
                 "2026-01-01T00:00:00Z,-,10.0.0.1,deny\n"
                 "2026-01-01T00:01:00Z,N/A,10.0.0.2,deny\n"
                 "2026-01-01T00:02:00Z,-,10.0.0.3,allow\n")
    ev = ingest_file(str(p))
    assert [e.src_ip for e in ev] == [None, None, None]
    assert correlate(ev) == []


def test_nul_in_ip_field_is_stripped_by_loader(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("timestamp,src_ip,action\n2026-01-01T00:00:00Z,1.2.3.4\x00,deny\n")
    assert ingest_file(str(p))[0].src_ip == "1.2.3.4"


def test_syslog_invalid_ipv4_is_not_taken_as_src_ip():
    ev = parse_syslog_line("Oct  3 22:00:00 h sshd[1]: Failed password for root "
                           "from 999.999.999.999 port 22")
    assert ev.src_ip is None


def test_syslog_skips_invalid_ip_for_next_valid_one():
    ev = parse_syslog_line("Oct  3 22:00:00 h sshd[1]: Failed password for root "
                           "from 999.1.1.1 port 22 peer 203.0.113.9")
    assert ev.src_ip == "203.0.113.9"


def test_each_structured_parser_drops_placeholder_ip():
    dash = {"src_ip": "-", "dst_ip": "N/A", "timestamp": "2026-01-01T00:00:00Z"}
    assert parse_edr({**dash, "action": "x"}).src_ip is None
    assert parse_edr({**dash, "action": "x"}).dst_ip is None
    assert parse_network({**dash, "action": "x"}).src_ip is None
    assert parse_network({**dash, "action": "x"}).dst_ip is None
    assert parse_dns({"query": "a.example", "src_ip": "-", "resolved_ip": "cdn.example"}).dst_ip is None
    assert parse_auth({**dash, "action": "x"}).src_ip is None
    assert parse_azure_signin({"User": "a@b.com", "IP address": "-",
                               "Status": "Success"}).src_ip is None
    assert parse_ual({"Operation": "UserLoggedIn", "ClientIP": "N/A",
                      "CreationTime": "2026-01-01T00:00:00Z"}).src_ip is None


def test_valid_ips_survive_every_parser():
    assert parse_edr({"action": "x", "src_ip": "10.1.1.1:55"}).src_ip == "10.1.1.1"
    assert parse_network({"action": "x", "dst_ip": "2001:db8::5"}).dst_ip == "2001:db8::5"
    assert parse_azure_signin({"User": "a@b.com", "IP address": "198.51.100.7",
                               "Status": "Success"}).src_ip == "198.51.100.7"
    assert parse_ual({"Operation": "UserLoggedIn", "ClientIP": "[2001:db8::9]:443",
                      "CreationTime": "2026-01-01T00:00:00Z"}).src_ip == "2001:db8::9"
