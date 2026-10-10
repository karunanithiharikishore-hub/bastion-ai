from datetime import datetime, timezone

from bluecell.ingest.parsers import parse_edr, parse_network, parse_syslog_line
from bluecell.models import Event


def test_firewall_row_ports():
    e = parse_network({"timestamp": "2026-01-01T00:00:00Z", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
                       "src_port": "51000", "dst_port": "443"})
    assert (e.src_port, e.dst_port) == (51000, 443)


def test_panos_headers():
    e = parse_network({"Receive Time": "2026-01-01 00:00:00", "Source Address": "10.0.0.1",
                       "Destination Address": "8.8.8.8", "Source Port": "1234", "Destination Port": "3389"})
    assert (e.src_port, e.dst_port) == (1234, 3389)


def test_defender_remote_port():
    e = parse_edr({"Timestamp": "2026-01-01T00:00:00Z", "DeviceName": "h", "ActionType": "ConnectionSuccess",
                   "LocalIP": "10.0.0.1", "RemoteIP": "8.8.8.8", "LocalPort": 50000, "RemotePort": 445})
    assert (e.src_port, e.dst_port) == (50000, 445)


def test_fortigate_ports():
    e = parse_syslog_line("date=2026-01-01 time=00:00:00 devname=fw srcip=10.0.0.1 srcport=4444 "
                          "dstip=8.8.8.8 dstport=22 action=accept")
    assert (e.src_port, e.dst_port) == (4444, 22)


def test_asa_ipv4_and_ipv6_endpoints():
    e = parse_syslog_line("%ASA-4-106023: Deny tcp src outside:1.2.3.4/5555 dst inside:10.0.0.5/3389 by access-group x")
    assert (e.src_port, e.dst_port) == (5555, 3389)
    e = parse_syslog_line("%ASA-4-106023: Deny tcp src outside:2001:db8::1/5555 dst inside:2001:db8::2/443 by access-group x")
    assert (e.src_ip, e.src_port, e.dst_port) == ("2001:db8::1", 5555, 443)
    e = parse_syslog_line("%ASA-2-106001: Inbound TCP connection denied from 1.2.3.4/1000 to 10.0.0.5/80 flags SYN")
    assert (e.src_port, e.dst_port) == (1000, 80)


def test_invalid_ports_dropped():
    for bad in ("nosuchservice", -1, 70000, "65536", True, 1.5, "", None, "80x"):
        e = Event(ts=datetime.now(timezone.utc), source="s", category="network", action="a", message="m",
                  src_port=bad, dst_port=bad)
        assert e.src_port is None and e.dst_port is None, bad
    assert Event(ts=datetime.now(timezone.utc), source="s", category="network", action="a", message="m",
                 dst_port="0").dst_port == 0


def test_ports_not_entities_or_id_and_shown_in_compact():
    kw = dict(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="s", category="network", action="a", message="m",
              src_ip="1.1.1.1", dst_ip="2.2.2.2")
    a, b = Event(**kw), Event(**kw, dst_port=443)
    assert a.event_id == b.event_id and a.entities() == b.entities()
    assert "dp=443" in b.compact() and "dp=" not in a.compact()
    assert b.to_dict()["dst_port"] == 443


def test_toolbox_dst_port_filter(tmp_path):
    import json
    from bluecell.agents.toolbox import Blackboard, SecurityToolbox
    from bluecell.agents.base import AgentContext
    evs = [Event(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="fw", category="network", action="a",
                 message=f"m{p}", dst_port=p) for p in (22, 443)]
    box = SecurityToolbox(AgentContext(events=evs, incidents=[], iocs={}, digest=""), "t", "T",
                          Blackboard(str(tmp_path / "b.jsonl")))
    assert json.loads(box.call("search_events", {"dst_port": 22}))["matches"] == 1


def test_named_ports_map_to_numbers():
    from bluecell.models import _port
    assert _port("https") == 443 and _port("SSH") == 22 and _port("netbios-ssn") == 139
