"""BUG-INGEST-15: a firewall CSV's `source`/`destination` address columns must map to
src_ip/dst_ip; Event.source comes from the device type, not from an address."""
import os

from bluecell.ingest.loader import ingest_file
from bluecell.ingest.parsers import parse_auth, parse_network


def test_firewall_csv_source_destination_addresses_map_to_ips(tmp_path):
    p = tmp_path / "firewall.csv"
    p.write_text("timestamp,source,destination,port,action\n"
                 "2026-01-01T00:00:00Z,10.0.0.5,8.8.8.8,53,deny\n")
    e = ingest_file(str(p))[0]
    assert (e.source, e.src_ip, e.dst_ip) == ("firewall", "10.0.0.5", "8.8.8.8")
    assert e.message == "10.0.0.5 -> 8.8.8.8:53"


def test_non_ip_source_is_still_the_log_source_label():
    e = parse_network({"action": "deny", "source": "fw-edge01", "destination": "8.8.8.8"})
    assert e.source == "fw-edge01"
    assert e.src_ip is None and e.dst_ip == "8.8.8.8"


def test_device_type_labels_source_when_source_is_an_address():
    e = parse_network({"action": "deny", "source": "10.0.0.5", "device_type": "palo-alto"})
    assert e.source == "palo-alto" and e.src_ip == "10.0.0.5"


def test_auth_source_address_maps_to_src_ip():
    e = parse_auth({"action": "fail", "source": "203.0.113.9", "user": "bob"})
    assert e.source == "auth" and e.src_ip == "203.0.113.9"
