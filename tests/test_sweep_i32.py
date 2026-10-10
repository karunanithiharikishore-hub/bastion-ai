"""ITEM-32: parse_dns must put the client IP in src_ip and the answer IP in dst_ip,
and read the common client/qname field names, so DNS events link to firewall events.
Sample: a DGA-like domain resolved by a LAN client to a TEST-NET-3 address, followed by
a 443 connection to that same address (likely real C2 beaconing)."""
from bluecell.ingest.parsers import parse_dns


def test_dns_client_and_answer_become_src_and_dst_ip():
    ev = parse_dns({"timestamp": "2026-10-03T22:00:00Z", "query": "abcdefghijklmnop12.xyz",
                    "client": "10.0.0.5", "answer": "203.0.113.9"})
    assert ev.src_ip == "10.0.0.5"
    assert ev.dst_ip == "203.0.113.9"
    assert ev.host != "10.0.0.5"


def test_dns_reads_alternate_client_and_qname_fields():
    for key in ("client_ip", "source_ip", "srcip", "src", "id.orig_h"):
        ev = parse_dns({"timestamp": "2026-10-03T22:00:00Z", "qname": "abcdefghijklmnop12.xyz",
                        key: "10.0.0.5"})
        assert ev is not None, "qname alias not recognised"
        assert ev.src_ip == "10.0.0.5", key
        assert ev.domain == "abcdefghijklmnop12.xyz", key
