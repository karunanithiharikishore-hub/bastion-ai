"""ITEM-28: a firewall-shaped CSV (src_ip/dst_ip/dst_port) must parse as network traffic
even when its filename contains an earlier-listed hint (azure, cloud, auth, dns)."""
from bluecell.ingest.loader import ingest_file

CSV = ("timestamp,src_ip,dst_ip,dst_port,action\n"
       "2026-10-03T22:00:00Z,203.0.113.5,10.0.0.5,22,deny\n")


def test_firewall_shaped_csv_keeps_dst_fields_whatever_the_filename(tmp_path):
    for name in ("azure_firewall.csv", "cloudflare_firewall.csv",
                 "auth_gateway_traffic.csv", "dns_over_https_network.csv"):
        p = tmp_path / name
        p.write_text(CSV)
        evs = ingest_file(str(p))
        assert len(evs) == 1, name
        assert evs[0].category == "network", name
        assert evs[0].dst_ip == "10.0.0.5" and str(evs[0].dst_port) == "22", name
