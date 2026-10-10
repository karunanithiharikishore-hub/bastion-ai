"""BUG-R4-INGEST-5: PAN-OS CSV, FortiGate key=value and Cisco ASA syslog keep ts, IPs and host."""
import os
import sys
import tempfile

import pytest

from bastion.ingest.loader import ingest_file

CASES = {
    "traffic.csv": ("Receive Time,Source address,Destination address,Application,Action,Device Name\n"
                    "2026/10/03 22:00:00,203.0.113.5,10.0.0.5,ssh,deny,PA01\n", "PA01", "203.0.113.5"),
    "fw.log": ("date=2026-10-03 time=22:00:00 devname=FGT01 srcip=203.0.113.5 dstip=10.0.0.5 action=deny\n",
               "FGT01", "203.0.113.5"),
    "asa.log": ("Oct  3 22:00:00 fw01 %ASA-4-106023: Deny tcp src outside:203.0.113.5/4444 dst inside:10.0.0.5/22 by access-group x\n",
                "fw01", "203.0.113.5"),
}


@pytest.mark.parametrize("name", CASES)
def test_firewall_formats_keep_fields(tmp_path, name):
    text, host, src = CASES[name]
    p = tmp_path / name
    p.write_text(text)
    ev = ingest_file(str(p))[0]
    assert (ev.ts.month, ev.ts.day, ev.ts.hour) == (10, 3, 22) and "ts-unparsed" not in ev.tags
    assert (ev.host, ev.src_ip, ev.dst_ip) == (host, src, "10.0.0.5")
    assert ev.action == "deny"


def test_asa_built_allows(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("Oct  3 22:00:00 fw01 %ASA-6-302013: Built inbound TCP connection 9 for outside:203.0.113.5/4444 (203.0.113.5/4444) to inside:10.0.0.5/22 (10.0.0.5/22)\n")
    ev = ingest_file(str(p))[0]
    assert (ev.action, ev.src_ip, ev.dst_ip) == ("allow", "203.0.113.5", "10.0.0.5")
