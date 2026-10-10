"""BUG-INGEST-22: Defender DeviceLogonEvents put RemoteIP (the client) in dst_ip,
so brute-force grouping and attacker-IP logic keyed on src_ip saw no source."""
import json

from bastion.ingest.loader import ingest_file
from bastion.ingest.parsers import parse_edr


def test_logon_remote_ip_is_src_ip_and_local_ip_is_dst_ip(tmp_path):
    p = tmp_path / "DeviceLogonEvents.json"
    p.write_text(json.dumps([{"Timestamp": "2026-01-01T00:00:00Z", "DeviceName": "pc1",
                              "ActionType": "LogonFailed", "AccountName": "alice",
                              "RemoteIP": "8.8.8.8", "LocalIP": "10.0.0.5"}]))
    ev = ingest_file(str(p))[0]
    assert ev.category == "authentication"
    assert (ev.src_ip, ev.dst_ip) == ("8.8.8.8", "10.0.0.5")
    assert ev.message == "logon failed for alice from 8.8.8.8"


def test_logon_without_local_ip_keeps_remote_ip_in_dst_ip():
    ev = parse_edr({"DeviceName": "pc1", "ActionType": "LogonSuccess", "AccountName": "alice",
                    "RemoteIP": "8.8.8.8"})
    assert (ev.src_ip, ev.dst_ip) == ("8.8.8.8", "8.8.8.8")


def test_device_network_keeps_local_src_and_remote_dst():
    ev = parse_edr({"DeviceName": "pc1", "ActionType": "ConnectionSuccess",
                    "RemoteIP": "8.8.8.8", "RemotePort": 443, "LocalIP": "10.0.0.5"})
    assert (ev.src_ip, ev.dst_ip) == ("10.0.0.5", "8.8.8.8")
