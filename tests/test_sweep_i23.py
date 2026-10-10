"""ITEM-23 regression: Okta, Suricata, Zeek, Wazuh, Falco, k8s/GCP audit and PAN JSON
keep ts, an IP pair and their summary text instead of falling to the EDR fallback."""
import json
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)

from bastion.ingest.loader import ingest_file

RECS = {
    "okta": {"published": "2026-10-03T22:00:00.123Z", "eventType": "user.session.start",
             "displayMessage": "User login to Okta", "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
             "actor": {"alternateId": "bob@corp.com"}, "client": {"ipAddress": "203.0.113.9"}},
    "suricata": {"timestamp": "2026-10-03T22:00:00.123456+0000", "event_type": "alert", "src_ip": "203.0.113.9",
                 "src_port": 51000, "dest_ip": "10.0.0.5", "dest_port": 445, "proto": "TCP",
                 "alert": {"signature": "ET EXPLOIT MS17-010 EternalBlue", "severity": 1}},
    "zeek": {"ts": 1791064800.5, "uid": "CHhAvVGS1DHFjwGM9", "id.orig_h": "10.0.0.5", "id.orig_p": 49152,
             "id.resp_h": "203.0.113.9", "id.resp_p": 4444, "proto": "tcp"},
    "wazuh": {"timestamp": "2026-10-03T22:00:00.000+0000", "rule": {"id": "5710", "level": 10,
              "description": "sshd: Attempt to login using a non-existent user"},
              "agent": {"id": "001", "name": "web01"}, "data": {"srcip": "203.0.113.9", "srcuser": "admin"}},
    "falco": {"time": "2026-10-03T22:00:00.123456789Z", "priority": "Critical", "rule": "Reverse shell",
              "output": "Outbound connection from shell in container (proc=bash)", "hostname": "node1",
              "output_fields": {"fd.cip": "10.0.0.5", "fd.sip": "203.0.113.9"}},
    "k8s": {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "verb": "list", "stageTimestamp": "2026-10-03T22:00:00.123456Z",
            "requestURI": "/api/v1/namespaces/kube-system/secrets", "user": {"username": "system:anonymous"},
            "sourceIPs": ["203.0.113.9"]},
    "gcp": {"timestamp": "2026-10-03T22:00:00Z", "protoPayload": {"methodName": "SetIamPolicy",
            "authenticationInfo": {"principalEmail": "eve@corp.com"}, "requestMetadata": {"callerIp": "203.0.113.9"}}},
    "pan": {"receive_time": "2026/10/03 22:00:00", "type": "TRAFFIC", "src": "203.0.113.9", "dst": "10.0.0.5",
            "dport": 445, "action": "deny"},
}


def load(tmp_path, name):
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(RECS[name]))
    evs = ingest_file(str(p))
    assert len(evs) == 1
    assert "ts-unparsed" not in evs[0].tags
    return evs[0]


def test_okta(tmp_path):
    ev = load(tmp_path, "okta")
    assert (ev.action, ev.user, ev.src_ip) == ("login_failed", "bob@corp.com", "203.0.113.9")


def test_suricata(tmp_path):
    ev = load(tmp_path, "suricata")
    assert "EternalBlue" in ev.message and (ev.src_ip, ev.dst_ip, ev.dst_port) == ("203.0.113.9", "10.0.0.5", 445)


def test_zeek(tmp_path):
    ev = load(tmp_path, "zeek")
    assert (ev.src_ip, ev.dst_ip, ev.dst_port) == ("10.0.0.5", "203.0.113.9", 4444)


def test_wazuh(tmp_path):
    ev = load(tmp_path, "wazuh")
    assert "non-existent user" in ev.message and ev.src_ip == "203.0.113.9" and ev.host == "web01"


def test_falco(tmp_path):
    ev = load(tmp_path, "falco")
    assert "shell" in ev.message and ev.dst_ip == "203.0.113.9" and ev.host == "node1"


def test_k8s_audit(tmp_path):
    ev = load(tmp_path, "k8s")
    assert (ev.action, ev.user, ev.src_ip) == ("list", "system:anonymous", "203.0.113.9")


def test_gcp_audit(tmp_path):
    ev = load(tmp_path, "gcp")
    assert (ev.action, ev.user, ev.src_ip) == ("SetIamPolicy", "eve@corp.com", "203.0.113.9")


def test_pan_json(tmp_path):
    ev = load(tmp_path, "pan")
    assert (ev.src_ip, ev.dst_ip, ev.dst_port, ev.action) == ("203.0.113.9", "10.0.0.5", 445, "deny")
