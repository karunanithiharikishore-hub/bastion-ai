from datetime import datetime, timezone

from bluecell.models import Event
from bluecell.pipeline.attack import map_attack


def _ev(dst_ip, port, action="allow", msg="conn"):
    return map_attack([Event(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="firewall", category="network", action=action,
                             message=msg, src_ip="10.0.0.5", dst_ip=dst_ip, dst_port=port)])[0]


def test_allowed_internal_rdp():
    assert "T1021" in _ev("10.0.0.9", 3389).attack


def test_denied_rdp_no_tag():
    assert not _ev("10.0.0.9", 3389, "deny").attack


def test_public_ssh_not_lateral():
    assert not _ev("8.8.8.8", 22).attack


def test_internal_smb():
    assert "T1021" in _ev("192.168.1.2", 445).attack


def test_text_fallback_and_no_double_tag():
    e = _ev("8.8.8.8", 80, msg="psexec session")
    assert e.attack == ["T1021"]
    e = _ev("10.0.0.9", 3389, msg="rdp login")
    assert len([t for t in e.tags if t.startswith("attack:T1021")]) == 1
