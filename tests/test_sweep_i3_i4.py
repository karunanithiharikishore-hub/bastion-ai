from datetime import datetime, timezone

from bluecell.models import Event
from bluecell.pipeline.attack import map_attack
from bluecell.pipeline.correlate import correlate
from bluecell.report.rca import _assess_rules as assess

_T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _net(action, msg="conn"):
    return Event(ts=_T, source="firewall", category="network", action=action, message=msg,
                 src_ip="10.0.0.9", dst_ip="10.0.0.5", dst_port=22)


def test_non_allow_actions_untagged():
    for a in ("discard", "aged-out", "close", "N/A", "quarantine", "tcp-fin", "filtered"):
        assert not map_attack([_net(a)])[0].attack, a
    assert not map_attack([_net("connection", "Teardown TCP connection")])[0].attack
    assert map_attack([_net("built")])[0].attack == ["T1021"]


def test_port_hit_plus_one_failed_login_not_malicious():
    ev = [_net("allow"), Event(ts=_T, source="auth", category="authentication", action="login_failed",
                               message="Failed password for alice", src_ip="10.0.0.9", severity=3)]
    inc = correlate(map_attack(ev), min_events=1)[0]
    assert inc.score() >= 50
    assert assess(inc)["level"] != "likely-malicious"
