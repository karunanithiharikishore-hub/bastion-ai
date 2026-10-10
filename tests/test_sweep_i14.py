"""ITEM-14: T1136 must catch `net user NAME /add` and Linux useradd/adduser syslog lines;
usermod group-add is account manipulation (T1098). Deletes and plain `net user` stay clean."""
import pytest

from bastion.models import Event
from bastion.pipeline.attack import map_attack

_TS = "2026-10-03T22:00:00Z"


def _ev(message, process=None, category="other", action="log"):
    return Event(ts=_TS, source="t", category=category, action=action, message=message, process=process)


@pytest.mark.parametrize("message,process", [
    ("net user svc_x /add", "net.exe"),
    ("net1 user svc_x P@ss /add /domain", "net1.exe"),
    ("new user: name=evil, UID=1001, GID=1001, home=/home/evil, shell=/bin/bash", "useradd"),
    ("new user: name=evil", "adduser"),
])
def test_account_creation_tags_t1136(message, process):
    e = _ev(message, process)
    map_attack([e])
    assert "T1136" in e.attack, (message, process)


def test_usermod_group_add_tags_t1098():
    e = _ev("add 'evil' to group 'sudo'", "usermod")
    map_attack([e])
    assert "T1098" in e.attack
    assert "T1136" not in e.attack


@pytest.mark.parametrize("message,process", [
    ("net user svc_x /delete", "net.exe"),
    ("net user svc_x", "net.exe"),
    ("usermod[9]: changed shell of evil", "usermod"),
    ("user session opened", "sshd"),
])
def test_non_creation_is_not_tagged(message, process):
    e = _ev(message, process)
    map_attack([e])
    assert "T1136" not in e.attack, (message, process)
    assert "T1098" not in e.attack, (message, process)
