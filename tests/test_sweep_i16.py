"""ITEM-16: common attacker actions get an ATT&CK tag; the read-only / benign twin of each does not."""
import pytest

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bastion.models import Event
from bastion.pipeline import map_attack


def _attack(category, message, action="x"):
    e = Event(ts="2026-10-03T22:00:00Z", source="s", category=category, action=action, message=message)
    map_attack([e])
    return set(e.attack)


CASES = [  # (category, malicious, benign, technique)
    ("process", "wevtutil cl Security", "wevtutil qe Security /c:5", "T1070.001"),
    ("process", "Clear-EventLog -LogName Security", "Get-EventLog -LogName Security", "T1070.001"),
    ("process", "EventID 1102 The audit log was cleared", "EventID 11020 service started", "T1070.001"),
    ("process", "netsh advfirewall set allprofiles state off", "netsh advfirewall show allprofiles state", "T1562.004"),
    ("process", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d C:\\x.exe",
     "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "T1547.001"),
    ("process", "mimikatz sekurlsa::logonpasswords", "lsass.exe started by wininit", "T1003"),
    ("process", "Invoke-Mimikatz -DumpCreds", "anti-mimikatz signature pack loaded", "T1003"),
    ("process", "EventID 4720 A user account was created", "EventID 4722 A user account was enabled", "T1136"),
    ("cloud_api", "x", "x", "T1562.008"),  # action-driven, below
    ("network", "upload completed to 203.0.113.9", "file upload completed 12KB to s3 bucket by backup job", "T1048"),
]


@pytest.mark.parametrize("cat,bad,good,tid", CASES)
def test_positive_and_negative(cat, bad, good, tid):
    if tid == "T1562.008":
        assert tid in _attack(cat, "cloudtrail call", action="StopLogging")
        assert tid in _attack(cat, "cloudtrail call", action="DeleteTrail")
        assert tid not in _attack(cat, "cloudtrail call", action="StartLogging")
        assert tid not in _attack(cat, "cloudtrail call", action="DescribeTrails")
        return
    assert tid in _attack(cat, bad)
    assert tid not in _attack(cat, good)
