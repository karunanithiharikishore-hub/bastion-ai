"""ITEM-38 regression: domain IOCs are hostnames, DNS/C2-only suspicion, and no
hash IOCs mined from bare 32-hex ids in messages."""
from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from datetime import datetime, timezone

from bastion.models import Event
from bastion.pipeline import extract_iocs

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(**kw):
    base = dict(ts=T0, source="edr", category="process", action="proc_start",
                message="powershell.exe", host="h1", user="bob")
    base.update(kw)
    return Event(**base)


def test_remote_url_domain_is_hostname_and_not_suspicious_for_t1059():
    ev = _ev(domain="https://update.microsoft.com/path?x=1", process="powershell.exe")
    ev.attack.append("T1059")
    dom = extract_iocs([ev])["domain"]
    assert [d["value"] for d in dom] == ["update.microsoft.com"]
    assert dom[0]["suspicious"] is False


def test_domain_suspicious_when_dns_c2_technique_fired():
    ev = _ev(domain="https://evil.example.net/x")
    ev.attack.append("T1071.004")
    dom = extract_iocs([ev])["domain"][0]
    assert dom["value"] == "evil.example.net" and dom["suspicious"] is True


def test_bare_32_hex_id_in_message_is_not_a_hash_ioc():
    ev = _ev(message="powershell.exe -SessionId 0123456789abcdef0123456789abcdef")
    ev.attack.append("T1059")
    assert extract_iocs([ev])["hash"] == []


def test_file_hash_field_still_yields_hash_ioc():
    h = "0123456789abcdef0123456789abcdef"
    ev = _ev(file_hash=h)
    ev.attack.append("T1059")
    hashes = extract_iocs([ev])["hash"]
    assert [x["value"] for x in hashes] == [h] and hashes[0]["suspicious"] is True
