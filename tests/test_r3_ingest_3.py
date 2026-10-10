"""BUG-R3-INGEST-3: non-cloud logon brute force must not blame a mail client."""
from bastion.models import Event
from bastion.pipeline import map_attack, correlate
from bastion.report.rca import assess_incident

T = "2026-09-26T09:%02d:00Z"


def _brute(source, n=40):
    evs = [Event(ts=T % (i % 60), source=source, host="srv01", category="authentication",
                 action="LogonFailed", message="An account failed to log on",
                 user="admin", src_ip="203.0.113.50") for i in range(n)]
    map_attack(evs)
    return assess_incident(correlate(evs)[0])


def test_edr_logon_brute_force_does_not_blame_mail_client():
    v = _brute("edr")
    assert "mail client" not in v["why"]
    assert "expired password" not in v["why"]
    assert "mistyped password or a stale credential" in v["why"]


def test_syslog_logon_brute_force_does_not_blame_mail_client():
    v = _brute("syslog")
    assert "mail client" not in v["why"]


def test_cloud_signin_still_blames_device_credential():
    v = _brute("azure_ad", n=36)
    assert "mail client" in v["why"]
