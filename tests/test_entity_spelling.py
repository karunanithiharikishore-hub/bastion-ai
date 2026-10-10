"""One machine / one person under different spellings must correlate together."""
from datetime import datetime, timezone

from bastion.models import Event
from bastion.pipeline.correlate import correlate


def _ev(minute, **kw):
    return Event(ts=datetime(2026, 10, 5, 2, minute, tzinfo=timezone.utc), source="edr",
                 category="process", action="x", message="m", **kw)


def test_fqdn_and_short_host_link():
    incs = correlate([_ev(1, host="FIN-SRV01.corp.local"), _ev(2, host="FIN-SRV01"),
                      _ev(3, host="fin-srv01")], window_minutes=60)
    assert len(incs) == 1 and len(incs[0].events) == 3


def test_domain_user_spellings_link():
    incs = correlate([_ev(1, user="CORP\\jsmith"), _ev(2, user="jsmith@corp.local"),
                      _ev(3, user="jsmith")], window_minutes=60)
    assert len(incs) == 1 and len(incs[0].events) == 3


def test_incident_lists_one_spelling_per_host_and_user():
    incs = correlate([_ev(1, host="FIN-SRV01.corp.local", user="CORP\\administrator"),
                      _ev(2, host="FIN-SRV01", user="administrator"),
                      _ev(3, host="FIN-SRV01", user="jsmith")], window_minutes=60)
    assert incs[0].hosts == {"FIN-SRV01.corp.local"}
    assert incs[0].users == {"CORP\\administrator", "jsmith"}
