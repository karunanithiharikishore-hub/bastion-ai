# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-AGENT-10: grounding must cover IPv6 and treat .sh/.py/.so consistently."""
from bluecell.models import Event
from bluecell.agents.grounding import evidence_index, check_text


def _ev(**kw):
    base = dict(ts="2026-10-03T22:00:00Z", source="syslog", category="other",
                action="log", message="routine", host="h1")
    base.update(kw)
    return Event(**base)


def test_invented_ipv6_is_flagged():
    idx = evidence_index([_ev()], [])
    res = check_text("Beacon to 2001:db8:dead:beef::1 from h1", idx)
    assert res["unverified"] == {"ips": ["2001:db8:dead:beef::1"]}


def test_ipv6_in_evidence_is_grounded_in_any_spelling():
    # evidence has the expanded form in src_ip; the model writes the compressed form
    idx = evidence_index([_ev(src_ip="2001:0db8:0000:0000:0000:0000:0000:0001")], [])
    assert check_text("Scan from 2001:db8::1 seen.", idx)["ok"]
    # ...and an IPv6 embedded in a log message counts as evidence too
    idx = evidence_index([_ev(message="conn from [fe80::1]:443")], [])
    assert check_text("Traffic from fe80::1 observed", idx)["ok"]


def test_timestamps_and_ratios_are_not_ipv6():
    idx = evidence_index([_ev()], [])
    assert check_text("At 10:22:33 on 2026-10-03, MAC 00:1a:2b:3c:4d:5e", idx)["ok"]


def test_ipv4_still_checked_alongside_ipv6():
    idx = evidence_index([_ev()], [])
    res = check_text("Hosts 203.0.113.250 and 2001:db8::5", idx)
    assert set(res["unverified"]["ips"]) == {"203.0.113.250", "2001:db8::5"}


def test_invented_sh_domain_is_flagged():
    idx = evidence_index([_ev()], [])
    res = check_text("dropper c2.evil.sh staged payload", idx)
    assert res["unverified"] == {"domains": ["c2.evil.sh"]}


def test_sh_py_so_domain_grounded_when_in_evidence():
    e = _ev(message="GET http://c2.evil.sh/x from h1")
    assert check_text("dropper c2.evil.sh staged", evidence_index([e], []))["ok"]


def test_sh_py_so_file_names_in_paths_are_not_domains():
    idx = evidence_index([_ev()], [])
    res = check_text("Ran /tmp/run.sh, then C:\\temp\\loader.py and /usr/lib/libx.so", idx)
    assert res["ok"], res


def test_url_with_ambiguous_tld_is_still_a_domain():
    idx = evidence_index([_ev()], [])
    res = check_text("Payload fetched from http://evil.sh/p.bin", idx)
    assert res["unverified"] == {"domains": ["evil.sh"]}


def test_bare_hostnames_and_users_are_not_checked():
    # documented behaviour: hosts/users are indexed but not verified
    idx = evidence_index([_ev()], [])
    assert check_text("host dc99 by user svc_backup", idx)["ok"]
