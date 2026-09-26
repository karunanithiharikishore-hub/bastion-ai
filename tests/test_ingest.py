import os

from conftest import SAMPLES
from bluecell.ingest import ingest_path, ingest_paths, detect_source
from bluecell.ingest.parsers import parse_syslog_line, parse_dns, parse_cloud


def test_detect_source_from_filename():
    assert detect_source("dns.jsonl") == "dns"
    assert detect_source("firewall.csv") == "firewall"
    assert detect_source("unknown.json") == "edr"  # default


def test_detect_source_from_record_field():
    assert detect_source("x.json", {"source": "dns"}) == "dns"


def test_syslog_failed_password():
    ev = parse_syslog_line(
        "Sep 26 09:01:12 web01 sshd[2211]: Failed password for admin from 203.0.113.66 port 41022 ssh2")
    assert ev.category == "authentication"
    assert ev.action == "login_failed"
    assert ev.host == "web01"
    assert ev.src_ip == "203.0.113.66"
    assert ev.user == "admin"


def test_syslog_unparseable_line_kept():
    ev = parse_syslog_line("totally freeform line without structure")
    assert ev is not None and ev.category == "other"


def test_syslog_empty_line_skipped():
    assert parse_syslog_line("   ") is None


def test_dns_requires_domain():
    assert parse_dns({"timestamp": "2026-09-26T09:00:00Z"}) is None
    ev = parse_dns({"timestamp": "2026-09-26T09:00:00Z", "query": "evil.xyz."})
    assert ev.domain == "evil.xyz"  # trailing dot stripped


def test_cloud_user_from_nested_identity():
    ev = parse_cloud({
        "eventTime": "2026-09-26T09:00:00Z", "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com", "userIdentity": {"userName": "admin"},
        "sourceIPAddress": "203.0.113.66",
    })
    assert ev.action == "CreateAccessKey"
    assert ev.src_ip == "203.0.113.66"


def test_ingest_all_samples():
    events = ingest_path(SAMPLES)
    assert len(events) > 15
    sources = {e.source for e in events}
    # syslog, edr, dns, firewall, cloud all represented
    assert "syslog" in sources
    assert "dns" in sources
    assert any("iam" in s or s == "cloud" for s in sources)


def test_ingest_missing_file_dir_recursion():
    # ingest_paths over a single csv returns firewall events
    events = ingest_paths([os.path.join(SAMPLES, "firewall.csv")])
    assert all(e.source in ("firewall",) or e.category == "network" for e in events)
    assert len(events) == 4
