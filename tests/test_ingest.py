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
    assert any("iam" in s or s in ("cloud", "cloudtrail") for s in sources)


def test_ragged_csv_with_extra_columns_does_not_crash(tmp_path):
    # A row with MORE fields than headers -> csv.DictReader adds a None key.
    # This previously raised: AttributeError: 'NoneType' has no attribute 'lower'.
    p = tmp_path / "signins.csv"
    p.write_text(
        "Date,User,IP address\n"
        "2026-09-26T09:00:00Z,admin,203.0.113.5,EXTRA1,EXTRA2\n"   # 5 cols, 3 headers
        "2026-09-26T09:01:00Z,bob,10.0.0.2\n",
        encoding="utf-8",
    )
    events = ingest_path(str(p))
    assert len(events) == 2   # both rows parsed, no crash


def test_csv_with_blank_header_column(tmp_path):
    p = tmp_path / "weird.csv"
    p.write_text("timestamp,,message\n2026-09-26T09:00:00Z,junk,hello\n", encoding="utf-8")
    events = ingest_path(str(p))  # empty-string header is fine; must not raise
    assert len(events) == 1


def test_ingest_missing_file_dir_recursion():
    # ingest_paths over a single csv returns firewall events
    events = ingest_paths([os.path.join(SAMPLES, "firewall.csv")])
    assert all(e.source in ("firewall",) or e.category == "network" for e in events)
    assert len(events) == 4


def test_syslog_user_skips_filler_words():
    cases = {
        "Oct  3 22:20:41 app01 sshd[3101]: pam_unix(sshd:session): session closed for user jsmith": "jsmith",
        "Oct  3 22:20:41 app01 sshd[3101]: pam_unix(sshd:session): session opened for user root by (uid=0)": "root",
        "Oct  3 22:01:10 app01 sshd[3101]: Failed password for invalid user oracle from 192.0.2.9 port 22 ssh2": "oracle",
        "Oct  3 22:01:10 app01 sshd[3101]: Invalid user test from 192.0.2.9 port 22": "test",
        "Oct  3 22:01:10 app01 sshd[3101]: Failed password for admin from 192.0.2.9 port 22 ssh2": "admin",
        "Oct  3 22:01:25 app01 sshd[3103]: Accepted publickey for jsmith from 10.0.5.20 port 51026 ssh2": "jsmith",
    }
    for line, user in cases.items():
        assert parse_syslog_line(line).user == user, line


# ---- from-scratch review fixes ---------------------------------------------

def test_timestamps_epoch_text_utc_and_year_rollover():
    from datetime import datetime, timezone, timedelta
    from bluecell.models import _parse_ts
    assert _parse_ts("1700000000").year == 2023                      # CSV epoch text
    assert _parse_ts("1700000000000") == _parse_ts(1700000000)       # millis text
    dt = _parse_ts("2026-10-03T22:00:00+05:30")
    assert dt.utcoffset() == timedelta(0) and dt.hour == 16           # converted to UTC
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)
    assert _parse_ts(future.strftime("%b %d %H:%M:%S")).year == now.year - 1


def test_event_coerces_non_string_entities_and_bad_severity():
    from bluecell.models import Event
    e = Event(ts="2026-10-03T22:00:00Z", source="edr", category="process", action="x",
              message=None, host=1234, user="  ", src_ip=["10.0.0.1"], severity=float("nan"))
    assert e.host == "1234" and e.user is None and isinstance(e.src_ip, str)
    assert e.severity == 0 and e.message == ""


def test_dedup_keeps_events_that_differ_only_by_source_ip():
    from bluecell.models import Event
    from bluecell.pipeline import normalize
    a = Event(ts="2026-10-03T22:00:00Z", source="firewall", category="network", action="allow",
              message="c2 beacon", src_ip="10.0.0.11", dst_ip="198.51.100.7")
    b = Event(ts="2026-10-03T22:00:00Z", source="firewall", category="network", action="allow",
              message="c2 beacon", src_ip="10.0.0.12", dst_ip="198.51.100.7")
    assert len(normalize([a, b])) == 2


def test_syslog_publickey_success_sudo_user_and_iso_timestamp():
    ok = parse_syslog_line("Oct  3 22:01:25 app01 sshd[3103]: Accepted publickey for jsmith from 10.0.5.20 port 51026 ssh2")
    assert ok.action == "login_success" and ok.user == "jsmith"
    sudo = parse_syslog_line("Oct  3 22:01:40 app01 sudo[3110]: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/id")
    assert sudo.action == "sudo" and sudo.user == "jsmith"
    iso = parse_syslog_line("2026-10-03T22:01:10.123+00:00 app01 sshd[1]: Failed password for root from 192.0.2.9 port 22 ssh2")
    assert iso.host == "app01" and iso.action == "login_failed"
    assert iso.ts.isoformat().startswith("2026-10-03T22:01:10")


def test_cloudtrail_user_from_identity_and_assumed_role():
    plain = parse_cloud({"eventTime": "2026-10-03T22:00:00Z", "eventName": "ListBuckets",
                         "userIdentity": {"type": "IAMUser", "userName": "alice"}})
    assert plain.user == "alice"
    role = parse_cloud({"eventTime": "2026-10-03T22:00:00Z", "eventName": "ListBuckets",
                        "userIdentity": {"type": "AssumedRole",
                                         "arn": "arn:aws:sts::1:assumed-role/Admin/bob"}})
    assert role.user == "bob"
    flat = parse_cloud({"eventTime": "2026-10-03T22:00:00Z", "eventName": "x", "caller": "carol"})
    assert flat.user == "carol"


def test_csv_with_byte_order_mark_keeps_timestamp(tmp_path):
    from bluecell.ingest import ingest_path
    p = tmp_path / "firewall.csv"
    p.write_bytes(b"\xef\xbb\xbftimestamp,action,src_ip,dst_ip,message\n"
                  b"2026-09-26T09:07:05Z,allow,10.0.0.11,203.0.113.90,dl\n")
    assert ingest_path(str(p))[0].ts.isoformat().startswith("2026-09-26T09:07:05")


def test_json_lines_inside_a_log_file_are_structured(tmp_path):
    from bluecell.ingest import ingest_path
    p = tmp_path / "dns_export.log"
    p.write_text('{"timestamp": "2026-10-03T22:01:45Z", "query": "evil.top", "host": "h1"}\n'
                 "Oct  3 22:02:00 h1 sshd[1]: Failed password for root from 192.0.2.9 port 22 ssh2\n")
    evs = ingest_path(str(p))
    assert [e.source for e in evs] == ["dns", "syslog"]
    assert evs[0].domain == "evil.top"
