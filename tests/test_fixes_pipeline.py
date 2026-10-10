"""Regression tests for pipeline / RCA / intel fixes (P1, P3-P13)."""
import json

from conftest import SAMPLES
from bluecell.analyzer import analyze
from bluecell.ingest import ingest_path
from bluecell.intel import IntelStore
from bluecell.models import Event
from bluecell.pipeline import normalize, map_attack, correlate, extract_iocs, compress
from bluecell.pipeline.ioc import hunt_checklist
from bluecell.report import render_markdown
from bluecell.report.rca import deterministic_storyline, assess_incident

T = "2026-09-26T09:%02d:00Z"


def _ev(minute, **kw):
    kw.setdefault("source", "syslog")
    kw.setdefault("host", "h")
    return Event(ts=T % minute, **kw)


def _tags(**kw):
    e = _ev(0, **kw)
    map_attack([e])
    return e.attack


# P1 -- phase count is distinct events, not (event, technique) pairs.
def test_p1_phase_count_counts_distinct_events():
    events = normalize(ingest_path(SAMPLES))
    map_attack(events)
    inc = correlate(events)[0]
    for p in deterministic_storyline(inc)["phases"]:
        tids = {t["id"] for t in p["techniques"]}
        distinct = {id(e) for e in inc.events if tids & set(e.attack)}
        assert p["count"] == len(distinct), p["tactic"]


def test_p1_one_event_two_techniques_counts_once():
    e = _ev(1, source="edr", category="process", action="process_create",
            message="powershell -enc AAAA", process="powershell.exe")
    map_attack([e])
    assert {"T1059", "T1059.001"} <= set(e.attack)
    phase = deterministic_storyline(correlate([e])[0])["phases"][0]
    assert phase["tactic"] == "execution" and phase["count"] == 1


# P3 -- brute-force checklist targets only users on T1110 events.
def test_p3_bruteforce_targets_only_bruteforced_users():
    evs = [_ev(1, category="authentication", action="login_failed",
               message="Failed password for admin", host="web01", user="admin",
               src_ip="203.0.113.66"),
           _ev(2, category="authentication", action="login_failed",
               message="Failed password for admin", host="web01", user="admin",
               src_ip="203.0.113.66"),
           _ev(3, source="edr", category="process", action="process_create",
               message="backup job", host="web01", user="svc_backup", process="rsync")]
    map_attack(evs)
    incs = correlate(evs)
    bf = [c for c in hunt_checklist(incs, extract_iocs(evs)) if "brute force" in c["action"]]
    assert bf and bf[0]["targets"] == ["admin"]


# P4 -- compress must not collapse lines that differ in a printed field.
def test_p4_compress_keeps_distinct_ips_and_processes():
    evs = [_ev(i, category="authentication", action="login_failed", message="Failed",
               user="admin", src_ip=f"203.0.113.{i}") for i in range(1, 6)]
    map_attack(evs)
    out = compress(evs)
    assert all(f"s=203.0.113.{i}" in out for i in range(1, 6))
    assert " x5" not in out

    evs = [_ev(1, source="edr", category="process", action="process_create",
               message="x", user="u", process="notepad.exe"),
           _ev(2, source="edr", category="process", action="process_create",
               message="y", user="u", process="mimikatz.exe", file_hash="a" * 64)]
    out = compress(evs)
    assert "mimikatz.exe" in out and "x2" not in out


def test_p4_identical_burst_still_collapses():
    evs = [_ev(i, category="authentication", action="login_failed", message="Failed",
               user="admin", src_ip="203.0.113.9") for i in range(1, 6)]
    assert compress(evs).rstrip().endswith("x5")


# P5 -- multi-source / multi-IP failures are not called single-source noise.
def test_p5_multi_source_spray_is_not_likely_benign():
    evs = [_ev(i + 1, source=src, category="authentication", action="login_failed",
               message=f"sign-in failure for user{i}", user=f"user{i}",
               src_ip=f"203.0.113.{i + 10}")
           for i, src in enumerate(("azure_ad", "okta", "syslog"))]
    map_attack(evs)
    v = assess_incident(correlate(evs)[0])
    assert v["level"] != "likely-benign"
    assert "single source" not in v["why"]


def test_p5_single_source_failures_still_likely_benign():
    evs = [_ev(i, source="azure_ad", category="authentication", action="login_failed",
               message="sign-in failure for bob", user="bob", src_ip="203.0.113.5")
           for i in range(1, 4)]
    map_attack(evs)
    v = assess_incident(correlate(evs)[0])
    assert v["level"] == "likely-benign" and "single source" in v["why"]


# P6 -- compound tactics are split; T1078 on a sign-in is credential-related.
def _t1078_incident():
    e1 = _ev(1, source="azure_ad", category="authentication", action="login_failed",
             message="Azure AD sign-in failure for bob", user="bob", src_ip="203.0.113.5")
    e2 = _ev(2, source="azure_ad", category="authentication", action="login_success",
             message="Azure AD sign-in Success for bob risk=high", user="bob",
             src_ip="203.0.113.5", severity=4)
    map_attack([e1, e2])
    e2.attack.append("T1078")
    return correlate([e1, e2])[0]


def test_p6_compound_tactic_is_split_into_real_phases():
    s = deterministic_storyline(_t1078_incident())
    tactics = [p["tactic"] for p in s["phases"]]
    assert all("/" not in t for t in tactics)
    steps = " ".join(s["attack_summary"]["what_they_did"])
    assert "defense-evasion/persistence" not in steps
    # Sweep I10: a T1078 sign-in is credential activity, not "disabled defenses / persistence".
    assert "credential-access" in tactics and "disabled or evaded defenses" not in steps


def test_p6_t1078_signin_counts_as_credential_activity():
    v = assess_incident(_t1078_incident())
    assert v["headline"].startswith("Failed sign-ins followed by a success")


# P7 -- substring false positives in ATT&CK rules.
def test_p7_rdp_smb_need_word_boundaries():
    assert "T1021" not in _tags(source="dns", category="dns", action="dns_query",
                                message="DNS query wordpress.com -> 192.0.78.9",
                                domain="wordpress.com")
    assert "T1021" not in _tags(source="edr", category="process", action="process_create",
                                message="dmidecode reading SMBIOS 3.2 table",
                                process="dmidecode")
    assert "T1021" in _tags(source="firewall", category="network", action="allow",
                            message="RDP session 10.0.0.5 -> 10.0.0.9:3389")
    assert "T1021" in _tags(source="edr", category="process", action="process_create",
                            message="net use \\\\db02\\c$ over smb", process="net.exe")
    for m in ("python smbexec.py corp/admin@10.0.0.9", "smbclient //db02/c$"):
        assert "T1021" in _tags(source="edr", category="process",
                                action="process_create", message=m), m


def test_p7_at_exe_not_matched_inside_chat_exe():
    assert "T1053" not in _tags(source="edr", category="process", action="process_create",
                                message="Started C:\\Program Files\\Chat\\chat.exe",
                                process="chat.exe")
    assert "T1053" in _tags(source="edr", category="process", action="process_create",
                            message="C:\\Windows\\System32\\at.exe 23:00 evil.bat",
                            process="at.exe")


def test_p7_account_disabled_is_not_impair_defenses():
    assert "T1562" not in _tags(
        source="windows", category="authentication", action="user_account_disabled",
        message="Microsoft-Windows-Security-Auditing 4725: A user account was disabled.")
    assert "T1562" not in _tags(source="firewall", category="network", action="allow",
                                message="firewall session stop 10.0.0.5 -> 8.8.8.8")
    assert "T1562" not in _tags(source="firewall", category="network", action="allow",
                                message="firewall connection was stopped by peer")
    assert "T1562" in _tags(source="edr", category="process", action="service_stop",
                            message="Stopped Windows Defender service")


def test_p7_real_defense_tampering_still_detected():
    for m in ("powershell Set-MpPreference -DisableRealtimeMonitoring $true",
              "sc stop WinDefend", "systemctl stop firewalld",
              "Microsoft Defender Antivirus real-time protection was disabled",
              "Security Center service stopped", "EDR agent uninstalled by admin"):
        assert "T1562" in _tags(source="edr", category="process",
                                action="process_create", message=m), m


def test_p7_success_mentioning_failure_is_not_bruteforce():
    e = _ev(0, category="authentication", action="login_success",
            message="Accepted publickey for bob after 1 failed attempt")
    map_attack([e])
    assert "T1110" not in e.attack and "auth:success" in e.tags


# P8 -- CDN hostnames are not DGA.
def test_p8_cdn_hostnames_not_dga():
    for dom in ("d3ag4hukkh62yn.cloudfront.net", "a1b2c3d4e5f6g7h8.azureedge.net"):
        assert "T1568" not in _tags(source="dns", category="dns", action="dns_query",
                                    message=f"DNS query {dom}", domain=dom)
    assert "T1568" in _tags(source="dns", category="dns", action="dns_query",
                            message="DNS query kj3h5g9x2zqwmnbvc7.top",
                            domain="kj3h5g9x2zqwmnbvc7.top")


# P9 -- patient zero is the first ATT&CK-tagged event.
def test_p9_patient_zero_is_first_tagged_event():
    evs = [_ev(0, category="other", action="log", message="change-mgmt CHG001 opened"),
           _ev(5, category="authentication", action="login_failed",
               message="Failed password", user="x")]
    map_attack(evs)
    s = deterministic_storyline(correlate(evs)[0])
    assert "login_failed" in s["patient_zero"]
    how = s["attack_summary"]["how_they_got_in"]
    assert "Earliest suspicious activity" in how and "change-mgmt" not in how


def test_p9_untagged_incident_uses_neutral_wording():
    from bluecell.pipeline.correlate import Incident
    evs = [_ev(0, category="other", action="log", message="a", user="x"),
           _ev(1, category="other", action="log", message="b", user="x")]
    map_attack(evs)
    s = deterministic_storyline(Incident(id="INC-x", events=evs))
    how = s["attack_summary"]["how_they_got_in"]
    assert "Earliest related activity" in how and "suspicious" not in how


# P10 -- a bare JSON list is accepted as intel entries; other shapes -> empty.
def test_p10_intel_store_accepts_bare_list(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps([{"id": "CVE-1", "title": "ssh brute", "description": "d",
                              "keywords": ["ssh"], "techniques": ["T1110"]}, "junk"]))
    s = IntelStore(str(p))
    assert [e["id"] for e in s.entries] == ["CVE-1"]
    assert s.search(["ssh"])[0]["id"] == "CVE-1"
    for bad in ("42", '"str"', "null"):
        p.write_text(bad)
        assert IntelStore(str(p)).entries == []


# P11 -- null fields do not crash the import; "cve"-keyed record title.
def test_p11_null_fields_and_cve_key(tmp_path):
    s = IntelStore(str(tmp_path / "i.json"))
    recs = [{"id": "CVE-1", "summary": None}, {"id": "CVE-2", "title": None, "summary": "x"},
            {"id": "CVE-3", "keywords": None, "techniques": None},
            {"cve": "CVE-4", "description": "some long description"}]
    assert s.ingest_cve_feed(recs) == 4
    assert {e["id"]: e["title"] for e in s.entries}["CVE-4"] == "CVE-4"
    assert IntelStore(str(tmp_path / "i.json")).stats()["total"] == 4


# P12 -- "Incidents found" reports the pre-truncation total.
def _many_events(n):
    return [{"timestamp": f"2026-09-26T{i:02d}:00:00Z", "host": f"h{i}", "user": f"u{i}",
             "action": "process_create", "process": "powershell.exe",
             "message": "powershell Get-Date", "severity": "medium"} for i in range(n)]


def test_p12_incident_total_survives_truncation(tmp_path):
    (tmp_path / "edr.json").write_text(json.dumps(_many_events(6)))
    r = analyze([str(tmp_path)], run_agents=False, use_llm=False, max_incidents=2)
    assert len(r["incidents"]) == 2 and r["meta"]["incidents_total"] == 6
    assert "Incidents found: **6 (showing top 2)**" in render_markdown(r)


# P13 -- digest header reports total signatures and the budget cut.
def test_p13_compress_header_reports_omitted():
    evs = [_ev(i, source="edr", category="process", action=f"a{i}", message="m")
           for i in range(10)]
    header = compress(evs, max_lines=3).splitlines()[0]
    assert "10 distinct signatures" in header and "7 omitted (budget)" in header
    assert "omitted" not in compress(evs).splitlines()[0]
