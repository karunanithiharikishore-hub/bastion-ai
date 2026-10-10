"""BUG-R4-INGEST-1: failed CloudTrail ConsoleLogins followed by a successful
ConsoleLogin (a cloud_api event) must not be judged "no successful compromise"."""
import json

from bluecell.ingest.loader import ingest_path
from bluecell.pipeline import normalize, map_attack, correlate
from bluecell.report.rca import assess_incident


def _ct(t, ok, name="ConsoleLogin"):
    r = {"eventTime": t, "eventSource": "signin.amazonaws.com", "eventName": name,
         "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.50",
         "userIdentity": {"type": "IAMUser", "userName": "admin"},
         "responseElements": {"ConsoleLogin": "Success" if ok else "Failure"}}
    if not ok:
        r["errorMessage"] = "Failed authentication"
    return r


def _verdict(recs, tmp_path):
    p = tmp_path / "trail.json"
    p.write_text(json.dumps({"Records": recs}))
    events = normalize(ingest_path(str(p)))
    map_attack(events)
    return assess_incident(correlate(events)[0])


def test_failures_then_console_success_is_not_called_benign(tmp_path):
    recs = [_ct(f"2026-10-03T22:0{i}:00Z", False) for i in range(6)]
    recs.append(_ct("2026-10-03T22:10:00Z", True))
    v = _verdict(recs, tmp_path)
    assert v["level"] == "needs-review"
    assert "followed by a success" in v["headline"]


def test_other_cloud_api_calls_are_not_logins(tmp_path):
    recs = [_ct(f"2026-10-03T22:0{i}:00Z", False) for i in range(6)]
    recs.append(_ct("2026-10-03T22:10:00Z", True, name="ListBuckets"))
    v = _verdict(recs, tmp_path)
    assert v["level"] == "likely-benign"
