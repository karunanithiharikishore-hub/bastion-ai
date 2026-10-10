"""ITEM-36 / ITEM-37: CloudTrail events from one trail share one log source
(the AWS service goes to a tag), a successful ConsoleLogin is an
authentication success, and the root identity's user is "root"."""
import json

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bastion.ingest.loader import ingest_path
from bastion.ingest.parsers import parse_cloud
from bastion.pipeline import normalize, map_attack, correlate

ROOT = {"type": "Root", "arn": "arn:aws:iam::123456789012:root"}


def _rec(name, svc, **kw):
    r = {"eventTime": "2026-10-03T22:00:00Z", "eventName": name, "eventSource": svc,
         "sourceIPAddress": "203.0.113.5",
         "userIdentity": {"type": "IAMUser", "userName": "bob"}}
    r.update(kw)
    return r


def test_services_of_one_trail_share_one_source(tmp_path):
    recs = [_rec("CreateUser", "iam.amazonaws.com"), _rec("GetObject", "s3.amazonaws.com"),
            _rec("RunInstances", "ec2.amazonaws.com"), _rec("GetCallerIdentity", "sts.amazonaws.com")]
    p = tmp_path / "trail.json"
    p.write_text(json.dumps({"Records": recs}))
    events = normalize(ingest_path(str(p)))
    map_attack(events)
    incs = correlate(events)
    assert {e.source for e in events} == {"cloudtrail"}
    assert len(incs) == 1 and incs[0].sources == {"cloudtrail"}


def test_service_is_kept_as_tag():
    ev = parse_cloud(_rec("GetObject", "s3.amazonaws.com"))
    assert ev.source == "cloudtrail"
    assert any("s3.amazonaws.com" in t for t in ev.tags)


def test_console_login_success_is_authentication_success():
    r = _rec("ConsoleLogin", "signin.amazonaws.com", responseElements={"ConsoleLogin": "Success"})
    ev = parse_cloud(r)
    assert ev.category == "authentication"
    assert ev.action == "login_success"
    map_attack([ev])
    assert "auth:success" in ev.tags


def test_console_login_failure_still_failed():
    r = _rec("ConsoleLogin", "signin.amazonaws.com", responseElements={"ConsoleLogin": "Failure"},
             errorMessage="Failed authentication")
    ev = parse_cloud(r)
    assert ev.action == "login_failed" and ev.category == "authentication"
    assert "aws:console-login-failed" in ev.tags


def test_root_user_is_root_not_full_arn():
    ev = parse_cloud(_rec("DeleteTrail", "cloudtrail.amazonaws.com", userIdentity=ROOT))
    assert ev.user == "root"
