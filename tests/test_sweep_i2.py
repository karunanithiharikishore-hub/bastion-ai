"""ITEM-2: rca's failure count must use attack.map_attack's T1110 predicate (action OR message)."""
import json

from bastion.ingest.loader import ingest_file
from bastion.pipeline.attack import map_attack
from bastion.pipeline.correlate import correlate
from bastion.report.rca import assess_incident


def test_message_only_auth_failures_are_counted_not_called_benign(tmp_path):
    # action is 'auth' for every record; the failure is only visible in the message (T1110 in attack.py).
    recs = [{"timestamp": f"2026-10-03T22:{i // 60:02d}:{i % 60:02d}Z", "user": "bob",
             "src_ip": f"203.0.113.{i % 2 + 5}", "action": "auth",
             "message": f"Authentication failed for bob (attempt {i})"} for i in range(500)]
    p = tmp_path / "vpn_auth.json"
    p.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    evs = map_attack(ingest_file(str(p)))
    assert all("T1110" in e.attack for e in evs)
    v = assess_incident(correlate(evs)[0])
    assert v["level"] == "needs-review"
    assert "500 failed" in v["why"]
    assert "brute force" in v["headline"].lower()
