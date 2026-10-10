"""Sweep ITEM-25 (repeated lines): 'last message repeated N times' re-emits the previous event."""
from bastion.ingest.loader import ingest_file
from bastion.pipeline.attack import map_attack

ATTACK = "sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2"


def _events(tmp_path, body):
    p = tmp_path / "auth.log"
    p.write_text(body)
    return ingest_file(str(p))


def test_repeated_with_header_expands_to_failures(tmp_path):
    evs = _events(tmp_path, f"Oct  3 22:00:00 web1 {ATTACK}\n"
                            "Oct  3 22:00:01 web1 sshd[1]: last message repeated 9 times\n")
    assert len(evs) == 10
    assert all(e.action == "login_failed" and e.src_ip == "203.0.113.9" for e in evs)
    assert len({e.event_id for e in evs}) == 10
    assert sum("T1110" in e.attack for e in map_attack(evs)) == 10


def test_repeated_without_header_expands_to_failures(tmp_path):
    evs = _events(tmp_path, f"Oct  3 22:00:00 web1 {ATTACK}\nlast message repeated 9 times\n")
    assert len(evs) == 10
    assert len({e.event_id for e in evs}) == 10
    assert sum("T1110" in e.attack for e in map_attack(evs)) == 10
