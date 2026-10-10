"""ITEM-17 regression: events that differ only in their message text must not collapse
into one 'xN' digest line, and the digest carries a bounded, escaped message excerpt."""
from bluecell.models import Event
from bluecell.pipeline import compress


def _ev(message, **kw):
    base = dict(ts="2026-10-03T22:00:00Z", source="syslog", category="other",
                action="log", message=message, host="web1", process="kernel")
    base.update(kw)
    return Event(**base)


def test_messages_differing_only_in_text_do_not_collapse():
    digest = compress([_ev("Out of memory: Killed process 123"), _ev("Segfault at 0")])
    lines = digest.splitlines()[1:]
    assert len(lines) == 2
    assert not any(" x2" in line for line in lines)
    assert "msg=Out of memory: Killed process 123" in digest
    assert "msg=Segfault at 0" in digest


def test_identical_messages_still_collapse():
    digest = compress([_ev("Segfault at 0", ts=f"2026-10-03T22:00:0{i}Z") for i in range(3)])
    assert digest.splitlines()[-1].endswith("x3")


def test_message_excerpt_is_capped_and_single_line():
    line = _ev("ok\nforged line " + "A" * 500).compact()
    assert "\n" not in line
    assert "forged line" in line          # escaped, not dropped
    assert "A" * 200 not in line          # capped
    assert len(line) < 200


def test_message_not_appended_when_attack_or_entities_present():
    e = _ev("Failed password", user="admin")
    assert "msg=" not in e.compact()
    e.attack.append("T1110")
    assert "msg=" not in e.compact()
