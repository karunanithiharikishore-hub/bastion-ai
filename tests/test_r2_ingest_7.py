"""BUG-INGEST-7: event_id must not depend on the wall-clock fallback used for
unparseable timestamps, while distinct unparsed lines stay distinct."""
import time

from bluecell.models import Event


def _unparsed(line):
    return Event(ts=None, source="syslog", category="other", action="log",
                 message=line, raw={"line": line})


def test_unparsed_event_id_is_stable_across_loads():
    a = _unparsed("garbage line without header")
    time.sleep(0.01)                      # now() moves on; id must not
    b = _unparsed("garbage line without header")
    assert "ts-unparsed" in a.tags
    assert a.event_id == b.event_id


def test_distinct_unparsed_lines_keep_distinct_ids():
    assert _unparsed("(sd-pam)[123]: ok").event_id != _unparsed("(sd-pam)[124]: ok").event_id


def test_parsed_event_id_still_uses_its_timestamp():
    a = Event(ts="2026-01-01T00:00:00Z", source="s", category="other", action="a", message="m")
    b = Event(ts="2026-01-02T00:00:00Z", source="s", category="other", action="a", message="m")
    assert a.event_id != b.event_id
