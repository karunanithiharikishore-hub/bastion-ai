"""R3-FEAT-2: an event with an unparseable timestamp gets a now() fallback ts.
The run-cache fingerprint must not include that guessed time, or the cache never hits."""
import time

from bastion import cache
from bastion.models import Event


def _event():
    return Event(ts="not-a-timestamp", source="edr", category="process",
                 action="process_create", message="no timestamp here", host="h1")


def test_unparsed_ts_gives_same_events_fingerprint_on_every_run():
    a = _event()
    time.sleep(0.01)                      # make the now() fallback differ between runs
    b = _event()
    assert "ts-unparsed" in a.tags and a.ts != b.ts
    assert cache.events_fingerprint([a]) == cache.events_fingerprint([b])
