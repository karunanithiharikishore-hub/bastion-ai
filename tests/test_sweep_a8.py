"""ITEM-8 regression: search_events text and pivot must see values that exist only in the
raw record (e.g. CommandLine), since grounding already accepts them as evidence."""
import json
import tempfile
from datetime import datetime, timedelta, timezone

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bluecell.models import Event
from bluecell.agents.base import AgentContext
from bluecell.agents.toolbox import SecurityToolbox, Blackboard
from bluecell.pipeline import extract_iocs

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _box():
    evs = [Event(ts=T0 + timedelta(seconds=i), source="edr", category="process",
                 action="proc_start", message=f"proc {i}", host=f"h{i % 3}", user="bob",
                 process=f"p{i}.exe") for i in range(6)]
    evs[0].raw = {"CommandLine": "mimikatz-custom.exe sekurlsa::logonpasswords"}
    ctx = AgentContext(events=evs, incidents=[], iocs=extract_iocs(evs), digest="", backbone=None)
    return SecurityToolbox(ctx, "t", "T", Blackboard(tempfile.mktemp()))


def test_search_events_text_finds_raw_only_value():
    box = _box()
    r = json.loads(box.call("search_events", {"text": "mimikatz-custom"}))
    assert r["matches"] == 1


def test_pivot_finds_raw_only_value():
    box = _box()
    r = json.loads(box.call("pivot", {"value": "mimikatz-custom.exe"}))
    assert r["matches"] == 1
