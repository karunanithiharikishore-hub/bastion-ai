# BUG-AGENT-12: search_events must reject unparseable start/end/min_severity with a clear
# error (not silently drop the filter), match ATT&CK techniques hierarchically
# (T1071 matches T1071.004; T1071.004 matches only itself), and not crash on non-string technique.
import copy
import json

from test_injection import _attack_ctx, _box


def _tagged_box(tmp_path, attacks):
    """Box whose events are copies of a real event, one per entry of `attacks` (attack tags)."""
    ctx = _attack_ctx(tmp_path)
    base = ctx.events[0]
    evs = []
    for i, tags in enumerate(attacks):
        c = copy.copy(base)
        c.attack = list(tags)
        c.message = f"marker-{i}"
        c.tags = [t for t in c.tags if "inject" not in t]
        evs.append(c)
    ctx.events = evs
    return _box(ctx, tmp_path)


def test_bad_start_end_or_min_severity_is_a_clear_error(tmp_path):
    box = _tagged_box(tmp_path, [[]])
    for args, name in [({"start": "yesterday"}, "start"),
                       ({"end": "next tuesday"}, "end"),
                       ({"min_severity": "abc"}, "min_severity"),
                       ({"min_severity": 9}, "min_severity")]:
        res = json.loads(box.call("search_events", args))
        assert "error" in res and name in res["error"], (args, res)
        assert "matches" not in res, (args, res)


def test_valid_filters_still_work(tmp_path):
    box = _tagged_box(tmp_path, [[], []])
    assert json.loads(box.call("search_events", {"min_severity": "info"}))["matches"] == 2
    assert "error" not in json.loads(box.call("search_events", {"min_severity": "2"}))
    assert json.loads(box.call("search_events", {"start": "2000-01-01", "end": "2999-12-31"}))["matches"] == 2


def test_parent_technique_matches_subtechnique_but_not_reverse(tmp_path):
    box = _tagged_box(tmp_path, [["T1071.004"], ["T1071"], ["T1071.001"], ["T1059"]])
    q = lambda t: json.loads(box.call("search_events", {"technique": t}))["matches"]
    assert q("T1071") == 3          # T1071, T1071.004, T1071.001
    assert q("T1071.004") == 1      # only itself
    assert q("T1071.00") == 0       # a partial id is not a parent
    assert q("T1059") == 1
    assert q("t1071.004") == 1      # case-insensitive


def test_non_string_technique_does_not_crash(tmp_path):
    box = _tagged_box(tmp_path, [["T1059"]])
    res = json.loads(box.call("search_events", {"technique": ["T1059"]}))
    assert "error" not in res and res["matches"] == 0
    res = json.loads(box.call("search_events", {"technique": 1059}))
    assert "error" not in res
