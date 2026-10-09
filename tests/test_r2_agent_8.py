# BUG-AGENT-8: pivot and search_events(ip=...) must match whole IP/host/user tokens,
# not substrings ("10.0.0.1" must not match 10.0.0.11). Text search stays substring.
import copy
import json

from test_injection import _attack_ctx, _box


def _ev_box(tmp_path, specs):
    """Box whose events are copies of a real event with the given (ip, host, user, message)."""
    ctx = _attack_ctx(tmp_path)
    base = ctx.events[0]
    evs = []
    for i, (src, dst, host, user, msg) in enumerate(specs):
        c = copy.copy(base)
        c.src_ip, c.dst_ip, c.host, c.user, c.message = src, dst, host, user, msg
        c.tags = [t for t in c.tags if "inject" not in t]
        evs.append(c)
    ctx.events = evs
    return _box(ctx, tmp_path)


SPECS = [
    ("10.0.0.11", "198.51.100.7", "web10", "bobby", "conn from 10.0.0.11 to 198.51.100.7"),
    ("10.0.0.12", "203.0.113.66", "web1", "bob", "login ok"),
    ("10.0.0.1", "203.0.113.90", "web1.corp", "bob", "dst 10.0.0.1:443"),
    ("11.2.3.45", "1.2.3.4", "db1", "eve", "hash 1.2.3.45"),
]


def _hit(res, marker):
    """True when the returned events include the one with this unique message marker."""
    return res["matches"] == 1 and marker in json.dumps(res["events"])


def test_search_ip_is_exact_not_substring(tmp_path):
    box = _ev_box(tmp_path, SPECS)
    res = json.loads(box.call("search_events", {"ip": "10.0.0.1"}))
    assert _hit(res, "dst 10.0.0.1:443")
    assert json.loads(box.call("search_events", {"ip": "1.2.3.4"}))["matches"] == 1
    assert json.loads(box.call("search_events", {"ip": "10.0.0"}))["matches"] == 0


def test_pivot_ip_is_token_bounded(tmp_path):
    box = _ev_box(tmp_path, SPECS)
    piv = json.loads(box.call("pivot", {"value": "10.0.0.1"}))
    # only the 'dst 10.0.0.1:443' event; 10.0.0.11 and 10.0.0.12 must not match
    assert piv["matches"] == 1
    assert json.loads(box.call("pivot", {"value": "1.2.3.4"}))["matches"] == 1
    assert json.loads(box.call("pivot", {"value": "10.0.0.11"}))["matches"] == 1


def test_pivot_host_and_user_are_token_bounded(tmp_path):
    box = _ev_box(tmp_path, SPECS)
    assert json.loads(box.call("pivot", {"value": "web1"}))["matches"] == 2  # web1 and web1.corp
    assert json.loads(box.call("pivot", {"value": "bob"}))["matches"] == 2  # not bobby
    assert json.loads(box.call("pivot", {"value": "bobb"}))["matches"] == 0


def test_text_search_keeps_substring_behaviour(tmp_path):
    box = _ev_box(tmp_path, SPECS)
    assert json.loads(box.call("search_events", {"text": "10.0.0.1"}))["matches"] == 3
