import time
from types import SimpleNamespace

from bluecell.agents.grounding import evidence_index


def _ev(raw):
    return SimpleNamespace(raw=raw, message="")


def test_long_dotted_field_is_fast():
    t = time.time()
    evidence_index([_ev({"ua": "a." * 30000 + "1"})], [])
    assert time.time() - t < 1


def test_ioc_after_escaped_newline_is_indexed():
    h = "ab" * 32
    idx = evidence_index([_ev({"d": "Net:\r\n\tAddr:\t203.0.113.9\r\nHash:\n" + h})], [])
    assert "203.0.113.9" in idx["ips"] and h in idx["hashes"]
