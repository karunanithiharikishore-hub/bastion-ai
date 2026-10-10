import pytest
from types import SimpleNamespace

from bluecell.agents.grounding import check_text, evidence_index

_EV = [SimpleNamespace(src_ip="10.0.0.1", dst_ip=None, domain="real.example", file_hash=None,
                       host="h", user="u", message="", raw=None)]
_IDX = evidence_index(_EV, [])


@pytest.mark.parametrize("t", [
    "198.51.100[.]77", "198.51.100(.)77", "zzz-evil-c2[.]ru", "hxxp://zzz-evil-c2[.]ru/x",
    "node 198.51.100.77", "release 198.51.100.77", "edge 198.51.100.77",
    "198.051.100.077", "c2_198.51.100.77", "ab" * 64,
])
def test_fabricated_ioc_rejected(t):
    assert not check_text("beacon to " + t, _IDX)["ok"]


def test_grounded_forms_pass():
    assert check_text("src 010.000.000.001 and real[.]example", _IDX)["ok"]
    assert check_text("Chrome 120.0.6.99", _IDX)["ok"]


def test_product_word_does_not_hide_fake_ip():
    assert not check_text("windows 203.0.113.9 beaconed", _IDX)["ok"]
