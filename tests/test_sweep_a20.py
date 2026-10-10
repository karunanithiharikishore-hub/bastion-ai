# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
# ITEM-20: _shrink must keep the reviewer's lead payload within 4000 chars, valid JSON.
import json

from bastion.agents.analyst import _shrink


def test_shrink_caps_many_string_keys():
    out = _shrink({f"k{i}": "x" * 50 for i in range(400)})
    assert len(out) <= 4000
    json.loads(out)


def test_shrink_caps_many_numeric_keys():
    out = _shrink({"verdict": "needs-review", "extra": {f"key{i}": i for i in range(1000)}})
    assert len(out) <= 4000
    json.loads(out)


def test_shrink_caps_oversized_key_names():
    out = _shrink({"x" * 5000: "v", "verdict": "needs-review"})
    assert len(out) <= 4000
    json.loads(out)
