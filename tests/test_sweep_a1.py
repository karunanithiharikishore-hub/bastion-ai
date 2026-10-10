# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-1 regression: a trimmed oversized tool result must still fit the cap
with its `truncated` note, instead of collapsing into an error with no data."""
import json

from conftest import SAMPLES  # noqa: F401  (sets sys.path to src)
from bluecell.agents.toolbox import SecurityToolbox


def _event(i, pad):
    return {"event_id": f"E{i:05d}", "message": "m" * pad, "severity": "high",
            "rationale": "r" * 120}


def test_fit_trimmed_result_fits_cap_with_note():
    cap = 12000
    for pad in range(0, 60, 3):
        result = {"events": [_event(i, pad) for i in range(300)], "returned": 300}
        fitted = SecurityToolbox._fit(result, cap)
        assert "error" not in fitted, f"pad={pad}: trimmed result became an error"
        assert len(json.dumps(fitted, default=str)) <= cap, f"pad={pad}: over cap"
        assert "omitted from events" in fitted["truncated"]
        assert fitted["returned"] == len(fitted["events"]) > 0
