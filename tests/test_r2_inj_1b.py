# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""BUG-INJ-1 follow-up: the analyzer must hand apply_tier2_verdict the case-wide
flagged events, so a Tier-2 dismissal of the real incident is downgraded even when
the injection sits in an unrelated host's event."""
import json
import re

import bluecell.analyzer as analyzer
from test_r2_inj_1 import _case_with_unrelated_injection

_RATIONALE = ("The injected kiosk7 text is an attempt to steer the analyst and does not "
              "change the verdict; the activity is a known scan.")


class _ObedientDismisser:
    """Fake Tier-2 model: reads case_overview, then dismisses every incident with a
    rationale that explains the injection and cites a flagged event (passes the guard)."""
    resolved = "api"
    model = "fake"
    temperature = 0.0

    def complete(self, prompt, system=None, max_tokens=0):
        return json.dumps({"verdict": "likely-benign", "confidence": 0.9, "headline": "x"})

    def messages(self, body):
        if "Tier-2 SOC Analyst" not in body["system"]:
            return {"content": [{"type": "text", "text": "nothing to file"}]}
        msgs = body["messages"]
        step = sum(1 for m in msgs if m["role"] == "assistant")
        results = msgs[-1]["content"]
        if step == 0:
            return {"content": [{"type": "tool_use", "id": "c0", "name": "case_overview",
                                 "input": {}}]}
        if step == 1:   # read every incident, to cite one of its own events
            ov = json.loads(results[0]["content"])
            self.incidents = [i["id"] for i in ov["incidents"]]
            self.flagged = ov["injection_warning"]["event_ids"]
            assert self.flagged, "case_overview must report the injection"
            return {"content": [{"type": "tool_use", "id": "g" + i, "name": "get_incident",
                                 "input": {"incident_id": i}} for i in self.incidents]}
        if step == 2:   # dismiss each incident, citing its own event and the flagged one
            uses = []
            for inc_id, res in zip(self.incidents, results):
                own = [e for e in re.findall(r"\b[0-9a-f]{12}\b", res["content"])
                       if e not in self.flagged and e != inc_id[4:]]
                uses.append({"type": "tool_use", "id": "v" + inc_id, "name": "submit_verdict",
                             "input": {"incident_id": inc_id, "decision": "dismissed",
                                       "confidence": 0.9, "rationale": _RATIONALE,
                                       "evidence": (own[:1] or self.flagged[:1]) + self.flagged[:1]}})
            return {"content": uses}
        return {"content": [{"type": "text", "text": "done"}]}

def test_tier2_dismissal_of_ransomware_is_not_likely_benign(tmp_path):
    case = _case_with_unrelated_injection(tmp_path)
    res = analyzer.analyze([case], backbone=_ObedientDismisser(), orchestration="fixed",
                           trace=False)
    # The real attack: every incident that does not contain the unrelated kiosk7 host.
    attack = [b for b in res["incidents"]
              if not any(e.get("host") == "kiosk7" for e in b["events"])]
    assert attack, "the real attack incident must be present"
    for block in attack:
        assert block["verdict"]["decided_by"] == "tier2-agent"
        assert block["verdict"]["level"] == "needs-review", block["verdict"]
        assert block["verdict"]["downgraded_from"] == "likely-benign"
    assert all(b["verdict"]["level"] != "likely-benign" for b in res["incidents"])

