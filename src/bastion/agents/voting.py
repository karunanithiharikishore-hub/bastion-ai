# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Self-consistency voting for the Tier-2 verdict.

The Tier-2 agent's confirm/dismiss decision drives the report headline, and a
single model run can land on either side of a borderline case. With ``votes=K``
the Tier-2 agent investigates K times independently (each run starts from the
same board, so no run sees another run's verdicts) and the per-incident
decisions are tallied here.

Rules (pure functions, no model involved):
- A ballot is one completed run: {incident_id: verdict dict}. A failed run is
  ``None`` and does not count. A completed run that filed no verdict for an
  incident abstains on it.
- An incident is decided when one decision holds a strict majority of the
  requested runs (2 of 3, 3 of 3, 2 of 2 ...). A failed or abstaining run cannot
  add to the majority, so a lone surviving run of three is a split: no agent
  verdict is used, the rule verdict stands and is marked for review.
- The merged verdict takes the winning side's evidence and reviewed candidates
  (union, in run order), its most common severity, the rationale of the first
  winning run, and confidence = mean winning confidence x agreement, where
  agreement = winning votes / requested runs. A 2-1 vote therefore reports a
  lower confidence than 3-0, and 2 of 3 with one failure reports 0.67.
"""
from __future__ import annotations

from collections import Counter

_SEV_ORDER = ("low", "medium", "high", "critical")


def _union(lists) -> list:
    seen, out = set(), []
    for items in lists:
        for x in items or []:
            if x not in seen:
                seen.add(x)
                out.append(x)
    return out


def tally(ballots: list, incident_ids) -> dict:
    """Tally ballots per incident.

    Returns {incident_id: {"outcome": "majority"|"split", "decision", "verdict",
    "votes": {...}}}; "verdict" is the merged winning verdict (None on a split).
    """
    completed = [b for b in ballots if b is not None]
    k, n = len(ballots), len(completed)
    out = {}
    for iid in incident_ids:
        cast = [b[iid] for b in completed if iid in b]
        counts = Counter(v["decision"] for v in cast)
        confirmed, dismissed = counts.get("confirmed", 0), counts.get("dismissed", 0)
        if confirmed > dismissed:
            decision, won = "confirmed", confirmed
        elif dismissed > confirmed:
            decision, won = "dismissed", dismissed
        else:
            decision, won = None, max(confirmed, dismissed)
        majority = decision is not None and won * 2 > k   # quorum: strict majority of requested runs
        agreement = round(won / k, 2) if k else 0.0
        record = {
            "k": k, "completed": n, "confirmed": confirmed, "dismissed": dismissed,
            "abstained": n - len(cast), "failed": k - n,
            "agreement": agreement,
            "outcome": "majority" if majority else "split",
            "decision": decision if majority else None,
        }
        verdict = None
        if majority:
            winners = [v for v in cast if v["decision"] == decision]
            mean_conf = sum(float(v["confidence"]) for v in winners) / len(winners)
            sev_counts = Counter(v["severity"] for v in winners)
            top = max(sev_counts.values())
            severity = max((s for s, c in sev_counts.items() if c == top),
                           key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else -1)
            verdict = dict(
                winners[0],
                confidence=round(mean_conf * agreement, 2),
                severity=severity,
                evidence=_union(v["evidence"] for v in winners),
                reviewed_candidates=_union(v.get("reviewed_candidates") for v in winners),
            )
            record["mean_confidence"] = round(mean_conf, 2)
        out[iid] = {"outcome": record["outcome"], "decision": record["decision"],
                    "verdict": verdict, "votes": record}
    return out
