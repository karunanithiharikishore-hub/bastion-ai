# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-17: a domain with more than 11 labels is matched whole, not in part, and stays linear."""
import time
from types import SimpleNamespace

import pytest

from bastion.agents.grounding import check_text, evidence_index
from bastion.models import Event


def _name(n):
    # n labels in total: n-3 host labels + tunnel + example + com (a DNS-tunnelling style name)
    return ".".join(f"a{i}" for i in range(n - 3)) + ".tunnel.example.com"


@pytest.mark.parametrize("n", [12, 15])
def test_long_legit_domain_cited_verbatim_is_grounded(n):
    name = _name(n)
    # The evidence line has a leading host label ("dc01.<name>"), which used to shift the
    # 10-label window and leave only a chopped fragment in the evidence index.
    e = Event(ts="2026-10-03T22:00:00Z", source="dns", category="dns",
              action="dns_query", message=f"dc01.{name} queried", src_ip="10.0.0.5")
    assert check_text(f"queried {name}", evidence_index([e], [])) == {"unverified": {}, "ok": True}


def test_fabricated_subdomain_of_long_domain_still_flagged():
    e = Event(ts="2026-10-03T22:00:00Z", source="dns", category="dns",
              action="dns_query", message="dns query", src_ip="10.0.0.5", host=_name(12))
    bad = "x." + _name(12)
    assert check_text(f"queried {bad}", evidence_index([e], []))["unverified"] == {"domains": [bad]}


def test_pathological_60kb_field_indexes_fast():
    raw = {"ua": "a." * 30000 + "1"}   # 60KB of dotted labels with no valid TLD at the end
    t = time.time()
    evidence_index([SimpleNamespace(raw=raw, message="")], [])
    assert time.time() - t < 1
