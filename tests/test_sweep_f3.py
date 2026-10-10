# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-3: a cache hit must report this run's events_ingested and show its
agents as cached (0 deployed), not inherit the stored run's numbers."""
import os

import pytest

from conftest import BENIGN_SAMPLES
from test_repeatability import VerdictBackbone
from bastion import analyzer, cache as run_cache


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "cache"
    monkeypatch.setenv(run_cache.CACHE_ENV, str(d))
    return d


def test_cache_hit_reports_this_runs_events_and_cached_agents(cache_dir, tmp_path):
    src = open(os.path.join(BENIGN_SAMPLES, "auth_syslog.log"), encoding="utf-8").read()
    log = tmp_path / "auth.log"
    log.write_text(src)

    bb = VerdictBackbone(str(log))   # Tier-2 files verdicts, so the first run is storable

    def run(**kw):
        return analyzer.analyze([str(log)], backbone=bb, intel_store=None,
                                orchestration="fixed", cache="use", **kw)

    first = run()
    assert first["meta"]["cache"] == "miss (stored)"
    assert first["meta"]["agents_deployed"] > 0
    # Same normalized events, twice the raw lines: the key matches, the raw count does not.
    log.write_text(src + src)
    expected = analyzer.analyze([str(log)], backbone=None, use_llm=False, run_agents=False,
                                cache="off")["meta"]["events_ingested"]
    second = run()
    assert second["meta"]["cache"] == "hit"
    assert second["meta"]["events_ingested"] == expected != first["meta"]["events_ingested"]
    assert second["meta"]["agents_deployed"] == 0
    assert second["meta"]["agents_cached"] == first["meta"]["agents_deployed"]
