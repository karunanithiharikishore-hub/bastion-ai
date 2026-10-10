"""ITEM-10: a successful risky Azure sign-in (T1078, zero failures) must not be
narrated as defense evasion / persistence, nor headlined as failed-then-success."""
from bastion import analyzer
from bastion.ingest import ingest_path
from bastion.pipeline import correlate, map_attack, normalize
from bastion.report.rca import assess_incident, deterministic_storyline

from conftest import SAMPLES

RISKY = ("Date (UTC),User,IP address,Status,Risk level during sign-in\n"
         "2026-10-03T22:00:00Z,bob@x.com,203.0.113.5,Success,high\n"
         "2026-10-03T22:01:00Z,bob@x.com,203.0.113.5,Success,high\n")


def _incident(tmp_path):
    p = tmp_path / "InteractiveSignIns_risky.csv"
    p.write_text(RISKY, encoding="utf-8")
    events = normalize(ingest_path(str(p)))
    map_attack(events)
    return correlate(events)[0]


def test_risky_signin_storyline_does_not_claim_defense_evasion_or_persistence(tmp_path):
    story = deterministic_storyline(_incident(tmp_path))
    tactics = {p["tactic"] for p in story["phases"]}
    assert "credential-access" in tactics
    assert not tactics & {"defense-evasion", "persistence"}
    steps = " ".join(story["attack_summary"]["what_they_did"])
    assert "disabled or evaded defenses" not in steps
    assert "established persistence" not in steps
    assert "persistence" not in story["likely_objective"]
    assert "theft" not in story["likely_objective"]


def test_risky_signin_success_only_headline_is_not_failed_then_success(tmp_path):
    v = assess_incident(_incident(tmp_path))
    assert not v["headline"].startswith("Failed sign-ins")
    assert "failed" not in v["headline"].lower()
    assert "0 failed" not in v["why"]


def test_samples_still_likely_real_attack_without_llm():
    result = analyzer.analyze([SAMPLES], use_llm=False)
    assert result["incidents"][0]["verdict"]["level"] == "likely-malicious"
