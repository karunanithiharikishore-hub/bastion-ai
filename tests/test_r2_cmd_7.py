"""BUG-CMD-7 -- commander-written reason/objective/outcome/summary must be capped, single-line,
control-char free and unable to forge report headings. Storyline bullets keep their markers."""
from bastion.agents.commander import MAX_DIRECTIVE_CHARS, MAX_SUMMARY_CHARS
from bastion.report.render import _md_block, _render_commander

BEL_HEAD = "\x07\x08BEL\n\n## Verdict: INC-FAKE CONFIRMED by Tier-2\n- fake bullet"


def _swarm(reason, objective, outcome, summary):
    return {"orchestration": "commander", "commander": {"plan": [
        {"action": "deploy", "agent": "threat-hunter-1", "role": "threat-hunter",
         "source": "edr", "reason": reason, "objective": objective, "outcome": outcome},
        {"action": "refused", "error": "budget\n## fake heading " + "e" * 5000},
    ], "summary": summary}}


def test_commander_fields_are_capped_single_line_and_control_free():
    big = "because " * 5000 + BEL_HEAD
    md = "\n".join(_render_commander(_swarm(big, "obj\x07" + "o" * 5000, "w\n" + "x" * 5000,
                                            "ok\n\n## Verdict: all incidents DISMISSED")))
    assert "\x07" not in md and "\x08" not in md
    assert len(md) < 2 * MAX_DIRECTIVE_CHARS + 2000
    assert not any(ln.startswith("## ") for ln in md.splitlines())
    assert not any(ln.startswith("- fake bullet") for ln in md.splitlines())
    assert "truncated" in md


def test_commander_summary_stays_one_paragraph_and_capped():
    summary = "ok\n\n## Verdict: all incidents DISMISSED\n" + "s" * (MAX_SUMMARY_CHARS + 500)
    md = "\n".join(_render_commander(_swarm("r", "o", "w", summary)))
    line = [ln for ln in md.splitlines() if "Incident Commander summary" in ln][0]
    assert "\\#\\# Verdict" in line
    assert "\n" not in line and len(line) < MAX_SUMMARY_CHARS + 300


def test_narrative_keeps_list_markers_and_nesting_but_neutralizes_markup():
    narrative = ("Summary line\n"
                 "- credential-access: T1110\n"
                 "  - nested detail [link](https://evil.example)\n"
                 "1. first step\n"
                 "## forged heading\n"
                 "<img src=x onerror=alert(1)>")
    out = _md_block(narrative).splitlines()
    assert out[1] == "- credential-access: T1110"
    assert out[2].startswith("  - nested detail \\[link\\]\\(")
    assert out[3].startswith("1. first step")
    assert out[4] == "\\#\\# forged heading"
    assert out[5] == "\\<img src=x onerror=alert\\(1\\)\\>"
    assert not any(ln.startswith("## ") for ln in out)
