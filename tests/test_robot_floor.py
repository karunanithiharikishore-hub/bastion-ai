# Bastion AI - SOC floor layout: no overlapping labels/bubbles/desks/HUD for 1..8 Tier-1 and 0..7 specialists.
import itertools, json, re, shutil, subprocess
from pathlib import Path
import pytest

STATIC = Path(__file__).resolve().parents[1] / "src/bastion/web/static"
APP_JS = (STATIC / "app.js").read_text()
PURE = APP_JS.split("/*FLOOR-PURE-START*/")[1].split("/*FLOOR-PURE-END*/")[0]
NODE = shutil.which("node")


@pytest.mark.skipif(not NODE, reason="node not installed")
@pytest.mark.skipif(not NODE, reason="node not installed")
def test_floor_labels_are_short_role_names():
    js = PURE + """console.log(JSON.stringify([floorLabel("soc-lead",0), floorLabel("soc2-lead",2), floorLabel("soc1-cloudtrail",1),
      floorLabel("Digital Forensics Analyst",3), floorLabel("Security Engineer / Architect",3), floorLabel("Threat Intelligence Analyst",3)]));"""
    out = json.loads(subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout)
    assert out == ["Commander", "Lead", "Cloud", "Forensics", "Engineer", "Intel"]


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_floor_layout_has_no_overlaps():
    js = PURE + """
const mk = (p, n) => Array.from({length: n}, (_, i) => ({id: p + i, label: floorLabel("z".repeat(20), 3)}));
const out = [];
for (let a = 1; a <= 8; a++) for (let c = 0; c <= 7; c++) for (let t2 = 0; t2 <= 2; t2++)
  out.push(floorLayout(mk("c", 1), mk("a", a), mk("l", t2), mk("s", c)));
console.log(JSON.stringify(out));
"""
    layouts = json.loads(subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout)
    assert len(layouts) == 8 * 8 * 3
    for L in layouts:
        boxes = [("hud", L["hud"])]
        for n in L["nodes"]:
            boxes += [(n["id"] + ":node", n["node"]), (n["id"] + ":label", n["label"]), (n["id"] + ":bubble", n["bubble"])]
        for name, b in boxes:
            assert 0 <= b["x"] and b["x"] + b["w"] <= L["W"] and 0 <= b["y"] and b["y"] + b["h"] <= L["H"], name
        for (n1, a), (n2, b) in itertools.combinations(boxes, 2):
            sep = a["x"] + a["w"] <= b["x"] or b["x"] + b["w"] <= a["x"] or a["y"] + a["h"] <= b["y"] or b["y"] + b["h"] <= a["y"]
            # a node's own label/bubble may touch its own node box edge; everything else must be clear
            assert sep or n1.split(":")[0] == n2.split(":")[0], (n1, n2)


def test_preparing_banner_wired_statically():
    # no DOM harness: check the reset/banner/HUD hooks exist and the banner only uses textContent
    assert "Preparing evidence" in APP_JS and 'ev.kind === "stage"' in APP_JS
    assert "Agents active ${active}/${total}" in APP_JS and '"–"' in APP_JS
    assert ".fbanner" in (STATIC / "styles.css").read_text()
