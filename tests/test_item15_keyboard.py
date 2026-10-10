# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""ITEM-15: run rows, phase layers and chip remove control must be keyboard reachable."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "src/bastion/web/static"
APP_JS = (STATIC / "app.js").read_text()
RUNS_JS = (STATIC / "runs.js").read_text()


def test_run_rows_are_focusable_buttons_with_enter_space():
    assert 'role="button" tabindex="0"' in RUNS_JS
    assert re.search(r'tr\.addEventListener\("keydown".*?e\.key === "Enter" \|\| e\.key === " "', RUNS_JS, re.S)


def test_phase_layers_are_focusable_with_label_and_key_handler():
    assert 'layer.setAttribute("role", "button"); layer.tabIndex = 0;' in APP_JS
    assert 'aria-label", `phase ${i + 1}' in APP_JS
    assert re.search(r'stage\.addEventListener\("keydown".*?showPhaseDetail', APP_JS, re.S)


def test_chip_remove_control_is_labelled_focusable_with_key_handler():
    assert 'role="button" tabindex="0" aria-label="remove ${esc(f.name)}"' in APP_JS
    assert re.search(r'b\.addEventListener\("keydown".*?rm\(\)', APP_JS, re.S)
