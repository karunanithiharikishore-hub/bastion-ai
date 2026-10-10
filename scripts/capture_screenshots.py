#!/usr/bin/env python3
# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Capture the README screenshots from a running dashboard (synthetic samples only).

    bastion serve samples --llm off --port 8787 &
    python3 scripts/capture_screenshots.py docs/screenshots

Needs Playwright (`pip install playwright`) and Google Chrome.
"""
import sys
from playwright.sync_api import sync_playwright
OUT = sys.argv[1]
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome", headless=True)
    pg = b.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    pg.goto("http://localhost:8787/", wait_until="networkidle")
    pg.wait_for_selector("#verdict:not(:empty)", timeout=60000)
    for y in range(0, 7000, 400):          # trigger scroll-reveal animations
        pg.evaluate(f"window.scrollTo(0,{y})"); pg.wait_for_timeout(150)
    pg.wait_for_timeout(1500)
    def shot(name, sel, pad=0):
        el = pg.locator(sel).first
        el.scroll_into_view_if_needed(); pg.wait_for_timeout(1200)
        el.screenshot(path=f"{OUT}/{name}")
        print("ok", name)
    pg.evaluate("window.scrollTo(0,0)"); pg.wait_for_timeout(1500)
    pg.screenshot(path=f"{OUT}/01-intake.png", clip={"x": 0, "y": 0, "width": 1440, "height": 900}, full_page=False)
    print("ok 01-intake.png")
    shot("02-verdict.png", "#verdict")
    shot("03-summary.png", "#summary-panel")
    shot("04-storyline.png", "section:has(#stage-wrap)")
    shot("05-swarm.png", "section:has(#orbit)")
    b.close()
