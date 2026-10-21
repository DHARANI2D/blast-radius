"""Capture README/abstract screenshots of the Control Tower and the architecture page.

Needs a running UI (python -m blastradius ui --port 8599) and Playwright with a
local Chromium. Usage:
    python scripts/capture_screenshots.py [--url http://localhost:8599] [--chromium /path/to/chrome]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "img"


def wait_idle(page, seconds: int = 120) -> None:
    page.wait_for_timeout(800)
    for _ in range(seconds * 4):
        if page.locator('[data-testid="stStatusWidget"]').count() == 0:
            break
        page.wait_for_timeout(250)
    page.wait_for_timeout(900)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8599")
    ap.add_argument("--chromium", default=None)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=a.chromium) if a.chromium else p.chromium.launch()
        page = b.new_page(viewport={"width": 1500, "height": 950})
        page.goto((ROOT / "docs" / "architecture.html").as_uri())
        page.locator(".wrap").screenshot(path=str(OUT / "architecture.png"))

        page.goto(a.url)
        wait_idle(page)
        page.get_by_role("button", name="Reset lab").click()
        wait_idle(page)
        page.get_by_role("button", name="Analyse change").click()
        wait_idle(page)
        page.screenshot(path=str(OUT / "01_blast_radius.png"))
        page.get_by_text("② Plan & Verifier").click()
        wait_idle(page)
        page.screenshot(path=str(OUT / "02_verifier.png"))
        page.get_by_text("③ Go / No-Go").click()
        wait_idle(page)
        page.screenshot(path=str(OUT / "03_go_no_go.png"))
        page.get_by_role("button", name="Approve and sign").click()
        wait_idle(page)
        page.get_by_text("④ Execution").click()
        wait_idle(page)
        page.wait_for_timeout(2500)
        page.screenshot(path=str(OUT / "04_canary_rollback.png"))
        page.get_by_text("⑤ Audit & report").click()
        wait_idle(page)
        page.screenshot(path=str(OUT / "05_audit.png"))
        page.get_by_role("button", name="New run").click()
        wait_idle(page)
        page.get_by_role("button", name="Analyse change").click()
        wait_idle(page)
        page.get_by_text("Risk heat").click()
        wait_idle(page)
        page.screenshot(path=str(OUT / "06_learned_rerun.png"))
        b.close()
    print(f"screenshots written to {OUT}")


if __name__ == "__main__":
    main()
