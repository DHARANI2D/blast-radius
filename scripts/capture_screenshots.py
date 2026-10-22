"""Capture README/abstract screenshots of the Control Tower and the architecture page.

Needs a running UI (python -m blastradius ui --port 8599, offline mode, default fault
scenario) and Playwright with a local Chromium. Usage:
    python scripts/capture_screenshots.py [--url http://localhost:8599] [--chromium /path/to/chrome]

Streamlit scrolls inside its own container, so long views are captured with a tall
viewport and clipped to the bottom of the rendered content.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "img"
WIDTH = 1500


def wait_idle(page, seconds: int = 120) -> None:
    page.wait_for_timeout(800)
    for _ in range(seconds * 4):
        if page.locator('[data-testid="stStatusWidget"]').count() == 0:
            break
        page.wait_for_timeout(250)
    page.wait_for_timeout(900)


def shot(page, name: str, height: int = 950) -> None:
    """Screenshot the app at the given viewport height, clipped to where the content ends."""
    page.set_viewport_size({"width": WIDTH, "height": height})
    page.wait_for_timeout(1200)
    bottom = page.evaluate("""() => {
        const blocks = document.querySelectorAll('[data-testid="stMainBlockContainer"] > div > div');
        let b = 0;
        for (const el of blocks) b = Math.max(b, el.getBoundingClientRect().bottom);
        return b;
    }""")
    clip_h = int(min(height, max(950, bottom + 24)))
    page.screenshot(path=str(OUT / name), clip={"x": 0, "y": 0, "width": WIDTH, "height": clip_h})
    page.set_viewport_size({"width": WIDTH, "height": 950})


def tab(page, label: str) -> None:
    page.get_by_role("tab", name=label).click()
    wait_idle(page)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8599")
    ap.add_argument("--chromium", default=None)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=a.chromium) if a.chromium else p.chromium.launch()
        page = b.new_page(viewport={"width": 1600, "height": 900})
        page.goto((ROOT / "docs" / "architecture.html").as_uri())
        page.locator(".wrap").screenshot(path=str(OUT / "architecture.png"))

        page.set_viewport_size({"width": WIDTH, "height": 950})
        page.goto(a.url)
        wait_idle(page)
        page.get_by_role("button", name="Reset lab").click()
        wait_idle(page)
        page.get_by_role("button", name="Analyse change").click()
        wait_idle(page)
        shot(page, "01_blast_radius.png")
        tab(page, "② Plan & Verifier")
        shot(page, "02_verifier.png", 2400)
        page.get_by_text("Red-team benchmark: how do we know").click()
        wait_idle(page)
        page.get_by_role("button", name="Run benchmark (about 5 s)").click()
        wait_idle(page)
        shot(page, "07_redteam.png", 3600)
        tab(page, "③ Go / No-Go")
        shot(page, "03_go_no_go.png", 1900)
        page.get_by_role("button", name="Approve and sign").click()
        wait_idle(page)
        tab(page, "④ Execution")
        page.wait_for_timeout(2500)
        shot(page, "04_canary_rollback.png", 3000)
        tab(page, "⑤ Audit & report")
        shot(page, "05_audit.png", 1400)
        tab(page, "⑥ Ask")
        page.get_by_role("button", name="Does System ROM U54 v2.32 fix SYN-CVE-2026-1105?").click()
        wait_idle(page)
        page.get_by_role("button", name="Ask", exact=True).click()
        wait_idle(page)
        shot(page, "08_ask.png", 1400)
        page.get_by_role("button", name="New run").click()
        wait_idle(page)
        page.get_by_role("button", name="Analyse change").click()
        wait_idle(page)
        page.get_by_text("Risk heat").click()
        wait_idle(page)
        shot(page, "06_learned_rerun.png")
        b.close()
    print(f"screenshots written to {OUT}")


if __name__ == "__main__":
    main()
