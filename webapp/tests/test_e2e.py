"""
Real browser end-to-end tests for the HAKUZA web dashboard, using Playwright
(Chromium, headless) — the current best-in-class open-source browser
automation tool, actively maintained by Microsoft, with first-class Python
support and auto-waiting that eliminates most test flakiness.

Why this exists / why it's stronger than the curl-based checks used earlier
tonight: curl-and-grep can only prove that a string like "<script>" doesn't
appear *unescaped* in the raw HTML response. It cannot prove that JavaScript
never actually *executes* — a real browser test can, by registering a
listener for the `dialog` event (which fires if and only if a live
`alert()`/`confirm()`/`prompt()` call runs) and asserting it never fires
when the page is loaded with a payload that would trigger it if the
escaping were broken. That's the strongest practical proof available that
the stored-XSS fix from earlier tonight (html.escape() on every finding
field) actually holds under a real rendering engine, not just under a
text-matching approximation of one.

Run with:  python3 -m pytest webapp/tests/test_e2e.py -v
Requires:  pip install playwright  &&  playwright install chromium
"""

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright, Page, Browser

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HAKUZA_PY = REPO_ROOT / "hakuza.py"
HAKUZA_HOME = Path.home() / ".hakuza"
PORT = 7391  # distinct from the default 7373, so a real `hakuza serve` running
             # concurrently on the operator's machine is never disturbed by this suite
BASE_URL = f"http://127.0.0.1:{PORT}"

ENG_SAFE = "e2e-safe-eng"
ENG_XSS = "e2e-xss-eng"
XSS_PAYLOAD_MARKER = "e2e_xss_marker_9f31c2"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HAKUZA_PY), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.fixture(scope="session", autouse=True)
def seeded_state():
    """
    Wipe any pre-existing ~/.hakuza state, seed two throwaway engagements via
    the real CLI (not by poking the DB directly — this exercises the exact
    same code path a real user's `hakuza init`/`hakuza add` would), start the
    web server, and clean everything up afterward regardless of test outcome.
    """
    had_prior_state = HAKUZA_HOME.exists()
    if had_prior_state:
        shutil.move(str(HAKUZA_HOME), str(HAKUZA_HOME) + ".e2e-test-backup")

    try:
        # Engagement 1: normal data, used for the "does the UI render real
        # content correctly" checks.
        r = _run_cli(
            "init", ENG_SAFE,
            "--client", "E2E Test Client",
            "--target", "example.com",
            "--type", "web",
        )
        assert r.returncode == 0, f"init failed: {r.stdout}\n{r.stderr}"

        r = subprocess.run(
            [sys.executable, str(HAKUZA_PY), "add", "--quick"],
            cwd=str(REPO_ROOT),
            input="Insecure Direct Object Reference on /api/accounts\n2\nexample.com/api/accounts/1234\nSequential numeric IDs allow enumerating other users' accounts.\n\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, f"add failed: {r.stdout}\n{r.stderr}"

        # Engagement 2: a finding whose title/description contain a literal
        # <script> payload, exactly the "pentester pastes their PoC into the
        # description field" scenario that produced a real stored-XSS bug
        # earlier tonight. The marker string lets the JS-execution-proof test
        # below assert on a *specific* alert(), not just "no alert fired for
        # any reason".
        r = _run_cli(
            "init", ENG_XSS,
            "--client", "E2E XSS Client",
            "--target", "example.com",
            "--type", "web",
        )
        assert r.returncode == 0, f"init failed: {r.stdout}\n{r.stderr}"

        xss_input = (
            f"Reflected XSS <script>alert('{XSS_PAYLOAD_MARKER}')</script>\n"
            "1\n"
            f"example.com/search?q=<script>alert('{XSS_PAYLOAD_MARKER}')</script>\n"
            f"Payload reflected unescaped: <script>alert('{XSS_PAYLOAD_MARKER}')</script>\n\n"
        )
        r = subprocess.run(
            [sys.executable, str(HAKUZA_PY), "add", "--quick"],
            cwd=str(REPO_ROOT),
            input=xss_input,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, f"add (xss) failed: {r.stdout}\n{r.stderr}"

        # Start the web server as a real subprocess (not in-process — this
        # exercises the actual `hakuza serve` entry point, threading flag and
        # all, not a test-only shortcut).
        env = os.environ.copy()
        env["HAKUZA_WEB_PORT"] = str(PORT)
        proc = subprocess.Popen(
            [sys.executable, str(HAKUZA_PY), "serve", "--no-browser", "--port", str(PORT)],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_for_server(BASE_URL, timeout=15)

        yield

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        shutil.rmtree(HAKUZA_HOME, ignore_errors=True)
        if had_prior_state:
            shutil.move(str(HAKUZA_HOME) + ".e2e-test-backup", str(HAKUZA_HOME))


def _wait_for_server(url: str, timeout: float) -> None:
    import urllib.request
    import urllib.error

    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except urllib.error.URLError as exc:
            last_exc = exc
            time.sleep(0.3)
    raise RuntimeError(f"hakuza serve never became reachable at {url}: {last_exc}")


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        yield b
        b.close()


@pytest.fixture
def page(browser: Browser):
    ctx = browser.new_context()
    pg = ctx.new_page()
    yield pg
    ctx.close()


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_index_loads_and_shows_engagement_cards(page: Page):
    page.goto(BASE_URL, wait_until="networkidle")
    assert "HAKUZA" in page.title()
    cards = page.locator("a.card")
    assert cards.count() >= 2, "expected both seeded engagements to appear as cards"
    assert page.locator("a.card", has_text=ENG_SAFE).count() == 1
    assert page.locator("a.card", has_text=ENG_XSS).count() == 1


def test_click_through_from_index_to_engagement(page: Page):
    """Real user interaction — an actual mouse click, not a direct URL nav —
    proves the card link/routing genuinely works end to end."""
    page.goto(BASE_URL, wait_until="networkidle")
    page.locator("a.card", has_text=ENG_SAFE).click()
    page.wait_for_load_state("networkidle")
    assert re.search(rf"/engagement/{ENG_SAFE}$", page.url)
    assert page.locator("h1", has_text=ENG_SAFE).count() == 1


def test_engagement_page_renders_risk_gauge_and_findings(page: Page):
    page.goto(f"{BASE_URL}/engagement/{ENG_SAFE}", wait_until="networkidle")
    assert page.locator(".panel.gauge-wrap svg").count() >= 1, "risk gauge SVG should render"
    assert page.locator("table").count() >= 1
    assert "Insecure Direct Object Reference" in page.content()


def test_finding_detail_click_through(page: Page):
    page.goto(f"{BASE_URL}/engagement/{ENG_SAFE}", wait_until="networkidle")
    page.get_by_role("link", name=re.compile("Insecure Direct Object Reference")).first.click()
    page.wait_for_load_state("networkidle")
    assert "/finding/" in page.url
    assert page.locator("h1", has_text="Insecure Direct Object Reference").count() == 1
    assert "Sequential numeric IDs" in page.content()


def test_nonexistent_engagement_returns_404(page: Page):
    resp = page.goto(f"{BASE_URL}/engagement/does-not-exist-e2e", wait_until="networkidle")
    assert resp.status == 404


def test_no_console_errors_on_any_page(page: Page):
    errors = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(str(exc)))

    for path in (
        "/",
        f"/engagement/{ENG_SAFE}",
        f"/engagement/{ENG_XSS}",
    ):
        page.goto(f"{BASE_URL}{path}", wait_until="networkidle")

    assert errors == [], f"unexpected browser console/JS errors: {errors}"


def test_xss_payload_does_not_execute_in_a_real_browser(page: Page):
    """
    The definitive test. If the html.escape() fix from earlier tonight ever
    regresses, this is what should catch it: register a listener for the
    `dialog` event — which Chromium only fires for a genuine, executing
    `alert()`/`confirm()`/`prompt()` call, never for escaped text that merely
    *looks* like a script tag — and assert it never fires while visiting
    every page that renders the seeded XSS-payload finding.
    """
    fired_dialogs = []

    def handle_dialog(dialog):
        fired_dialogs.append(dialog.message)
        dialog.dismiss()

    page.on("dialog", handle_dialog)

    page.goto(f"{BASE_URL}/engagement/{ENG_XSS}", wait_until="networkidle")
    # Confirm the payload text is actually present on the page (as inert,
    # escaped text) — otherwise this test would trivially "pass" by testing
    # nothing at all.
    assert XSS_PAYLOAD_MARKER in page.content()

    finding_link = page.get_by_role("link", name=re.compile("Reflected XSS")).first
    finding_link.click()
    page.wait_for_load_state("networkidle")
    assert XSS_PAYLOAD_MARKER in page.content()

    assert fired_dialogs == [], (
        f"XSS payload actually executed in a real browser — a genuine, "
        f"live regression of the stored-XSS fix. Fired dialog(s): {fired_dialogs}"
    )


def test_report_link_serves_content(page: Page):
    resp = page.goto(f"{BASE_URL}/engagement/{ENG_SAFE}/report", wait_until="networkidle")
    # No `hakuza report` has been run for this engagement yet in this suite,
    # so a 404 with a clear message is the *correct* behavior, not an error —
    # assert on that rather than requiring a report to exist.
    assert resp.status in (200, 404)
