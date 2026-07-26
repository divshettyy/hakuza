# `webapp/tests/test_e2e.py` — real-browser dashboard tests

Real-browser tests for the web dashboard using [Playwright](https://playwright.dev/)
(Chromium, headless) — the strongest practical proof that pages render correctly and
that the stored-XSS fix holds, since it asserts on actual DOM/JS behavior rather than
grepping raw HTML. The key test seeds a finding containing a literal
`<script>alert(...)</script>` payload, visits it in a real Chromium engine, and asserts
the browser's `dialog` event never fires (which it only does for a genuinely
*executing* `alert()`) — a stronger check than any text-matching approach.

```bash
pip install -r webapp/tests/requirements.txt
python3 -m playwright install chromium
python3 -m pytest webapp/tests/test_e2e.py -v
```

The suite spins up `hakuza serve` on a dedicated port (7391), seeds two throwaway
engagements through the real CLI, runs 8 tests (page rendering, click-through
navigation, 404 handling, zero console errors, the XSS-execution proof, and
report-link serving), and backs up/restores any pre-existing `~/.hakuza` state so it's
safe to run against a real installation with real engagement data.

## Root-less environments (no sudo)

On a root-less environment where `playwright install --with-deps` can't run `apt-get`,
Chromium's shared-library dependencies (`libnspr4`, `libnss3`, `libatk-1.0`,
`libatk-bridge-2.0`, `libXdamage`, `libasound2`, `libatspi2.0`, `libxres1`) may need to
be extracted manually via `dpkg -x <deb> <destdir>` from downloaded `.deb` packages and
referenced via `LD_LIBRARY_PATH` before Chromium will launch:

```bash
export LD_LIBRARY_PATH="$HOME/.local/lib/playwright-deps:$LD_LIBRARY_PATH"
```

A real CI runner with root can just use `playwright install --with-deps chromium`
instead — this workaround is only needed without one. The same `LD_LIBRARY_PATH`
export is also required before `hakuza active`'s DOM-XSS check can launch Chromium in
the same kind of environment.
