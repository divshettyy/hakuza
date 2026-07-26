# HAKUZA — Unified Penetration Testing Platform

An AI-augmented CLI that runs the full lifecycle of a security engagement — recon, scanning, findings management, exploitation-chain reasoning, and reporting — from one tool, backed by a local SQLite engagement database and Anthropic's Claude for triage and analysis.

Built by Divith D Shetty — CEH · CRTP · CAISP · BFSI specialist.

## Why this exists

Most pentest tooling is single-purpose: a scanner, a notes app, a report template, an AI chat window, all disconnected. HAKUZA keeps one engagement record (target, scope, findings, recon artifacts, AI analysis) and drives real tools — subfinder, httpx, katana, waybackurls, nuclei, ffuf — directly against it, so a finding discovered by `hakuza scan` is the same finding `hakuza report` writes up, with no copy-pasting between tools.

## The flagship feature: `hakuza autopilot`

```bash
hakuza init my-target --client "Acme Corp" --target https://acme.com --type web
hakuza scope --add "https://acme.com/*"
hakuza autopilot --profile full
```

One command, unattended: recon (subfinder/httpx/nmap) → subdomain takeover scan → wayback URL mining → secrets hunting → nuclei vulnerability scan → AI triage → AI attack-chain reasoning → final report. Each phase is isolated — one tool failing doesn't kill the run — and a JSON run log with per-phase timing lands in the engagement directory when it's done. If scope is defined and you override the target, it refuses to run against anything outside it.

Without an `ANTHROPIC_API_KEY` set, the AI-dependent phases (analyze/chain/report) are skipped automatically rather than blocking on an interactive prompt — the recon/takeover/wayback/secrets/scan phases still run and persist real findings.

## Engagement lifecycle

| Command | Purpose |
|---|---|
| `hakuza init` / `status` / `list` / `switch` | Create and manage engagements |
| `hakuza recon` | subfinder + httpx + nmap, AI subdomain prediction fallback |
| `hakuza takeover` | Subdomain takeover scan — 15-service dangling-CNAME fingerprint DB (S3, GitHub Pages, Heroku, Azure, Netlify, etc.), confirmed hits auto-saved as findings |
| `hakuza wayback` | waybackurls + katana historical URL mining, categorized and secret-scanned |
| `hakuza secrets` | JS file + exposed-path secret hunting |
| `hakuza fuzz` | Smart ffuf wrapper — dirs/params/api/vhosts, tech-aware wordlist selection |
| `hakuza scan` | nuclei scan, parsed and persisted as findings. `--profile vuln` runs a comprehensive vulnerability-class sweep — XSS, SQLi, NoSQLi, RCE, SSRF, SSTI, XXE, LFI, IDOR, CORS, JWT, CSRF, deserialization, open redirect, GraphQL, file upload, CRLF injection (`quick`=fast CVE/exposure triage, `full`=everything, `stealth`=vuln tags at a throttled request rate to avoid WAF/IDS alerting) |
| `hakuza autopilot` | recon → takeover → wayback → secrets → scan → (AI triage/chain) → report, chained, unattended |
| `hakuza active` | Live active testing — statistical baseline + parameter mutation + differential response analysis, with optional AI escalation and auto-generated curl/Python PoCs (see below) |
| `hakuza import` | Import Nessus/Nuclei/Burp/CSV output |
| `hakuza scope` | Add/check/list scope entries (glob-matched) |
| `hakuza add` / `findings` / `update` | Manual findings CRUD |
| `hakuza analyze` / `chain` / `advise` | AI triage, exploitation chains, attack-vector suggestions |
| `hakuza deduplicate` / `enrich` | AI-powered findings-list cleanup — merge duplicates, fill in missing CVSS/CWE/impact/remediation |
| `hakuza prioritize` / `matrix` | AI remediation ordering (with optional BFSI regulatory-deadline weighting) and an attack-chain matrix across findings |
| `hakuza diff-report` | Delta report between two findings exports — new/fixed/changed, no AI required |
| `hakuza report` | Markdown + HTML report with risk gauge and finding cards |
| `hakuza ad` / `network` / `lateral` | Active Directory / internal network testing modules |
| `hakuza mobile` / `ios` / `cloud` / `iot` | Mobile, cloud, and IoT testing modules |
| `hakuza ai-audit` | LLM/AI system security audit (28 tests) |
| `hakuza wizard` | Guided walkthrough for demos |
| `hakuza dashboard` | Live terminal dashboard for the current engagement |
| `hakuza serve` | Browser-based web dashboard (Flask) — read-only view of all engagements |

Run `hakuza --help` or `hakuza <command> --help` for full details — 40+ commands total.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # optional — AI phases degrade gracefully without it
python3 hakuza.py init test --client "Test Co" --target scanme.nmap.org --type web
python3 hakuza.py autopilot --profile quick
```

State lives in `~/.hakuza/` (SQLite DB + per-engagement artifact directories), separate from this repo.

## Web dashboard (`hakuza serve`)

```bash
hakuza serve                 # http://127.0.0.1:7373, opens a browser tab
hakuza serve --port 8080     # or run it directly: cd webapp && python3 run.py
```

A dark-themed Flask dashboard (`webapp/`) rendering the same engagement DB the CLI
uses — engagement cards with per-severity finding counts and an animated risk meter,
a per-engagement view with the SVG risk gauge, severity bar chart, recon summary and a
findings table, click-through finding detail, and a link to the latest generated HTML
report. It reuses hakuza.py's own DB helpers and report colour palette so the web UI and
the CLI-generated HTML report look identical. It is **read-only** against the database
and binds to `127.0.0.1` only; the Werkzeug debugger stays off unless `--debug` (or
`HAKUZA_WEB_DEBUG=1`) is set explicitly.

## End-to-end tests (`webapp/tests/test_e2e.py`)

Real-browser tests for the web dashboard using [Playwright](https://playwright.dev/) (Chromium, headless) — the strongest practical proof that pages render correctly and that the stored-XSS fix holds, since it asserts on actual DOM/JS behavior rather than grepping raw HTML. The key test seeds a finding containing a literal `<script>alert(...)</script>` payload, visits it in a real Chromium engine, and asserts the browser's `dialog` event never fires (which it only does for a genuinely *executing* `alert()`) — a stronger check than any text-matching approach.

```bash
pip install -r webapp/tests/requirements.txt
python3 -m playwright install chromium
python3 -m pytest webapp/tests/test_e2e.py -v
```

The suite spins up `hakuza serve` on a dedicated port (7391), seeds two throwaway engagements through the real CLI, runs 8 tests (page rendering, click-through navigation, 404 handling, zero console errors, the XSS-execution proof, and report-link serving), and backs up/restores any pre-existing `~/.hakuza` state so it's safe to run against a real installation with real engagement data.

On a root-less environment where `playwright install --with-deps` can't run `apt-get` (no sudo), Chromium's shared-library dependencies (`libnspr4`, `libnss3`, `libatk-1.0`, `libatk-bridge-2.0`, `libXdamage`, `libasound2`, `libatspi2.0`, `libxres1`) may need to be extracted manually via `dpkg -x <deb> <destdir>` from downloaded `.deb` packages and referenced via `LD_LIBRARY_PATH` before Chromium will launch. A real CI runner with root can just use `playwright install --with-deps chromium` instead.

## Live active testing (`hakuza active`)

Every other scanning path in HAKUZA — `hakuza scan` (nuclei) — is STATIC template matching: a known request/response signature compared against a fixed library of known-bad patterns. `hakuza active` (`mod_active.py`) is the opposite approach: a real ACTIVE, adaptive differential-testing engine that sends live HTTP requests and reasons about *this specific target's* actual behavior instead of pattern-matching against a static template library.

```bash
hakuza active "https://target.tld/listproducts.php?cat=1"        # single URL
hakuza active --all --depth deep                                  # every query-param URL from `hakuza wayback` recon data
hakuza active "https://target.tld/page.php?id=1" --no-ai --max-requests 50
```

How it works: for each candidate URL it (1) sends the SAME real GET request 3 times to build a statistical baseline — status code, body length, sha256 hash, and response timing (mean + population stdev) — then (2) mutates one query parameter at a time with a small set of non-destructive probes and diffs the live mutated response against that real baseline (status/length/hash/`difflib` similarity ratio/timing), then (3) for ambiguous signals, optionally escalates to Claude for a human-pentester-style judgment call, and (4) for every CONFIRMED result, auto-generates a standalone, reproducible **curl command + Python PoC script** so the finding can be independently re-run — not just trusted on a scanner's say-so.

Vuln classes covered: reflected XSS (unescaped-reflection + working-payload confirmation, vs. encoded-but-inert reflection reported only as informational), SQL injection (error-based via vendor error signatures, boolean-based blind via three-way response-similarity comparison, and — `--depth deep` only — time-based blind with a *statistical* timing gate: `baseline_mean + max(3×stdev, 2.5s)`, not a fixed ">4 seconds" rule, to avoid false positives on naturally slow targets), OS command injection (time-based, `--depth deep` only, on shell-shaped parameter names), SSTI (`{{7*7}}`, Jinja2/Twig family), path traversal / LFI (`/etc/passwd` signature match, on file/path-shaped parameter names), open redirect (canary Location-header check, on redirect-shaped parameter names), CRLF/header injection (real parsed-header check), and a context-aware IDOR **heuristic** (path-ID substitution + differential analysis — flags a genuine signal at any similarity level, including same-template pages that only swap a few fields like a real profile/order page, while filtering out noise-field churn like session IDs/timestamps and access-denied pages via *context*, not just the raw similarity ratio; UUID/hashid-shaped IDs, which can't be brute-forced, are tested by cross-referencing real sibling IDs already discovered in the engagement's own recon data instead of guessing — always labeled as a lead requiring manual two-session confirmation, never an over-claimed finding).

**Beyond detection — UNION-based SQLi data extraction (`--depth deep`).** Once error-based SQLi is confirmed *and* the exact DB vendor is known from the error signature (MySQL, PostgreSQL, SQLite, or MSSQL), `hakuza active` automatically determines the injectable query's column count (`ORDER BY` binary probe), finds a column position that reflects string data into the response, and extracts real proof: DB version, current database, current user, and (MySQL/PostgreSQL/SQLite) up to 5 real table names — all via read-only `UNION SELECT`, nothing ever written. This turns "this parameter is injectable" into "here is the actual data it leaked," which is the difference between a scanner's say-so and a report a client can't argue with. Every extraction query uses a boundary marker filtered for leftover SQL syntax, specifically so it isn't fooled by a target that *also* reflects the raw payload elsewhere on the same page (a real failure mode found and fixed while building this against testlab's own `/product` endpoint, which has exactly that combination).

**Per-target checks (run once per URL, not per parameter):** CORS misconfiguration (an attacker-controlled `Origin` reflected in `Access-Control-Allow-Origin` — critical if paired with `Access-Control-Allow-Credentials: true`; also checks the `null`-origin bypass) and NoSQL injection via bracket-notation operators (`user[$ne]=x`, targeting Express/`qs`-style and PHP-style query parsers that turn bracket syntax into nested objects fed straight into a MongoDB-style query). NoSQL injection is tested two ways: per-parameter (catches a single field reaching an unsanitized query, e.g. a search/filter endpoint) and all-parameters-simultaneously (catches the classic AND-conjunction auth-bypass shape — `username == X AND password == Y` stays fully enforced unless every ANDed field is neutralized at once, confirmed directly against testlab's own `/login` endpoint, which needs exactly that). Both NoSQLi checks verify against a control request (the parameter simply removed, not bracket-renamed) before ever persisting a finding — otherwise a target that doesn't do bracket-notation parsing at all would false-positive purely because renaming a key makes the original parameter vanish, which can independently change behavior for reasons that have nothing to do with NoSQL operators (a real false-positive class found and fixed while building this).

**Race conditions — a genuinely different testing model.** Every check above is sequential baseline-vs-mutated diffing; race conditions need the opposite — N identical requests fired at the *same instant* via a real thread pool, not one after another. Gated to URLs that look action-shaped (`redeem`, `claim`, `checkout`, `vote`, `transfer`, ...) so a 10-request burst isn't wasted on every target. If 2 or more of the N concurrent requests come back as an unqualified success, that's treated as near-certain proof rather than a suggestive lead — for a correctly-guarded single-use action, at most one concurrent request should ever win. Confirmed findings get a dedicated, genuinely concurrent Python PoC (not the standard single-request template, which can't reproduce a race at all) — running it re-fires the same N-way burst and reports the real pass/fail count each time.

**JWT testing (`--jwt TOKEN`).** The one check that needs a real token handed to it rather than discovering its own target — `hakuza active` has no login flow of its own, so this is an explicit mode (like `--script`) rather than an automatic per-target check: `hakuza active "https://target.tld/api/profile" --jwt eyJ...`. Tests three real, extremely common JWT implementation bugs: **alg=none bypass** (forges a token with the header's algorithm set to `none` and no signature at all — a server that trusts the token's own declared algorithm instead of enforcing one specific expected algorithm will accept it), **weak HS256 secret brute-force** (tries a small built-in list of common/guessable secrets, including `your-256-bit-secret` — jwt.io's own documentation example, left unchanged by developers often enough to be worth a dedicated entry), and **`kid` header path traversal** (for verifiers that build a filesystem path from the token's own `kid` header to look up its signing key — a real, common multi-key/key-rotation pattern — pointing `kid` at a predictable zero-byte file like `/dev/null` and signing with an empty-bytes secret forges a valid signature if there's no containment check on the resulting path). Both checks compare the forged token's response against a genuine authenticated baseline *and* a genuine unauthenticated one — not just "got a 200" — and explicitly bail out with a clear message if the endpoint doesn't appear to differentiate by auth state at all (a real false-positive class found and fixed while building this: an endpoint that doesn't check the token in the first place would otherwise "fail" both checks trivially, since there's nothing to bypass).

**Stored XSS — a second, genuinely two-request check.** Every other XSS check in this file (including plain reflected detection) is single-request: send a payload, look at that same response. Stored XSS needs two — submit a payload once, then a COMPLETELY SEPARATE follow-up request that uses only the parameter's original value and never carries the payload at all. If a working `<script>` tag still comes back unescaped on that second, unrelated request, it proves the payload outlived the request that sent it — the actual defining property of stored (not reflected) XSS, and the difference between "this one crafted link is dangerous" and "every visitor to this page is compromised." Reported as its own finding, separate from any reflected-XSS hit the same parameter might also produce.

`--script PATH` runs your own pre-existing Python test script (no AI involved) and offers to persist any `HAKUZA_FINDING: {json}` line from its stdout as a real finding — the plug-in point for custom tests written for a specific engagement or live in an interview. `--ai-script "description"` has Claude draft a standalone test script for you; the **full script is always printed for review and is never executed without an explicit confirmation prompt** — no exceptions, since it would otherwise run arbitrary AI-authored code with the operator's own permissions.

Safety guardrails, actually enforced (not just documented): v1 is **GET-only** — the `--allow-state-changing` flag is accepted but is currently a documented no-op, reserved for a future version; every run is bounded by a running **request budget** (`--max-requests`, default 300) that stops the whole run with a clear summary rather than running away; every live request is rate-limited (`--delay`, default 0.15s); time-based payloads sleep a bounded 4 seconds, never something that piles up slow queries on a live target; no payload is ever destructive (no `DROP TABLE`, no `rm -rf`, no real file writes); and every target is checked against `hakuza scope` before it's touched, best-effort (an engagement with no scope defined is never blocked, matching `hakuza autopilot`'s existing behavior).

Requires `requests` (hard dependency, no graceful degradation — see Setup) and, optionally, `mod_active_ai.py` for AI escalation and PoC generation; without it the core diffing engine still runs fully and just skips those two pieces with a one-line notice.

## Architecture

`hakuza.py` is the ~10k-line core (engagement DB, AI client, most commands). `mod_recon_plus.py` is loaded as a real Python import (`import mod_recon_plus`) rather than text-inlined, and resolves shared symbols from the running process lazily via `importlib.import_module("hakuza")` — this is the pattern used for `wayback`/`secrets`/`fuzz`/`wizard`/`scope`/`config`.

`mod_ad_network.py`, `mod_ai_batch.py`, `mod_dashboard.py`, `mod_mobile_cloud.py`, and `mod_report.py` are merged directly into `hakuza.py` at build time via `assemble.py` (`python3 assemble.py`); they exist standalone here for reference/editing but the assembled `hakuza.py` is what actually runs. If you edit one of these and re-run `assemble.py`, sanity-check the result with `python3 -m py_compile hakuza.py` before trusting it — the merge step has previously introduced broken self-import remnants (fixed 2026-07-25, but watch for regressions on re-merge).

## Tool dependencies

Best with `subfinder`, `httpx`, `katana`, `waybackurls`, `nuclei`, `ffuf` on `$PATH` (`hakuza tools` checks what's installed). Missing tools degrade to AI-generated manual command suggestions rather than failing outright.
