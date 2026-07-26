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

## Architecture

`hakuza.py` is the ~10k-line core (engagement DB, AI client, most commands). `mod_recon_plus.py` is loaded as a real Python import (`import mod_recon_plus`) rather than text-inlined, and resolves shared symbols from the running process lazily via `importlib.import_module("hakuza")` — this is the pattern used for `wayback`/`secrets`/`fuzz`/`wizard`/`scope`/`config`.

`mod_ad_network.py`, `mod_ai_batch.py`, `mod_dashboard.py`, `mod_mobile_cloud.py`, and `mod_report.py` are merged directly into `hakuza.py` at build time via `assemble.py` (`python3 assemble.py`); they exist standalone here for reference/editing but the assembled `hakuza.py` is what actually runs. If you edit one of these and re-run `assemble.py`, sanity-check the result with `python3 -m py_compile hakuza.py` before trusting it — the merge step has previously introduced broken self-import remnants (fixed 2026-07-25, but watch for regressions on re-merge).

## Tool dependencies

Best with `subfinder`, `httpx`, `katana`, `waybackurls`, `nuclei`, `ffuf` on `$PATH` (`hakuza tools` checks what's installed). Missing tools degrade to AI-generated manual command suggestions rather than failing outright.
