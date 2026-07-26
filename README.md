# HAKUZA — Unified Penetration Testing Platform

An AI-augmented CLI that runs the full lifecycle of a security engagement — recon, scanning, findings management, exploitation-chain reasoning, and reporting — from one tool, backed by a local SQLite engagement database and Anthropic's Claude for triage and analysis.

Built by Divith D Shetty — CEH · CRTP · CAISP · BFSI specialist.

## Why this exists

Most pentest tooling is single-purpose: a scanner, a notes app, a report template, an AI chat window, all disconnected. HAKUZA keeps one engagement record (target, scope, findings, recon artifacts, AI analysis) and drives real tools — subfinder, httpx, katana, waybackurls, nuclei, ffuf — directly against it, so a finding discovered by `hakuza scan` is the same finding `hakuza report` writes up, with no copy-pasting between tools.

## Quickstart: `hakuza autopilot`

```bash
hakuza init my-target --client "Acme Corp" --target https://acme.com --type web
hakuza scope --add "https://acme.com/*"
hakuza autopilot --profile full
```

One command, unattended: recon (subfinder/httpx/nmap) → subdomain takeover scan → wayback URL mining → secrets hunting → nuclei vulnerability scan → AI triage → AI attack-chain reasoning → final report. Each phase is isolated — one tool failing doesn't kill the run. If scope is defined and you override the target, it refuses to run against anything outside it. Without an `ANTHROPIC_API_KEY` set, the AI-dependent phases are skipped automatically — recon/takeover/wayback/secrets/scan still run and persist real findings.

## Commands

| Command | Purpose |
|---|---|
| `hakuza init` / `status` / `list` / `switch` | Create and manage engagements |
| `hakuza recon` | subfinder + httpx + nmap, AI subdomain prediction fallback |
| `hakuza takeover` | Subdomain takeover scan across 15 services (S3, GitHub Pages, Heroku, Azure, Netlify, etc.) |
| `hakuza wayback` | waybackurls + katana historical URL mining, categorized and secret-scanned |
| `hakuza secrets` | JS file + exposed-path secret hunting |
| `hakuza fuzz` | Smart ffuf wrapper — dirs/params/api/vhosts, tech-aware wordlist selection |
| `hakuza scan` | nuclei scan, parsed and persisted as findings (`--profile vuln/quick/full/stealth`) |
| `hakuza autopilot` | Full pipeline, chained, unattended |
| `hakuza active` | **Live active testing** — a real differential HTTP engine, not template matching. See below. |
| `hakuza import` | Import Nessus/Nuclei/Burp/CSV output |
| `hakuza scope` | Add/check/list scope entries (glob-matched) |
| `hakuza analyze` / `chain` / `advise` | AI triage, exploitation chains, attack-vector suggestions |
| `hakuza deduplicate` / `enrich` / `prioritize` / `matrix` | AI-powered findings cleanup and remediation ordering |
| `hakuza report` | Markdown + HTML report with risk gauge and finding cards |
| `hakuza ad` / `network` / `lateral` | Active Directory / internal network testing modules |
| `hakuza mobile` / `ios` / `cloud` / `iot` | Mobile, cloud, and IoT testing modules |
| `hakuza ai-audit` | LLM/AI system security audit |
| `hakuza dashboard` / `serve` | Terminal dashboard / browser-based web dashboard |

Run `hakuza --help` or `hakuza <command> --help` for full details — 40+ commands total.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # optional — AI phases degrade gracefully without it
python3 hakuza.py init test --client "Test Co" --target scanme.nmap.org --type web
python3 hakuza.py autopilot --profile quick
```

State lives in `~/.hakuza/` (SQLite DB + per-engagement artifact directories), separate from this repo.

## `hakuza active` — live differential testing

Every other scanning path in HAKUZA is static template matching against known-bad signatures. `hakuza active` is the opposite: it sends live HTTP requests, builds a real statistical baseline per target, mutates parameters, and diffs the live response — reasoning about *this specific target's* actual behavior instead of pattern-matching. Confirmed findings auto-generate a standalone, independently-reproducible curl + Python PoC.

```bash
hakuza active "https://target.tld/listproducts.php?cat=1"
hakuza active --all --depth deep
hakuza active "https://target.tld/api/profile" --jwt eyJ...
```

**22+ vulnerability classes**, each with a real live-request signal (not a heuristic guess): reflected/stored/DOM-based XSS, HTTP Parameter Pollution, SQL injection (error/boolean/time-based) with UNION-based data extraction, SSTI, path traversal, open redirect (with 3 filter-bypass techniques), CRLF injection, SSRF (file:// + cloud metadata), XXE, IDOR, CORS misconfiguration (with a subdomain-prefix bypass), Web Cache Deception, NoSQL injection, race conditions, GraphQL introspection, default credentials, HTTP request smuggling, exposed Kubernetes/kubelet APIs, and JWT attacks (alg=none, weak secrets, `kid` path traversal).

Safety guardrails actually enforced: GET-only in v1, a hard request budget, rate limiting, bounded time-based payloads, no destructive payloads ever, and scope checking before every request.

**→ [Full technical writeup of every check, its methodology, and the real bugs found while building it](docs/ACTIVE_ENGINE.md)**

**→ [`testlab/`](testlab/) is a matching vulnerable practice range** — one endpoint per vulnerability class above, plus negative controls, so every check here can be verified hands-on against a target you own.

**→ [Every bug found and fixed while building this, chronologically](docs/BUGS_FOUND_AND_FIXED.md)**

## Web dashboard (`hakuza serve`)

```bash
hakuza serve                 # http://127.0.0.1:7373, opens a browser tab
```

A dark-themed Flask dashboard (`webapp/`) rendering the same engagement DB the CLI uses — engagement cards, per-engagement risk gauge and findings table, click-through finding detail. Read-only against the database, binds to `127.0.0.1` only. Covered by a real-browser Playwright end-to-end test suite (`webapp/tests/`) that proves the stored-XSS fix holds against actual DOM/JS execution, not just text-matching — see [`webapp/tests/`](webapp/tests/) for details.

## Architecture

`hakuza.py` is the ~10k-line core (engagement DB, AI client, most commands). `mod_recon_plus.py`, `mod_active.py`, and `mod_active_ai.py` are real Python imports; several other `mod_*.py` files are merged into `hakuza.py` at build time via `assemble.py`.

## Tool dependencies

Best with `subfinder`, `httpx`, `katana`, `waybackurls`, `nuclei`, `ffuf` on `$PATH` (`hakuza tools` checks what's installed). Missing tools degrade to AI-generated manual command suggestions rather than failing outright.
