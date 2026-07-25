# NEXUS — Unified Penetration Testing Platform

An AI-augmented CLI that runs the full lifecycle of a security engagement — recon, scanning, findings management, exploitation-chain reasoning, and reporting — from one tool, backed by a local SQLite engagement database and Anthropic's Claude for triage and analysis.

Built by Divith D Shetty — CEH · CRTP · CAISP · BFSI specialist.

## Why this exists

Most pentest tooling is single-purpose: a scanner, a notes app, a report template, an AI chat window, all disconnected. NEXUS keeps one engagement record (target, scope, findings, recon artifacts, AI analysis) and drives real tools — subfinder, httpx, katana, waybackurls, nuclei, ffuf — directly against it, so a finding discovered by `nexus scan` is the same finding `nexus report` writes up, with no copy-pasting between tools.

## The flagship feature: `nexus autopilot`

```bash
nexus init my-target --client "Acme Corp" --target https://acme.com --type web
nexus scope --add "https://acme.com/*"
nexus autopilot --profile full
```

One command, unattended: recon (subfinder/httpx/nmap) → wayback URL mining → secrets hunting → nuclei scan → AI triage → AI attack-chain reasoning → final report. Each phase is isolated — one tool failing doesn't kill the run — and a JSON run log with per-phase timing lands in the engagement directory when it's done. If scope is defined and you override the target, it refuses to run against anything outside it.

Without an `ANTHROPIC_API_KEY` set, the AI-dependent phases (analyze/chain/report) are skipped automatically rather than blocking on an interactive prompt — the recon/wayback/secrets/scan phases still run and persist real findings.

## Engagement lifecycle

| Command | Purpose |
|---|---|
| `nexus init` / `status` / `list` / `switch` | Create and manage engagements |
| `nexus recon` | subfinder + httpx + nmap, AI subdomain prediction fallback |
| `nexus wayback` | waybackurls + katana historical URL mining, categorized and secret-scanned |
| `nexus secrets` | JS file + exposed-path secret hunting |
| `nexus fuzz` | Smart ffuf wrapper — dirs/params/api/vhosts, tech-aware wordlist selection |
| `nexus scan` | nuclei scan, parsed and persisted as findings |
| `nexus autopilot` | All of the above, chained, unattended |
| `nexus import` | Import Nessus/Nuclei/Burp/CSV output |
| `nexus scope` | Add/check/list scope entries (glob-matched) |
| `nexus add` / `findings` / `update` | Manual findings CRUD |
| `nexus analyze` / `chain` / `advise` | AI triage, exploitation chains, attack-vector suggestions |
| `nexus report` | Markdown + HTML report with risk gauge and finding cards |
| `nexus ad` / `network` / `lateral` | Active Directory / internal network testing modules |
| `nexus mobile` / `ios` / `cloud` / `iot` | Mobile, cloud, and IoT testing modules |
| `nexus ai-audit` | LLM/AI system security audit (28 tests) |
| `nexus wizard` | Guided walkthrough for demos |
| `nexus dashboard` | Live terminal dashboard for the current engagement |

Run `nexus --help` or `nexus <command> --help` for full details — 40+ commands total.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # optional — AI phases degrade gracefully without it
python3 nexus.py init test --client "Test Co" --target scanme.nmap.org --type web
python3 nexus.py autopilot --profile quick
```

State lives in `~/.nexus/` (SQLite DB + per-engagement artifact directories), separate from this repo.

## Architecture

`nexus.py` is the ~10k-line core (engagement DB, AI client, most commands). `mod_recon_plus.py` is loaded as a real Python import (`import mod_recon_plus`) rather than text-inlined, and resolves shared symbols from the running process lazily via `importlib.import_module("nexus")` — this is the pattern used for `wayback`/`secrets`/`fuzz`/`wizard`/`scope`/`config`.

`mod_ad_network.py`, `mod_ai_batch.py`, `mod_dashboard.py`, `mod_mobile_cloud.py`, and `mod_report.py` are merged directly into `nexus.py` at build time via `assemble.py` (`python3 assemble.py`); they exist standalone here for reference/editing but the assembled `nexus.py` is what actually runs. If you edit one of these and re-run `assemble.py`, sanity-check the result with `python3 -m py_compile nexus.py` before trusting it — the merge step has previously introduced broken self-import remnants (fixed 2026-07-25, but watch for regressions on re-merge).

## Tool dependencies

Best with `subfinder`, `httpx`, `katana`, `waybackurls`, `nuclei`, `ffuf` on `$PATH` (`nexus tools` checks what's installed). Missing tools degrade to AI-generated manual command suggestions rather than failing outright.
