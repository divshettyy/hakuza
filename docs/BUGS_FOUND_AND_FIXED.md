# Bugs found and fixed — running log

A chronological, scannable record of every real bug found while building HAKUZA (and
the secondary `pentest-ai-assistant` project), across every session. This is a living
document — updated as new bugs are found, not a one-time snapshot. For the full prose
narrative behind any `hakuza active`/testlab entry, see
[`docs/ACTIVE_ENGINE.md`](ACTIVE_ENGINE.md) and [`docs/TESTLAB_NOTES.md`](TESTLAB_NOTES.md).

Format: **Bug** — root cause → fix → how it was verified.

## Initial repair (rename + broken assemble.py output)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 1 | `hakuza.py` had a fatal `SyntaxError` and couldn't run at all, despite an earlier session's fixes supposedly being in place | Root cause: re-running `assemble.py` (the mod_*.py → hakuza.py merge step) regressed previously-applied fixes by leaving broken self-import remnants. Repaired 7 dead self-import remnants + duplicate shadowed functions (`_require_engagement`, `print_banner`, a ~330-line dead `cmd_report` pair) + 4 raw-string bugs from Windows-path escape sequences | `py_compile` + full `--help` sweep |
| 2 | `mod_recon_plus.py` (wayback/secrets/fuzz/wizard/scope/config) existed as complete working source but had never actually been merged into the shipped CLI | Wired in via a real `import mod_recon_plus`, not text-inlining | Full `--help` sweep, live smoke test |
| 3 | Scope-matching wildcards broken | Fixed matching logic | — |
| 4 | Rich `MarkupError` crashes masking a real typo | Fixed the typo and the missing escaping | — |
| 5 | `scan --target` silently a no-op | Flag was documented and read by code but never registered with argparse | — |
| 6 | `ad`/`network`/`lateral` blocked on an interactive API-key prompt when run non-interactively | Fixed prompt handling | — |
| 7 | `init --type` argparse drift | Fixed | — |
| 8 | HTML report crashed with `NameError: math not defined` | Added missing import | — |
| 9 | Findings-export wrote to CWD instead of the engagement directory | Fixed path resolution | — |
| 10 | **Real stored-XSS** in the HTML report — finding title/description/impact/remediation and engagement client/target/tester interpolated into HTML with no/incomplete escaping; markdown body fed through `markdown2` without `safe_mode` (passes raw embedded HTML through by design) | Fixed with `html.escape()` everywhere + `safe_mode="escape"` | Adversarial: payloads in client name, target, and every finding field — confirmed zero live script tags survive |
| 11 | `hakuza update --note` crashed (`no such column: notes`) | Added schema column + idempotent migration | — |
| 12 | `requirements.txt` missing `markdown2`, imported unconditionally at module scope — whole tool failed to start, not just `--html` | Added to requirements.txt | Fresh venv install |

## Second deep-audit pass (subagent fan-out)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 13 | `_parse_json_from_response` mis-parsed AI object responses as their inner array — `prioritize`/`matrix` could **never** render a real AI result regardless of API key | Now picks whichever of `{`/`[` appears first as the true container | — |
| 14 | `MarkupError` crashes in all 4 AI-batch commands from unescaped finding titles hitting Rich **tables** (`Table.add_row()` parses markup too — same bug class as `console.print`, different widget) | Escaped table cell content | — |
| 15 | `mobile`/`ios`/`cloud`/`iot` crashed on EOF at a shared confirmation prompt when run non-interactively | Fixed prompt handling | — |
| 16 | `recon --target`/`--deep` and `import --source` documented and read by code, never wired to argparse (same class as bug #5) | Registered the flags | — |
| 17 | ~9 call sites read engagement target/client/scope via keys (`target_url`, `client_name`, `scope_notes`) that don't exist in the schema — AI prompts for `analyze`/`advise`/`chain`/`threat`/`chat` silently injected "Target: N/A" with no error | Fixed key names to match real schema | — |
| 18 | The wizard (the tool's own demo walkthrough) crashed on its final step | Fixed | — |

## Third pass (`hakuza takeover`, CI/CD, `hakuza serve`)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 19 | **Takeover false-positive trap**: the S3 check matched any CNAME merely containing the substring "s3" and probed a synthetic bucket URL that returns `NoSuchBucket` for almost any subdomain — auto-persisting false CRITICAL findings for ordinary subdomains with zero confirmation step | Fixed matching + added a real confirmation step | Independently re-verified by reproducing the false-positive trap directly, not just trusting the audit report |
| 20 | `webapp/app.py` reused `hakuza.py`'s process-wide singleton SQLite connection; Werkzeug's dev server dispatches requests on different threads even with debug off, and `sqlite3` forbids cross-thread reuse — any request on a different thread than whichever created the cached connection 500'd | Fixed with `threaded=False` in both server entry points | Reproduced with two ordinary back-to-back page loads, no attack needed |

## Fourth pass (`--profile vuln`)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 21 | `--profile stealth` was a documented CLI option that silently did nothing different from `quick` (missing dict entries + hardcoded concurrency, no rate limit) | Made it genuinely throttled | — |

## Fifth pass (Playwright E2E suite)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 22 | `playwright install --with-deps` needs sudo (unavailable non-interactively) — Chromium downloaded but wouldn't launch (`libnspr4.so: cannot open shared object file`) | Manually downloaded `.deb` packages, extracted with `dpkg -x` (no root) into `~/.local/lib/playwright-deps/`, iterated via `ldd` for each missing library (8 packages, one manual symlink `libasound.so.2 -> libasound.so.2.0.0`); export `LD_LIBRARY_PATH` before launching Chromium | Full 8-test suite passed, reproduced twice |

## Sixth/seventh pass (`hakuza active` + `testlab/` built)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 23 | First throwaway test-fixture had a `redirect` param that always short-circuited regardless of other params | Diagnosed as the test fixture's own fault via direct curl, not a tool bug | Direct curl before trusting the live detector |
| 24 | **IDOR heuristic gap**: only flagged a differently-numbered-ID response as a lead if `difflib` similarity fell in a 0.3–0.85 band — testlab's two profile pages (same template, only username/email/SSN differ) measured 0.976, above the band, so a completely real IDOR went undetected. Arguably the *most common* real-world IDOR shape | See pass 8 below | — |

## Eighth pass (IDOR heuristic fix)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 25 | (continuation of #24) `_idor_diff_signal`'s upper similarity bound excluded same-template swapped-data IDORs entirely | Removed the upper bound; every differing span now judged by BASELINE context immediately preceding it (noise-field labels excluded), not the diffed text's own content | Caught an issue in the *first draft of this very fix* — a diffed fragment like "xyz999" doesn't self-identify as noise once separated from its label, only surrounding context does — fixed before shipping; 5 synthetic cases + full 7-endpoint regression |

## Ninth pass (UNION extraction, IDOR UUID, CORS, NoSQLi, race conditions, JWT)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 26 | **SQLi UNION marker collision**: a target both SQLi- and XSS-vulnerable on the same param (testlab's `/product`) caused the extraction marker to match the raw unevaluated reflected payload before the genuinely evaluated result | Filtered marker matches for leftover SQL syntax | Re-verified against `/product` |
| 27 | `--all` mode filtered out URLs with no query string before baseline capture — per-target param-less checks (CORS, IDOR) could never fire in `--all` mode | Fixed baseline capture to not require query params | — |
| 28 | **NoSQLi false positive**: both checks rename a param key to bracket notation, which for non-bracket-parsing endpoints (`/product`, `/doc`, `/go`) makes the original key vanish — an unrelated side effect that independently changes output | Added a control request (parameter simply removed, not bracket-renamed) before ever persisting | Re-verified across 8 endpoints: 10/10 real vuln classes, zero false positives |
| 29 | **NoSQLi missed detection**: the real bypass's short "denied"→"success" text swap didn't clear a length-diff threshold borrowed from SQLi | Added a targeted semantic failure-phrase signal | — |

## Tenth pass (DOM-XSS + first parallel-subagent fan-out)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 30 | **DOM-XSS non-determinism**: `_build_url()` correctly preserves an existing URL fragment when mutating only the query string, but if the fragment ALREADY carries a payload (copy-pasted from an earlier fragment-based finding), that payload rides along into every query-param navigation too — two independent `<img onerror>` elements fire two genuinely async events with no guaranteed order, so canary-matching became non-deterministic | Explicitly clear the fragment before building any query-param test URL | First observed directly as a failing PoC re-run (`fired = ['hkzfrag', 'hkzdomcdf0c18125']`, wrong canary first), not hypothetically; re-verified deterministic across 5 consecutive runs |

## Independent adversarial audit — 9 bugs (fanned-out read-only subagent)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 31 | `--jwt` mode bypassed the scope guard entirely and had zero budget/rate-limiting | Threaded in the same scope-guard + budget/delay wiring every other mode gets | Out-of-scope `--jwt` target now refused pre-flight; in-scope target still finds both real bugs |
| 32 | Smuggling's `_raw_send_and_time` had `sendall()`/`settimeout()` outside its own try/except despite a "never raises" docstring — a `ConnectionResetError` could crash the whole run | Moved both calls inside the guarded block | — |
| 33 | Several categories' auto-generated PoC was structurally broken regardless of whether the bug was live: CORS/CRLF/open-redirect need header checks a body-substring template can't do; time-based SQLi/cmdi prove themselves via elapsed time, not body text; GraphQL's evidence string was an invented label, never real output | Built 3 new dedicated PoC generators + a `verify=False` passthrough for K8s | Every one independently re-verified to reproduce standalone |
| 34 | Default-credential testing could misread a target's own account lockout as "credentials accepted" | Taught the failure-indicator pattern to recognize lockout/rate-limit phrasing | — |
| 35 | K8s trigger regex matched any versioned REST API, not just Kubernetes; leak check was a loose substring match | Tightened both to genuinely K8s-specific paths + real JSON-shape check | `/pods` still fires; no longer risks firing on arbitrary `/api/v1/...` |
| 36 | UNION-extraction marker filter rejected any extracted value containing common punctuation *anywhere*, false-negativing on real data (MSSQL version strings, names like "O'Brien") | Rewritten to check only the marker's boundary | Re-verified: SQLite version/table extraction unchanged |
| 37 | JWT's similarity-based bypass detection could drift on ordinary dynamic content (timestamps, nonces) | Strip dynamic spans before diffing | Both JWT checks still fire correctly with normalization added |
| 38 | SSTI probe (`{{7*7}}` → "49") had zero ambiguity gate — any unrelated content containing "49" would satisfy it | Random operands + AI-escalation CONFIRMED/LIKELY pattern | — |
| 39 | Confirmed NoSQLi finding silently skipped the same parameter's stored-XSS check (`return` instead of `break`) | Changed to `break` | — |

## Eleventh pass (SSRF + XXE)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 40 | (Self-audit, before shipping) SSRF's cloud-metadata-leak signal had no baseline comparison — a real page (cloud dashboard, DevOps blog) could legitimately already contain terms like "instance-id" | Required the match be genuinely new relative to baseline | Constructed adversarial case (fake baseline already mentioning "instance-id") confirmed no false positive; real positive case unaffected |

## Twelfth pass (HTTP Parameter Pollution)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 41 | (Caught before running) HPP check's success branch used `return` instead of `break` — would have silently skipped every later step (SQLi, SSTI, path traversal, ...) for that parameter, the same bug class as #39 | Fixed to `break` before compiling | — |

## Thirteenth pass (Web Cache Deception)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 42 | (Caught before running) Bare `console.print(...)` call inside a function with no local `console` alias in scope — `NameError` waiting to happen the first time the "lead" branch executed | Changed to `ctx.console.print(...)` | — |
| 43 | (Caught before running) testlab's `/dashboard` demo echoed the requested path into the page body — baseline vs. mutated responses measured only 95.2% similar, uncomfortably close to the detector's own 0.95 threshold, real false-negative risk | Removed the unnecessary echo; response now byte-for-byte identical regardless of path suffix | Re-measured after the fix |

## Fourteenth pass (depth extensions: redirect/CORS bypass)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 44 | (Caught before running) CORS subdomain-prefix bypass payload hardcoded `https://` regardless of the target's actual scheme — would have silently never matched any plain-HTTP target, including testlab itself | Derived the scheme from the target URL | — |
| 45 | (Found via full whole-session regression, not a synthetic test) Web Cache Deception fired a false "lead" against the project's own raw-socket smuggling demo, which returns identical `text/plain` content for any path — exposed a real scoping gap: the same signal would fire on any real target's JSON API or a legitimate SPA's client-side-routed shell | Gated the check on the baseline response's `Content-Type` actually containing `html` | False lead against the smuggling demo confirmed gone; `/dashboard` still confirms; JSON endpoints unaffected |

## Cleanup pass (stale test artifacts)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 46 | Two stale self-test engagements (`domxss-selftest`, `hakuza-active-selftest`) left in `~/.hakuza/` from earlier verification work, never cleaned up | Removed from DB and disk | Confirmed empty `~/.hakuza/engagements/` |

## `pentest-ai-assistant` (secondary project)

| # | Bug | Fix | Verified |
|---|---|---|---|
| 47 | Flask dashboard's downloadable report had a real stored-XSS — finding fields from an unvalidated file upload, and client/tester from an unvalidated form POST, interpolated into HTML with zero escaping | `html.escape()` everywhere | Uploaded `<script>` payloads through the actual running server, confirmed zero live script tags in the downloaded report |
| 48 | Flask `debug=True` default in both `run.py` and a duplicate entry point in `app.py` — a Werkzeug debugger RCE vector | Disabled by default, opt-in via `PENTEST_AI_DEBUG=1` | — |
| 49 | `requirements.txt` missing `flask` and `requests` | Added | Fresh venv install |
| 50 | `cvss` command's math was an AI guess, not deterministic | Made it genuinely deterministic CVSS v3.1 vector math | — |
| 51 | The same HTML-escaping bug class as #47 found a third time, in `pentest_ai.py`'s own `generate_html()` | `html.escape()` | — |

## Declined (investigated, deliberately not built — not bugs, but worth tracking why)

| Item | Reason |
|---|---|
| Oracle SQLi UNION extraction | Requires a `FROM` clause on every SELECT including the injected UNION half — the shared column-count/visible-column probes don't support any vendor's `FROM` requirement today, real surgery not a dict entry. No Oracle instance available anywhere to verify a fix live. |
| GraphQL→SQLi pivot | Would need hand-rolling real GraphQL query parsing — meaningfully more novel/fragile surface area than anything else in the engine. |
| Deserialization (pickle, etc.) | No reliable way yet to auto-identify a serialized-blob parameter without a false-positive-prone guess. |
| JWT `alg` case-variant bypass (`None`/`NONE`) | Tests a narrow, library-specific historical quirk — a "realistic" demo would mean writing a verifier with that exact flaw and testing against it, a much weaker validation loop than everything else built. |
