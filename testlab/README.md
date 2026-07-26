# HAKUZA Practice Range

A small, deliberately vulnerable web app for safely validating `hakuza active`
against a target you own — no third-party dependencies, stdlib only.

**Localhost-only. Do not expose this to any network. Do not run it anywhere
but your own machine.** Every endpoint is a real, working vulnerability (real
SQL injection against a real SQLite backend, real `eval()`-based SSTI, real
unsanitized path traversal, etc.) — this is not a simulation that prints fake
results, it is genuinely exploitable, on purpose, against fake in-memory data.

## Run it

```bash
python3 testlab/vulnerable_site.py            # http://127.0.0.1:9911
python3 testlab/vulnerable_site.py --port 8080
```

## Test it

```bash
hakuza init practice-range --client "Practice" --target http://127.0.0.1:9911 --type web
hakuza active "http://127.0.0.1:9911/product?cat=1" --depth deep --no-ai
hakuza active "http://127.0.0.1:9911/greet?name=guest" --no-ai
hakuza active "http://127.0.0.1:9911/doc?file=welcome.txt" --no-ai
hakuza active "http://127.0.0.1:9911/go?redirect=/product" --no-ai
hakuza active "http://127.0.0.1:9911/echo?msg=hello" --no-ai
hakuza active "http://127.0.0.1:9911/user/1001/profile?tab=1" --no-ai
hakuza findings          # everything hakuza active confirmed
```

Drop `--no-ai` if you have `ANTHROPIC_API_KEY` set and want to see the AI
escalation path exercised too (it mainly matters for the boolean-blind SQLi
and IDOR heuristic paths, where the signal is ambiguous enough to ask for a
second opinion).

## What's vulnerable where

| Endpoint | Vulnerable param | Bug | What `hakuza active` should confirm |
|---|---|---|---|
| `/product?cat=` | `cat` | Real string-concatenated SQL query against SQLite (error-based, boolean-blind, and time-based via a registered `sleep()` SQL function) + the value is reflected into HTML unescaped | Reflected XSS, SQL Injection (error/boolean/time-based — which one fires first depends on exact SQLite parsing of the payload, that's expected, real-world variance) |
| `/greet?name=` | `name` | User input is spliced into a template *string* before a `{{ expr }}`-style block is `eval()`'d — the same class of bug that causes real Jinja2/Twig SSTI when a developer accidentally renders user input as template source instead of template data | Server-Side Template Injection (`{{7*7}}` → `49`), and also Reflected XSS since the raw value lands in HTML too |
| `/doc?file=` | `file` | Filename is joined onto a base directory with `os.path.join()` and no canonical-path containment check | Path Traversal / LFI (`../../../../etc/passwd`) |
| `/go?redirect=` | `redirect` | `Location` header is set directly from the parameter, no allow-list | Open Redirect |
| `/echo?msg=` | `msg` | Value is placed into a custom response header with no CR/LF stripping — `http.server`'s `send_header()` does not validate embedded control characters | CRLF / HTTP Header Injection |
| `/user/<id>/profile` | path segment | No auth/session check of any kind — whichever numeric ID is in the path gets returned | Intended for the IDOR heuristic — **see note below, it currently does NOT fire here** |

## Known gap this range surfaced: the IDOR heuristic misses same-template IDORs

Testing against `/user/<id>/profile` was genuinely useful: the heuristic
(`mod_active.py::_test_idor_heuristic`) only flags a differently-numbered ID
as a lead if the response's `difflib` similarity to the baseline falls in the
**0.3–0.85** band — "meaningfully different, but still a real 200 OK page,"
distinguishing a real second record from an error/not-found page. This
practice range's two profile pages differ only in username/email/SSN inside
an otherwise identical template, which measures at **0.976** similarity —
*above* the band, so it's correctly excluded by the current logic even though
it's a completely real IDOR (confirmed directly: `curl
127.0.0.1:9911/user/1001/profile` vs `.../user/1000/profile` returns two
different real users, no auth check at all).

This is arguably the *most common* real-world IDOR shape (a well-built app's
profile/order/invoice page — same template, different data), so the
heuristic's current band under-covers it. Not fixed yet — flagging it here so
it isn't lost. A reasonable fix: also flag when the response is *highly*
similar in structure but differs in specific token positions that match the
injected ID or adjacent-looking data (e.g., diff on `difflib.unified_diff`
line-by-line rather than whole-body ratio, or specifically check whether the
requested ID variant's value literally appears in the new response body while
the original ID's value does not) — worth a follow-up pass on
`mod_active.py` if IDOR coverage matters for real engagements.

## Extending this range

Each endpoint is a small, independent method on `Handler` in
`vulnerable_site.py` — add a new one following the same pattern (unsanitized
param → the bug → return HTML) to test additional detection classes as
`hakuza active` grows new probes (NoSQLi, XXE, and deserialization are not
covered yet — none of them have a detector in `mod_active.py` as of this
writing, so there's nothing to validate against them here either).
