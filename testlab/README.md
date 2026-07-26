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

This also starts a second, separate listener on `--port + 1` (9912 by default) — a hand-rolled raw-socket HTTP responder for the request-smuggling demo (see "HTTP request smuggling" below). It's not part of the main `Handler` class at all; smuggling needs byte-level control over request parsing that `http.server` would normalize away.

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

`/order/<uuid>` is a second IDOR endpoint, UUID-keyed instead of sequential — a UUID can't be brute-forced, so testing it exercises a different code path (`mod_active.py`'s real-sibling-ID cross-reference, not the numeric id-1/id+1000 offset logic). It needs the engagement's own recon data seeded with the other real order UUIDs first, simulating a prior `hakuza wayback` run having already discovered them:

```bash
python3 -c "
import hakuza
eng = hakuza.get_engagement('practice-range')
urls = '\n'.join([
    'http://127.0.0.1:9911/order/3f2504e0-4f89-4e63-9a0c-0305e82c3301',
    'http://127.0.0.1:9911/order/7c9e6679-7425-40de-944b-e07fc1f90ae7',
    'http://127.0.0.1:9911/order/f47ac10b-58cc-4372-a567-0e02b2c3d479',
])
hakuza.add_recon_data(eng['id'], 'wayback_urls', urls, 'wayback')
"
hakuza active "http://127.0.0.1:9911/order/3f2504e0-4f89-4e63-9a0c-0305e82c3301" --no-ai
```

Without that seeding step, `hakuza active` correctly refuses to guess a UUID and skips with a one-line explanation instead — that's the intended behavior, not a bug.

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
| `/user/<id>/profile` | path segment | No auth/session check of any kind — whichever numeric ID is in the path gets returned | IDOR heuristic (numeric offset path) |
| `/order/<uuid>` | path segment | Same bug, UUID-keyed instead of sequential | IDOR heuristic (real-sibling cross-reference path — see "Test it" above for the recon-data seeding step it needs) |
| `/api/account` | `Origin` header | The request's own `Origin` is reflected verbatim into `Access-Control-Allow-Origin`, paired with `Access-Control-Allow-Credentials: true` | CORS Misconfiguration |
| `/login?username=&password=` | `username`, `password` | Query string parsed with bracket notation (`username[$ne]=x` becomes a dict, not a string) and handed unsanitized to a naive "MongoDB-style" matcher | NoSQL Injection — both the per-parameter check (fires on `password` alone, since the baseline `username=admin` already matches for real) and the all-parameters check (the classic bypass: `/login?username[$ne]=x&password[$ne]=x` logs in as admin with no real credentials) |
| `/redeem?code=` | `code` (path/behavior, not injection) | Read-then-write with no lock around a single-use coupon (1 use available); a 50ms sleep between the availability check and the decrement stands in for the real DB round-trip that creates this exact window in production apps | Race Condition — fire 10 concurrent requests and all 10 redeem successfully instead of 1 |
| `/api/token` → `/api/profile` | `Authorization: Bearer` header | Real hand-rolled HS256 JWT issuer/verifier — trusts the token's own declared `alg` (accepts `none` with zero signature check) and verifies real HS256 signatures against a weak, guessable secret (`secret123`) | JWT — get a real token from `/api/token`, then `hakuza active .../api/profile --jwt <token>` finds both the alg=none bypass and the weak-secret HS256 forgery |
| `/comments?text=` | `text` | Every submitted comment is appended to a shared, unbounded list and every future page load renders the full history unescaped — a real GET-based guestbook, still a genuine pattern in the wild | Stored XSS — submit `<script>...</script>` once, then any later visit with a *different* `text` value still renders it |
| `/api/kid-token` → `/api/kid-profile` | `Authorization: Bearer` header | A second, separately-vulnerable JWT verifier — looks the signing key up per-token via the header's own `kid` field (a real key-rotation pattern) with a naive `os.path.join` and no containment check | JWT `kid` path traversal — `kid=../../../../dev/null` signed with an empty-bytes secret is accepted |
| `/graphql?query=` | `query` | A minimal hand-rolled GraphQL responder that answers the standard introspection query for any anonymous caller, no access check at all | GraphQL Introspection Enabled — leaks 7 real type names including `AdminMutation` and `ResetPassword` |
| `/admin/login?username=&password=` | `username`, `password` | A plain equality check against a literal, never-changed `admin`/`admin` pair — a separate endpoint from `/login`, which intentionally uses a strong password so it correctly does *not* trigger this check | Default Credentials — `admin`/`admin` accepted |
| `http://127.0.0.1:9912/` (separate port, raw sockets) | — | A hand-rolled, byte-level HTTP responder (not `http.server`) that trusts `Content-Length` even when `Transfer-Encoding` is also present, then genuinely blocks on a real `recv()` waiting for bytes that never arrive if the CL-bounded body isn't complete chunked framing | HTTP Request Smuggling (CL.TE) — a real ~5s hang, not a simulated delay |

## Fixed: the IDOR heuristic now catches same-template IDORs

Testing against `/user/<id>/profile` originally surfaced a real gap: the v1
heuristic only flagged a differently-numbered ID as a lead if the response's
whole-body `difflib` similarity to the baseline fell in a **0.3–0.85** band.
This practice range's two profile pages differ only in username/email/SSN
inside an otherwise identical template — **0.976** similarity, above the
band — so a completely real IDOR (confirmed directly via curl: `/user/1001/profile`
vs `/user/1000/profile` return two different real users, no auth check at
all) went undetected. That's arguably the *most common* real-world IDOR
shape (a well-built app's profile/order/invoice page, same template,
different data), so this mattered.

**Fixed in `mod_active.py::_idor_diff_signal`.** The upper similarity bound
is gone. Instead, every differing span between baseline and mutated response
(via `SequenceMatcher.get_opcodes()`) is checked in context: a span is
treated as noise (and excluded) if the ~40 characters immediately preceding
it in the *baseline* match a known noise-field label (`Session:`, `csrf`,
`Loaded at`, `timestamp`, etc.) or if the changed text itself looks like a
bare random token/hash — otherwise, if any real, non-trivial content differs
outside those cases, it's treated as a signal at *any* similarity level,
still gated by an explicit access-denied/login-wall phrase check (so a 200-OK
"please log in" page doesn't become a false positive once the upper bound is
gone) and a lower similarity floor of 0.3 (still excludes wildly different
error pages).

Re-verified against this exact range after the fix: `hakuza active
"http://127.0.0.1:9911/user/1001/profile?tab=1" --no-ai` now correctly
persists `Potential IDOR (heuristic) on path ID 1001`, citing `alice` as the
differing content (the swapped username), at similarity ratio 0.98. Also
unit-verified the new false-positive guards directly: a response that's
byte-identical, one that differs only by a session-ID/timestamp swap, and a
200-OK access-denied page are all correctly still excluded — plus a
realistic case where a real IDOR and simultaneous noise churn (session id
*and* timestamp both changing at the same time as the swapped username) are
both present, and the noise is correctly filtered out while the real signal
still fires.

## UNION-based extraction against `/product?cat=`, and a real bug it found

`hakuza active --depth deep` doesn't stop at confirming `/product?cat=` is
SQL-injectable — once error-based detection knows the exact vendor, it
determines column count, finds a visible/reflectable column, and extracts
real proof: SQLite version, current database, and (critically) the actual
table names in this database, including `users` — the same table the IDOR
endpoint's SSNs live in, reachable through a completely different bug.

Building and verifying this against `/product` surfaced a genuine bug in the
extraction logic itself, not the test fixture: `/product?cat=` reflects the
raw `cat` value unescaped elsewhere on the page (that's its XSS bug). The
extraction code's boundary marker (`HKZS...HKZE`) was appearing *twice* in
the response — once as part of the raw, unevaluated injected payload text
(the XSS reflection), and once as the genuinely evaluated UNION result. The
naive first-match search grabbed the raw occurrence, "extracting" the SQL
syntax itself instead of a real value. Fixed by filtering matches for
leftover SQL syntax (quotes, `||`, parens) — a real evaluated value never
contains those; the unevaluated echo always does. Documented in
`mod_active.py` directly since it's a general correctness property of the
extraction logic, not something specific to this range — any real target
that reflects its own SQL-injectable parameter elsewhere on the page (a
common combination: the same input point being both XSS- and SQLi-vulnerable)
would have hit the same bug.

Also worth knowing if you're extending `_product`'s error message: it's
deliberately phrased to say `sqlite3.OperationalError` rather than generic
"you have an error in your SQL syntax" wording, because the latter is
MySQL's classic fingerprint text — `hakuza active`'s vendor detection reads
the error phrasing to pick UNION-extraction syntax, and generic-sounding
error text will make it (correctly, by its own logic) guess the wrong
vendor for a backend that isn't actually MySQL.

## CORS and NoSQL injection, and a real false-positive class they surfaced

`/api/account` and `/login` were added to close two total gaps hakuza active
had no coverage for at all: CORS misconfiguration (per-target — `curl -H
"Origin: https://evil.example" http://127.0.0.1:9911/api/account` shows the
origin reflected straight back with credentials allowed) and NoSQL
injection (`/login?username[$ne]=x&password[$ne]=x` logs in as admin with
no real password — a real bracket-notation-to-object parsing bug, not a
simulation, implemented without a MongoDB dependency by reproducing the
exact parsing behavior that makes the bug possible).

Building the NoSQLi checks against this range surfaced a real false-positive
class: both checks work by renaming a parameter's key to bracket notation
(`cat` becomes `cat[$ne]`). Against `/product`, `/doc`, and `/go` — none of
which do bracket-notation parsing — that rename has an *unrelated* side
effect: the original key vanishes entirely, so `cat` reads back empty,
`file` reads back empty, etc. Losing a parameter can independently change a
page's output for reasons that have nothing to do with NoSQL operators, and
all three endpoints initially false-positived here purely from that. Fixed
by adding a control request — the parameter simply *removed*, not
bracket-renamed — before ever persisting a finding: if dropping the
parameter alone produces the same apparent effect as the operator payload,
the operator proved nothing, and the finding is correctly suppressed.
Re-verified across all 8 endpoints after the fix: 10/10 real vuln classes
confirm, zero false positives.

## HTTP request smuggling — a real hang, not a simulated delay

Getting this right required more care than most checks here: a naive demo
(just `time.sleep()` on certain requests) would validate nothing about
whether `hakuza active`'s timing detector actually works — it would pass
regardless of whether the detection logic was correct. The demo server on
port 9912 is a hand-rolled, byte-level HTTP responder (not `http.server`,
which would parse/normalize the request before the ambiguity was even
visible) that genuinely blocks on a real `socket.recv()` call waiting for
bytes that will never arrive, if a Content-Length-bounded request body
doesn't form complete, valid chunked framing — exactly the real-world
mechanism, reproduced faithfully rather than faked:

```bash
python3 -c "
import mod_active as m
elapsed, ok, timed_out = m._raw_send_and_time('127.0.0.1', 9912, b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n', 5, 5)
print('baseline:', elapsed)  # ~0.0004s
raw = m._SMUGGLE_CLTE_TEMPLATE.format(path='/', host='127.0.0.1').encode()
elapsed, ok, timed_out = m._raw_send_and_time('127.0.0.1', 9912, raw, 5, 10)
print('CL.TE probe:', elapsed)  # ~5.0s — a real block, not a sleep()
"
```

Also worth knowing: the generic single-request PoC generator
(`gen_python_poc`, a plain `requests.get()`) is meaningless for a
timing-based finding — the same problem race-condition findings hit
earlier. Caught it by actually reading the generated PoC before trusting
it (it checked for a literal descriptive string that would never appear in
any real response, meaning it would fail forever regardless of whether the
bug was real). Fixed with a dedicated PoC generator
(`_gen_smuggling_poc`) that resends the exact raw probe bytes over a real
socket and re-measures elapsed time — independently re-run and verified it
reproduces the same ~5s hang standalone.

Findings here are always reported as a LEAD needing manual confirmation,
never a confirmed vulnerability — this timing technique is most reliable
against a real front-end/back-end split (a CDN or reverse proxy in front
of an app server, how most real targets are deployed); a single
monolithic server's timing signal can be ambiguous even when, as here, the
demo is built to produce an unambiguous one.

## JWT testing, and a real false-positive class it surfaced

`--jwt` is the one check that needs a real token handed to it — `/api/token`
issues one, signed with the same weak secret `/api/profile` verifies against,
standing in for "copy a real session token out of your browser." Get one and
try both bypasses:

```bash
TOKEN=$(curl -s http://127.0.0.1:9911/api/token | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
hakuza active "http://127.0.0.1:9911/api/profile" --jwt "$TOKEN" --no-ai
```

Building this against `/api/account` (the CORS endpoint, which never checks
`Authorization` at all) surfaced a real false-positive class: without a
guard, both the alg=none and weak-secret checks "confirmed" a bypass against
it — because an endpoint that doesn't check the token in the first place
returns the same response with or without one, which trivially "passes" a
check for "does the forged token's response resemble the real one." Fixed by
comparing the REAL token's response against a genuinely unauthenticated
request (no `Authorization` header at all) up front: if those two already
look identical, the endpoint isn't gating on this token at all, and hakuza
active now says so explicitly and skips both checks rather than reporting a
bypass of nothing. Re-verified both directions: `/api/account` now correctly
skips with a clear explanation, `/api/profile` still correctly finds both
real bugs.

## Extending this range

Each endpoint is a small, independent method on `Handler` in
`vulnerable_site.py` — add a new one following the same pattern (unsanitized
param → the bug → return HTML) to test additional detection classes as
`hakuza active` grows new probes (XXE and deserialization are not covered
yet — neither has a detector in `mod_active.py` as of this writing, so
there's nothing to validate against them here either).
