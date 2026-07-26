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
| `/go-filtered?redirect=` | `redirect` | A realistic naive filter — blocks a literal `http(s)://` prefix that doesn't match this app's own host, but never inspects a value that doesn't start with `http`, and compares the raw string prefix rather than the resolved host | Open Redirect (filter-bypass technique) — the plain payload is correctly blocked, but `//canary-host/x` (protocol-relative), `https://thishost@canary-host/x` (userinfo), and `/\canary-host/x` (backslash) all sail through |
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
| `/api/v1/pods` (also `/pods`, `/api/v1/namespaces`) | — | Real Kubernetes/kubelet API shape (`PodList`, real field structure), anonymous-auth left enabled — the actual bug this demonstrates, container/cluster *escape* itself needs to run from inside a container and isn't something this range (or `hakuza active`, remotely) can demonstrate | Exposed Kubernetes/Kubelet API — leaks pod env vars including fake `DB_PASSWORD`/`STRIPE_SECRET_KEY` |
| `/domxss` (fragment and `?name=`) | `location.hash`, `location.search` (`name`) — both client-side only | Two independent, zero-sanitization `.innerHTML` sinks in an inline `<script>` block; the served HTML is byte-identical no matter what the query string or fragment contain — the server-side handler never reads `qs` for its response at all | DOM-based XSS — the fragment vector (`#<img src=x onerror=alert(1)>`) never reaches this server in the first place, so it's the one bug on this entire range that only a real-browser check can find; see `/domxss-safe` below for the negative control |
| `/domxss-safe` (fragment and `?name=`) | — (intentionally not vulnerable) | Structurally identical to `/domxss` — same two sinks, same page shape — except both use `.textContent` instead of `.innerHTML`, inert by construction | Nothing should fire here — a negative control specifically so the DOM-XSS check's real-execution proof (not surface pattern-matching) gets exercised against a true negative, not just a true positive |
| `/fetch?url=` | `url` | Hands the parameter straight to `urllib.request.urlopen()` with zero scheme or host validation — a real, unmocked network fetch (`file://` reads real local files; an arbitrary `http://` host gets a real outbound request) | Server-Side Request Forgery — `file:///etc/passwd` for local file read, `http://169.254.169.254/latest/meta-data/` for the cloud-metadata-credential-theft variant (the two metadata hosts are canned in this handler since they aren't routable in this sandbox; point `/fetch` at its own address for a fully unmocked end-to-end demo) |
| `/fetch-safe?url=` | — (intentionally not vulnerable) | Same feature, same page shape, except the URL is checked against an http(s)-only scheme allow-list and a host denylist (metadata addresses, loopback, link-local) before ever reaching `urlopen` | Nothing should fire here — negative control for the SSRF check |
| `/xmlpreview?data=` | `data` | Parses the parameter with lxml's `XMLParser(resolve_entities=True)` — a real, unmocked external-entity resolution (needs `pip install lxml`; see "XXE, and the one dependency this range needed" below) | XXE — a DOCTYPE declaring an entity pointing at `file:///etc/passwd` gets resolved and the real content comes back in the response |
| `/xmlpreview-safe?data=` | — (intentionally not vulnerable) | Same feature, same page shape, except `resolve_entities=False` (lxml's own default) + `load_dtd=False` | Nothing should fire here — negative control for the XXE check |
| `/hppdemo?msg=` | `msg` | A real split-validation bug: the blocklist filter reads the FIRST occurrence of a duplicated `msg` parameter, the renderer reads the LAST — genuinely common in production frameworks where different code paths access duplicate params differently | HTTP Parameter Pollution — `?msg=hello&msg=<script>...</script>` (benign first, payload second) bypasses the filter |
| `/hppdemo-safe?msg=` | — (intentionally not vulnerable) | Same feature, same page shape, except both the filter and the renderer consistently use the same (first) occurrence | Nothing should fire here — negative control for the HPP check |
| `/dashboard` (also `/dashboard/*`, `/dashboard;*`) | path (routing, not a query param) | Greedy prefix routing serves the identical personalized page for `/dashboard`, `/dashboard/anything.css`, and `/dashboard;anything.css`, with `Cache-Control: public, max-age=3600` | Web Cache Deception — routing confusion + a cacheable response |
| `/dashboard-safe` | — (intentionally not vulnerable) | Exact-match routing only — `/dashboard-safe/anything.css` falls through to a real 404 | Nothing should fire here — negative control for the cache-deception check |

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

## Exposed Kubernetes API — the testable slice of "container escape"

"Container escape" got written off once as needing fundamentally different
tooling — genuinely true for the actual escape (breaking a running
container's namespace needs to run from inside it). But an exposed,
anonymous-auth-enabled kubelet or Kubernetes API server is a plain REST
API leaking real cluster data (or worse, offering command execution via
the kubelet's exec/run endpoints) to anyone who can reach it — that slice
is exactly as testable as any other HTTP endpoint, and it's a real,
well-known finding (CIS Kubernetes Benchmark 4.2.1).

`/api/v1/pods` here demonstrates the actual leaked-data shape a real
kubelet would return, with illustrative-but-fake secret values
(`DB_PASSWORD`, `STRIPE_SECRET_KEY`) so the stakes read as concrete rather
than abstract. One honest scoping note: a real kubelet API is HTTPS with a
self-signed certificate; reproducing that here would need either a
third-party crypto library or shelling out to `openssl` at startup, both
of which break this range's zero-dependency, single-file philosophy for a
detail that's orthogonal to the actual bug — anonymous-auth leaking this
exact response shape is the same vulnerability regardless of which
transport carries it, so the demo runs over plain HTTP on the main port.

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

## DOM-based XSS, and a real non-determinism bug it surfaced

```bash
hakuza active "http://127.0.0.1:9911/domxss?name=x" --no-ai
```

Requires Playwright + a headless Chromium (`pip install playwright &&
python3 -m playwright install chromium`) — every other check in this file
degrades gracefully without it, this one just skips with a one-line notice.

`/domxss` was verified as a genuine bug *manually* before ever trusting
`hakuza active`'s own detector against it: a standalone Playwright script
navigated to `/domxss#<img src=x onerror=alert('x')>` and
`/domxss?name=<img src=x onerror=alert('x')>` and confirmed a real `dialog`
event fired for both, then confirmed the negative control `/domxss-safe`
produces zero dialogs for the identical payloads on both vectors — only
after both directions were confirmed by hand was the built-in check trusted.

Building the query-parameter vector surfaced a real, genuinely non-obvious
bug in the check itself, not the test fixture: `_build_url()` correctly
preserves a URL's existing fragment when only the query string is being
mutated — every other check in this file relies on that. But re-testing a
URL whose fragment *already contains a payload* (exactly what you get by
copy-pasting the `url` field off a fragment-based DOM-XSS finding this same
check just persisted, to confirm it) meant every subsequent query-parameter
navigation for that target carried the OLD fragment payload along for the
ride as a second, fully independent live sink on the same page load. Two
`<img onerror=...>` elements both fire genuine, asynchronous image-load-
failure events, and Chromium does not guarantee they fire in DOM-insertion
order — confirmed directly: the very first end-to-end run against this
range showed the query-parameter finding's *own generated PoC* fail to
reproduce (`fired = ['hkzfrag', 'hkzdomcdf0c18125']` — the unrelated
fragment canary arrived first, not the canary the PoC was actually checking
for), a real, observed flake, not a hypothetical one. Fixed by explicitly
clearing the fragment (`parts._replace(fragment="")`) before building any
query-parameter test URL, so exactly one live payload exists per
navigation. Re-verified: the same PoC now reproduces deterministically
across 5 consecutive standalone runs.

## An independent adversarial audit, and 9 real bugs it found

After the DOM-XSS check landed, a separate, read-only subagent was set loose
on `mod_active.py` with one job: try to break every check that had been
built most recently, using the exact bug taxonomy this file already
documents (rich-markup escaping gaps, marker/signal collisions, confounds
from the test mechanism itself, generic PoCs that can't reproduce a
non-body-substring finding, false-positive gates that don't actually gate)
as its checklist. It found 9 real issues, none hypothetical, all
independently re-verified against this range before being fixed:

- **`--jwt` mode bypassed scope and had no rate limiting at all.** Unlike
  every other `hakuza active` mode, `--jwt` doesn't discover its own
  targets — and the scope-guard + budget/rate-limiting wiring that every
  other mode gets automatically had simply never been threaded into it.
  Fixed and re-verified directly against this range: `hakuza active
  "http://example.com/api/profile" --jwt <token>` (a target outside any
  reasonable engagement's scope) is now refused before a single request
  goes out; `/api/profile` in-scope still correctly finds both real bugs.
- **A raw-socket exception could crash the whole run.** `_raw_send_and_time`
  (the smuggling check's raw-socket helper) had `sendall()`/`settimeout()`
  sitting *outside* its own try/except, despite the docstring claiming
  "never raises" — a `ConnectionResetError` from a deliberately-malformed
  smuggling probe could have killed the entire `hakuza active` run,
  including every other finding already gathered. Fixed by moving both
  calls inside the guarded block.
- **Several categories' auto-generated Python PoC was structurally broken**
  — CORS/CRLF/open redirect need to send/inspect *headers*, not body
  content the generic template checks; time-based SQLi/cmdi prove
  themselves via elapsed time, not body text; GraphQL's `"Leaked types:
  ..."` evidence string is a label this code invented, never real server
  output. Three new dedicated generators (mirroring the existing
  race-condition/smuggling/DOM-XSS pattern) fixed all five; re-run against
  this range, every one of them now genuinely reproduces its finding
  standalone — confirmed by executing each generated script directly
  against a live `vulnerable_site.py` and checking for `[PASS]`.
- **Default-credential testing could false-positive off its own lockout.**
  `/admin/login`'s 8-pair credential list runs sequentially against the
  same username; a target that locks the account partway through and
  returns 200 with lockout wording (matching neither the existing
  denial-phrase nor failure-indicator patterns) would have been misread as
  "credentials accepted." Fixed by teaching the failure-indicator pattern
  to recognize lockout/rate-limit phrasing too.
- **The Kubernetes-API trigger regex was too broad, and its leak check too
  loose.** It originally matched a bare `/api/v1` prefix — any
  conventionally-versioned REST API, not just Kubernetes — and treated any
  response containing the substrings `"kind"` and `"items"` as a leak, both
  common key *names* in ordinary list APIs. Tightened to genuinely
  Kubernetes-specific paths/ports and a real JSON-shape check against a
  `PodList`/`NamespaceList`/etc. allow-list; `/pods` on this range still
  fires correctly, and the tightened regex no longer risks firing on an
  arbitrary `/api/v1/...` endpoint elsewhere in a real `--all` run.
- **The UNION-extraction marker filter was blunter than it needed to be.**
  It rejected any extracted value containing an apostrophe, pipe, paren, or
  plus *anywhere* — which would have false-negatived on real extracted data
  like an MSSQL `@@version` string full of parens, or a username like
  "O'Brien". Rewritten to check only the marker span's *boundary* (every
  vendor's concat syntax wraps the raw, unevaluated marker in a leading and
  trailing quote — the same adjacency idea already used elsewhere in this
  file), which is precise instead of blunt. Re-verified against `/product`:
  extraction of the SQLite version and table names still works unchanged.
- **JWT similarity thresholds could drift on ordinary dynamic content.**
  `_looks_authenticated`'s fixed 0.7/0.95 cutoffs diff whole response
  bodies — a timestamp, nonce, or regenerated session id sitting next to an
  otherwise-identical body could push a genuinely-unchanged comparison past
  either threshold. Fixed by stripping ISO timestamps and long hex/token
  spans before diffing; both JWT checks against this range still fire
  correctly with the added normalization.
- **The SSTI probe was a coincidence magnet.** A static `{{7*7}}` → "49"
  check had no ambiguity gate at all — any unrelated dynamic content
  containing "49" (a price, a view count) would satisfy it and go straight
  to critical. Switched to two random two-digit operands per run (a
  distinctive, hard-to-coincide-with product) and routed an ambiguous hit
  through the same AI-escalation CONFIRMED/LIKELY/manual-confirmation-lead
  pattern boolean-blind SQLi already uses. `--no-ai` runs against `/greet`
  now correctly downgrade to a "needs manual confirmation" medium instead
  of an unconditional critical; re-verified this is exactly what happens.
- **A confirmed NoSQLi finding silently skipped the stored-XSS check on the
  same parameter.** Step 9's `return` (instead of `break`) exited the
  entire per-parameter loop, so a parameter vulnerable to both NoSQLi and
  stored XSS would never get its step-10 check run at all. Changed to
  `break`.

Full regression after all nine fixes: every endpoint in this range re-run
end to end (`--depth deep`, both with and without `--no-ai`), plus `--jwt`
against `/api/profile` and `/api/kid-profile`, plus the negative controls
(`/domxss-safe`, an out-of-scope `--jwt` target) — all findings this range
is designed to produce still fire, zero new false positives, and every
rewired PoC script independently reproduces its finding when run standalone.

## SSRF, and the "make no mistakes" call on Oracle

Two more checks added in a later pass, after the adversarial-audit hardening
above. **SSRF** (`/fetch?url=`) was a genuine, previously-unflagged gap —
even the capability audit had missed it; `hakuza active` had zero real SSRF
coverage, only a static nuclei tag. Built two zero-ambiguity signals rather
than a differential/timing-based blind-SSRF lead (deliberately left out —
genuinely uncertain without an out-of-band callback this tool doesn't have):
`file://` scheme for local file read, and a cloud-metadata-shaped fetch for
real AWS/GCP instance-metadata content leakage. The two metadata hosts
(`169.254.169.254`, `metadata.google.internal`) aren't routable in this
sandbox, so `/fetch`'s handler special-cases them to return realistic canned
IMDS-shaped content directly — the same honest tradeoff already used for
`/api/v1/pods` above (mocking only the unreproducible environmental
prerequisite, while the vulnerability and detector code are both 100% real).
Point `/fetch` at its own address (`http://127.0.0.1:<port>/`) for a fully
unmocked demonstration with zero mocking involved at all.

**XXE** (`/xmlpreview?data=`) came with a real architectural question: fits
the engine's existing GET-only per-parameter loop cleanly (gated on the
parameter's *own baseline value* already looking like XML, no new POST
capability needed), but genuinely demonstrating it needs a parser that can
be misconfigured to resolve external entities — and Python's own stdlib XML
parsers (`ElementTree`, `minidom`, `sax`, all built on `expat`) structurally
cannot do this at all, confirmed directly before writing any code (the exact
payload that leaks real content under lxml's `resolve_entities=True` raises
`Entity 'x' not defined` under stdlib `ElementTree`, with no parser option
to change that). This range's whole design philosophy up to this point was
"zero third-party dependencies, stdlib only" — but that constraint was never
really about avoiding dependencies for their own sake, it was about not
reaching for a library to shortcut something otherwise buildable. Here, the
dependency isn't a shortcut, it's the only way this vulnerability class can
exist at all — so `lxml` is a genuine, one-time, honestly-documented
exception (optional import, `HAS_LXML`, same pattern as `HAS_PLAYWRIGHT`
elsewhere in this project — every other endpoint keeps working with zero
dependencies if it isn't installed).

Also considered and explicitly ruled out in the same pass: **Oracle SQLi
UNION-extraction syntax**, the last vendor the capability audit had flagged
as missing from `mod_active.py`'s `_SQLI_VENDOR_SYNTAX` dict (MySQL,
PostgreSQL, SQLite, and MSSQL are all implemented; Oracle error-based
*detection* already works via `_SQLI_ERROR_SIGNATURES`, only extraction was
missing). Investigated properly before deciding, not skipped reflexively:
Oracle requires a `FROM` clause on *every* `SELECT`, including the injected
half of a `UNION` — but the shared `_sqli_column_count`/`_sqli_visible_column`
probe functions build a bare `UNION SELECT {cols}` with no vendor branching
at all today, so adding Oracle isn't a one-line dict entry, it needs surgery
to code every other vendor's extraction already depends on. With no Oracle
instance reachable in this environment (no Docker; Oracle XE is a multi-GB
licensed install, not a lightweight pip/apt package like every other
supported vendor), there was no way to verify a change here live — and
shipping an unverified change to shared SQL-injection extraction code fails
this session's own "make no mistakes" brief. Left out, matching this file's
existing MSSQL precedent (`tables_query: None`, honestly "not implemented,"
rather than a guess presented as working).

## HTTP Parameter Pollution, and why the bypass needed both orderings

A real, OWASP-recognized class with zero prior coverage, and the cleanest
possible architectural fit of anything added so far: no new request
capability needed at all, since `_build_url` already builds a URL from a
plain list of `(key, value)` pairs and never deduplicated them — sending
the same parameter name twice was already representable, just never
exercised.

Gated to run only as a *fallback*: the new check fires immediately after
the existing plain single-value reflected-XSS probe, and only if that
probe did **not** already confirm the same signal directly. Sends the
target parameter twice in one request — once with a benign placeholder,
once with a working `<script>` payload — in both orderings (benign-then-
payload, payload-then-benign), because real backends genuinely disagree
about which occurrence of a duplicated parameter is authoritative (PHP's
`$_GET` uses the *last* occurrence by default; many WAFs and framework-
level validators only ever inspect the *first*). This isn't a new
detection signal — it reuses the exact same "genuinely executable,
unescaped payload present in the live response" certainty the plain
reflected-XSS check already established, just delivered a different way.

`/hppdemo?msg=` demonstrates a real, common split-validation pattern: the
blocklist filter reads `qs["msg"][0]` (the first occurrence), the
renderer reads `qs["msg"][-1]` (the last) — two different pieces of code
each reasonably picking *an* occurrence, just not the *same* one.
Confirmed directly via curl before trusting the live detector that only
**one** ordering (benign first, payload second) actually bypasses this
particular endpoint — `?msg=hello&msg=<script>...</script>` slips through
(filter checks "hello", passes; page renders the script tag), while
`?msg=<script>...</script>&msg=hello` is correctly still blocked (filter
checks the script tag first). That asymmetry is exactly why the check
tries both orderings rather than one: a single-ordering test would have
had roughly even odds of missing this exact, realistic bug shape
entirely.

Caught and fixed a real bug in the check's own first draft before it
ever ran live, not found in production: the success branch originally
used `return`, which would have silently skipped every later step (SQLi,
SSTI, path traversal, and everything else `_test_param` still needed to
try on that same parameter) — the identical bug class an earlier audit
round already caught once, in NoSQLi's own step 9 (`return` instead of
`break`). Fixed to `break` before compiling, let alone committing.

## Web Cache Deception, and a 95.2%-similarity near-miss caught before it shipped

The newest addition, and a genuinely different mechanism from every other
check on this range: not an injection, a URL-routing confusion bug (Omer
Gil's original research, plus the well-known path-parameter/trailing-
segment variants since). `/dashboard`'s routing greedily matches ANY path
starting with `/dashboard` — `/dashboard/fake.css`, `/dashboard;fake.css` —
and serves the identical personalized page regardless, with
`Cache-Control: public, max-age=3600`. Two things have to be true for this
to be genuinely exploitable, and the check verifies both rather than
either alone: the routing confusion itself (proven via response-similarity
against baseline), and a cache actually willing to store the deceptive
URL (proven via `Cache-Control`, not just assumed). An explicit
`no-store`/`private`/`max-age=0` is treated as a real, working safety
control and silently skipped — not reported at any severity — since
nearly every real cache respects an explicit directive like that;
`Cache-Control` absent or ambiguous is reported as an honest lead rather
than confirmed, since several real CDNs cache by file-extension heuristic
regardless of origin headers, a detail this tool can't see from outside.

Caught two real mistakes before either ever ran live, not found in
production. First, the detector's own first draft had a bare
`console.print(...)` call inside a function that only has `ctx.console`
in scope — a `NameError` waiting to happen the first time the "lead"
branch executed, caught on a second read-through before ever running it.
Second, and more interesting: the testlab demo's own first draft echoed
the requested path back into the page body (`<p>Requested path:
{path}</p>`) — meaning the baseline response for `/dashboard` and the
mutated response for `/dashboard/fake.css` were never quite identical.
Measured directly: **95.2%** similarity — technically still above the
detector's 0.95 threshold, but only by a hair, and a real risk of
false-negativing on the slightest additional real-world variance (a
timestamp, a request ID, anything else that might legitimately differ
per request). Fixed by removing the unnecessary echo entirely, so the
demo response is byte-for-byte identical regardless of path suffix —
which is also the more realistic shape for a genuine cache-deception
target in the first place (a page that's supposed to look effectively
static to a cache, not one that visibly varies per request).

## Extending this range

Each endpoint is a small, independent method on `Handler` in
`vulnerable_site.py` — add a new one following the same pattern (unsanitized
param → the bug → return HTML) to test additional detection classes as
`hakuza active` grows new probes (deserialization is not covered yet — no
detector for it in `mod_active.py` as of this writing, so there's nothing
to validate against it here either; XXE was closed in a later pass, see
above).
