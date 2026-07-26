# `hakuza active` — full technical reference

This is the comprehensive, implementation-level writeup of `hakuza active`'s detection
methodology: exactly what each check does, why it's built the way it is, and the real
bugs found and fixed while building each one. The main [README](../README.md) covers
this in a few sentences for anyone skimming the project; this document is for anyone who
wants the full detail — a deep interview conversation, a code reviewer, or future-me.

For hands-on verification of every check listed here, see
[`testlab/README.md`](../testlab/README.md) — a matching vulnerable practice range with
one endpoint per class described below, plus a negative control for most of them.

## Why this exists

Every other scanning path in HAKUZA — `hakuza scan` (nuclei) — is STATIC template
matching: a known request/response signature compared against a fixed library of
known-bad patterns. `hakuza active` (`mod_active.py`) is the opposite approach: a real
ACTIVE, adaptive differential-testing engine that sends live HTTP requests and reasons
about *this specific target's* actual behavior instead of pattern-matching against a
static template library.

```bash
hakuza active "https://target.tld/listproducts.php?cat=1"        # single URL
hakuza active --all --depth deep                                  # every query-param URL from `hakuza wayback` recon data
hakuza active "https://target.tld/page.php?id=1" --no-ai --max-requests 50
```

## How it works

For each candidate URL it (1) sends the SAME real GET request 3 times to build a
statistical baseline — status code, body length, sha256 hash, and response timing (mean
+ population stdev) — then (2) mutates one query parameter at a time with a small set of
non-destructive probes and diffs the live mutated response against that real baseline
(status/length/hash/`difflib` similarity ratio/timing), then (3) for ambiguous signals,
optionally escalates to Claude for a human-pentester-style judgment call, and (4) for
every CONFIRMED result, auto-generates a standalone, reproducible **curl command + Python
PoC script** so the finding can be independently re-run — not just trusted on a
scanner's say-so.

Most categories use one generic PoC template (a single request, checking the expected
signal against the response body); several categories whose evidence genuinely isn't a
body substring get a dedicated generator instead — race conditions (a real concurrent
burst), HTTP smuggling and DOM-XSS (below), CORS/CRLF/open redirect (header-based:
send/inspect specific request/response headers, not body), time-based SQLi/command
injection (elapsed-time based, not body), and GraphQL introspection (a real JSON-shape
check, not an invented text label) — each independently verified to actually reproduce
its finding when run standalone against a live target, not just assumed to work because
the live check found it.

## Vuln classes covered

**Reflected XSS.** Unescaped-reflection + working-payload confirmation, vs.
encoded-but-inert reflection reported only as informational, plus an HTTP Parameter
Pollution bypass fallback — sending the same parameter name twice, once benign and once
a working payload, in both orderings, since real backends disagree about which
occurrence of a duplicated parameter is authoritative. Only runs when the plain
single-value probe didn't already confirm the same signal directly.

**SQL injection.** Error-based via vendor error signatures, boolean-based blind via
three-way response-similarity comparison, and — `--depth deep` only — time-based blind
with a *statistical* timing gate: `baseline_mean + max(3×stdev, 2.5s)`, not a fixed
">4 seconds" rule, to avoid false positives on naturally slow targets.

**Beyond detection — UNION-based SQLi data extraction (`--depth deep`).** Once
error-based SQLi is confirmed *and* the exact DB vendor is known from the error
signature (MySQL, PostgreSQL, SQLite, or MSSQL), `hakuza active` automatically
determines the injectable query's column count (`ORDER BY` binary probe), finds a
column position that reflects string data into the response, and extracts real proof:
DB version, current database, current user, and (MySQL/PostgreSQL/SQLite) up to 5 real
table names — all via read-only `UNION SELECT`, nothing ever written. This turns "this
parameter is injectable" into "here is the actual data it leaked." Every extraction
query uses a boundary marker filtered for leftover SQL syntax, specifically so it isn't
fooled by a target that *also* reflects the raw payload elsewhere on the same page (a
real failure mode found and fixed while building this against testlab's own `/product`
endpoint, which has exactly that combination). That filter checks only the marker
span's boundary (every vendor's concat syntax wraps the raw, unevaluated text in a
leading/trailing quote) rather than rejecting any candidate containing a
quote/pipe/paren/plus *anywhere* — the earlier, blunter version of this filter
false-negatived on legitimately-extracted data containing that punctuation, e.g. an
MSSQL `@@version` string full of parens, or a username like "O'Brien". Oracle
extraction syntax was investigated and explicitly not implemented — see
[Explicitly declined](#explicitly-declined) below.

**OS command injection.** Time-based, `--depth deep` only, on shell-shaped parameter
names.

**SSTI.** `{{a*b}}` with two random two-digit operands per run rather than a fixed
`{{7*7}}`, so the expected result is a distinctive number unlikely to already be on the
page by coincidence — a short, common literal like "49" can trivially appear from
unrelated dynamic content. An ambiguous single hit is routed through the same
AI-escalation CONFIRMED/LIKELY/manual-confirmation-lead pattern used for boolean-blind
SQLi rather than reported as an unconditional critical (Jinja2/Twig family only in v1).

**Path traversal / LFI.** `/etc/passwd` signature match, on file/path-shaped parameter
names.

**Open redirect.** Canary Location-header check, on redirect-shaped parameter names.
Beyond a plain absolute-URL payload, also tries 3 real filter-bypass techniques:
protocol-relative (`//host`), userinfo-embedded (`https://trusted@host`), and a
leading-backslash variant — resolving each Location header's real target host the way a
browser would (parsed netloc, backslash-normalized, userinfo stripped) rather than
trusting a literal string match.

**CRLF / header injection.** Real parsed-header check — the injected header must
actually appear in `response.headers`, not just somewhere in raw text.

**IDOR heuristic.** Path-ID substitution + differential analysis — flags a genuine
signal at any similarity level, including same-template pages that only swap a few
fields like a real profile/order page, while filtering out noise-field churn like
session IDs/timestamps and access-denied pages via *context*, not just the raw
similarity ratio. Numeric IDs are tried across a small bounded spread in both directions
(`-5,-2,-1,+1,+2,+5,+10,+100,+1000` — covers both the single most common real-world
shape, an immediately-adjacent account, and a few longer-range candidates) rather than a
single arbitrary offset. UUID/hashid-shaped IDs, which can't be brute-forced, are tested
by cross-referencing real sibling IDs already discovered in the engagement's own recon
data instead of guessing. Always labeled as a lead requiring manual two-session
confirmation, never an over-claimed finding.

**SSRF.** Gated to URL-fetch-shaped parameter names (`url`, `uri`, `link`, `src`,
`image`, `webhook`, `callback`, `proxy`, `fetch`, `endpoint`, `target`, `host`, `site`,
`resource`, `remote` — deliberately broad, since both signals below only ever confirm on
a genuine content match, so over-gating only costs request budget, never a false
positive). A structurally different bug from open redirect: open redirect proves the
*client's browser* gets sent somewhere attacker-controlled; SSRF proves the *server
itself* makes a network request to an attacker-chosen target. Two signals, both
zero-ambiguity content matches rather than a differential/timing-based blind-SSRF lead
(genuinely uncertain without an out-of-band callback this tool doesn't have, so left out
rather than shipped as a false-positive-prone guess):
- **file:// scheme → local file read** — many real URL-fetch clients (raw `urllib`, PHP
  cURL's default settings, Java's `URLConnection`) happily honor `file://` alongside
  `http(s)://` unless explicitly restricted.
- **Cloud-metadata-shaped fetch → real metadata content leak** — points the parameter at
  `169.254.169.254` (AWS/most clouds' link-local instance-metadata address) and GCP's
  `metadata.google.internal`; only confirms on a genuine AWS/GCP instance-metadata
  content signature in the live response, never merely "the request didn't error" — the
  SSRF-to-cloud-credential-theft chain behind some of the highest-severity real-world
  SSRF disclosures.

**XXE.** Fits the existing GET-only per-parameter architecture with zero new request
capability: gated on a parameter's *own baseline value* already looking like XML (a
leading `<?xml` or opening tag) rather than guessing XML onto an arbitrary
string/numeric parameter — real evidence this exact parameter already carries XML
content through to the server's parser (SOAP-over-GET, XML-in-query-param
config/preview validators, and legacy XML-RPC-style endpoints are all real, if less
common than POST-body XXE). Submits a DOCTYPE declaring an external entity pointing at
`file:///etc/passwd` and checks for the same zero-ambiguity `/etc/passwd` content
signature the path-traversal and SSRF `file://` checks use. No blind/out-of-band-DTD
tier, same reasoning as blind SSRF.

**Insecure Deserialization (Python pickle).** `--depth deep` only — needs a real timing
side-channel, same gating as time-based SQLi/cmdi. Same "test only what the target
already demonstrated it accepts" discipline as XXE, applied to a different format:
only fires when a parameter's *own baseline value* already decodes to bytes matching
pickle's protocol-2+ magic header (`0x80` + a protocol byte 2-5 — specific enough,
1-in-65536 by chance before even requiring valid base64, that this is real evidence
rather than a guess) — a "session state"/"cart"/"remember-me token" parameter that
round-trips through `pickle.loads()` server-side, a genuine if bad real-world pattern.
Builds a real payload via `__reduce__` → `(os.system, ('sleep 4',))` — the textbook
pickle RCE technique — re-encoded in whichever base64 alphabet the target's own
baseline value used, and proves RCE the exact same way the time-based SQLi/cmdi checks
above do: a bounded sleep and the same statistical timing gate. Not a new risk category
for the tool — the existing time-based command-injection check already sends a real,
executing `sleep 4` if the target is vulnerable; this carries an identical safety
profile via a different delivery mechanism.

**Stored XSS.** A second, genuinely two-request check. Every other XSS check is
single-request: send a payload, look at that same response. Stored XSS needs two —
submit a payload once, then a COMPLETELY SEPARATE follow-up request that uses only the
parameter's original value and never carries the payload at all. If a working
`<script>` tag still comes back unescaped on that second, unrelated request, it proves
the payload outlived the request that sent it — the actual defining property of stored
(not reflected) XSS.

**DOM-based XSS.** The one check that doesn't look at the HTTP response at all.
Reflected and stored XSS both work by inspecting raw response TEXT. That's structurally
blind to DOM-based XSS, where the bug is entirely client-side JavaScript
(`document.write(location.hash)`, `el.innerHTML = new
URLSearchParams(location.search).get('x')`) and the payload never has to touch the
server's response body at all. This check launches a real headless Chromium (via
[Playwright](https://playwright.dev/)) and proves genuine execution, not text matching:
it registers a listener for the `dialog` event (which only fires for a live, executing
`alert()`/`confirm()`/`prompt()` call) and navigates to a payload URL built with an
`<img src=x onerror=alert(...)>` canary (not `<script>` — the DOM spec deliberately does
not execute a `<script>` tag inserted via `innerHTML`). Two vectors are tried per
target: the **URL fragment** (`#<payload>`) first and unconditionally — never
transmitted to the server at all, so it's real attack surface invisible to every other
check in this entire tool — then each existing **query parameter**. One browser
instance is reused across every payload tried against a target. Gracefully degrades
with a one-line console notice if Playwright isn't installed. Because it's genuine
browser execution, it also fires (correctly) on parameters that are also plain
reflected-XSS-vulnerable — a real browser doesn't distinguish "reflected into raw HTML"
from "written into the DOM by JS."

*A real false-positive class found and fixed while building this:* `_build_url()`
deliberately preserves a URL's existing fragment when only the query string is being
mutated. But when the fragment itself already carries an XSS payload — the exact shape
of a URL a user would copy-paste from an earlier fragment-based finding to re-test it —
that leftover fragment payload rode along into every query-parameter navigation too, and
two independent `<img onerror>` elements on the same page fired two independent,
genuinely async image-load-failure events whose ordering Chromium doesn't guarantee,
making canary-matching non-deterministic. Fixed by explicitly clearing the fragment
before building any query-parameter test URL.

**HTTP Parameter Pollution.** See "Reflected XSS" above — HPP is implemented as a
fallback delivery mechanism on that check, not a separate class.

## Per-target checks

These run once per URL rather than per parameter.

**CORS misconfiguration.** An attacker-controlled `Origin` reflected in
`Access-Control-Allow-Origin` — critical if paired with
`Access-Control-Allow-Credentials: true`. Also checks the `null`-origin bypass, and a
subdomain-prefix validation bypass: a domain that merely starts with the target's own
host as a literal string prefix (e.g. `https://target.tld.attacker.tld`), defeating a
validator that checks `origin.startswith(trusted_origin)` instead of properly parsing
the resolved host. Only reached if the two wide-open probes didn't already confirm.

**Web Cache Deception.** A genuinely different mechanism: not an injection at all, but
a URL-routing confusion bug (Omer Gil's original research, and the well-known
path-parameter/trailing-segment variants since). Appends a fake static-looking filename
to the URL's path via two independent techniques — a trailing segment (`/path/fake.css`)
and a path-parameter (`/path;fake.css`) — and checks whether the response is still the
exact same dynamic content. The exploitable half needs a cache actually willing to
store the result, so the check also inspects `Cache-Control` before ever calling
anything confirmed: explicitly cacheable (`public`/`max-age>0`) is a confirmed finding;
explicitly uncacheable (`no-store`/`private`/`max-age=0`) is silently skipped entirely,
since that's a genuine, working safety control nearly every real cache respects; absent
or ambiguous is reported as an honest lead, since several real CDNs cache by
file-extension heuristic regardless of what the origin sends. Scoped to responses whose
Content-Type indicates HTML — the classic scenario is a personalized *page*, not an
arbitrary API response, and this scoping also cuts noise against real targets' JSON
APIs and legitimate single-page-app shells (found via a full regression run against this
project's own raw-socket smuggling demo, which returns identical `text/plain` content
for any path).

**NoSQL injection.** Bracket-notation operators (`user[$ne]=x`, targeting
Express/`qs`-style and PHP-style query parsers that turn bracket syntax into nested
objects fed straight into a MongoDB-style query). Tested two ways: per-parameter
(catches a single field reaching an unsanitized query) and all-parameters-simultaneously
(catches the classic AND-conjunction auth-bypass shape — `username == X AND password ==
Y` stays fully enforced unless every ANDed field is neutralized at once). Both checks
verify against a control request (the parameter simply removed, not bracket-renamed)
before ever persisting a finding — otherwise a target that doesn't do bracket-notation
parsing at all would false-positive purely because renaming a key makes the original
parameter vanish, which can independently change behavior for reasons that have nothing
to do with NoSQL operators.

**Race conditions.** A genuinely different testing model — N identical requests fired
at the *same instant* via a real thread pool, not sequential diffing. Gated to URLs
that look action-shaped (`redeem`, `claim`, `checkout`, `vote`, `transfer`, ...). If 2
or more of the N concurrent requests come back as an unqualified success, that's
treated as near-certain proof — for a correctly-guarded single-use action, at most one
concurrent request should ever win. Confirmed findings get a dedicated, genuinely
concurrent Python PoC.

**GraphQL introspection.** Gated to URLs that look like a GraphQL endpoint. Many real
GraphQL servers accept queries via a plain GET `?query=` param for convenience and CDN
cache-ability. Sends the standard introspection query and checks whether the response
leaks real schema data.

**Default / weak credentials.** Gated to URLs with both a username-shaped and
password-shaped query parameter. Tries a small, bounded list of extremely common
default pairs — deliberately **not** a wordlist spray. Its own repeated login attempts
are accounted for: a target that locks the account partway through the small credential
list is recognized as a lockout, not misread as a successful login.

**HTTP request smuggling.** The one check that abandons `requests` entirely for raw
sockets — smuggling is fundamentally about ambiguous request framing that a
well-behaved HTTP client won't let you construct. Sends the two classic desync probes
(CL.TE, TE.CL) and times the response for a server that hangs waiting for bytes that
will never arrive. **Always reported as a lead needing manual confirmation, never a
confirmed finding** — most reliable against a real front-end/back-end split. Confirmed
findings get a dedicated raw-socket PoC. HTTP only in v1.

**Exposed Kubernetes/kubelet API.** A genuine container escape needs to run from
inside that container — out of scope for a remote HTTP tester. But the kubelet API
(`:10250`) and Kubernetes API server (`:6443`) are both plain HTTPS REST APIs, and
"anonymous-auth left enabled" is a real, historically common finding (CIS Kubernetes
Benchmark 4.2.1). Checks for a genuine `PodList`/`NamespaceList`/etc. `"kind"` value via
real JSON parsing, not just any 200.

## JWT testing (`--jwt TOKEN`)

The one check that needs a real token handed to it rather than discovering its own
target — an explicit mode (like `--script`) rather than an automatic per-target check:

```bash
hakuza active "https://target.tld/api/profile" --jwt eyJ...
```

Tests three real, extremely common JWT implementation bugs:

- **alg=none bypass** — forges a token with the header's algorithm set to `none` and no
  signature at all.
- **Weak HS256 secret brute-force** — tries a small built-in list of
  common/guessable secrets, including `your-256-bit-secret` (jwt.io's own documentation
  example).
- **`kid` header path traversal** — for verifiers that build a filesystem path from the
  token's own `kid` header to look up its signing key, pointing `kid` at a predictable
  zero-byte file like `/dev/null` and signing with an empty-bytes secret.

Both checks compare the forged token's response against a genuine authenticated
baseline *and* a genuine unauthenticated one — not just "got a 200" — and explicitly
bail out with a clear message if the endpoint doesn't appear to differentiate by auth
state at all. That comparison first strips obviously-dynamic spans (ISO timestamps,
long hex/token-shaped strings) before diffing, so routine per-response noise like a
regenerated session id can't drag the similarity ratio across either threshold.
`--jwt` mode goes through the exact same scope guard and request-budget/rate-limiting
as every other mode.

## Custom scripts

`--script PATH` runs your own pre-existing Python test script (no AI involved) and
offers to persist any `HAKUZA_FINDING: {json}` line from its stdout as a real finding.
`--ai-script "description"` has Claude draft a standalone test script for you; the
**full script is always printed for review and is never executed without an explicit
confirmation prompt**.

## Safety guardrails (actually enforced, not just documented)

- v1 is **GET-only** — `--allow-state-changing` is accepted but currently a documented
  no-op, reserved for a future version.
- Every run is bounded by a running **request budget** (`--max-requests`, default 300).
- Every live request is rate-limited (`--delay`, default 0.15s).
- Time-based payloads sleep a bounded 4 seconds.
- No payload is ever destructive (no `DROP TABLE`, no `rm -rf`, no real file writes).
- Every target is checked against `hakuza scope` before it's touched, best-effort (an
  engagement with no scope defined is never blocked).

## Explicitly declined

A few additions were investigated in depth and deliberately not built, because they
couldn't clear the same "genuinely realistic, independently verifiable" bar everything
above met. One item — Python pickle deserialization — was declined this way in an
earlier round, then reconsidered and built after the specific abstract objection (no
reliable detection gate) was actually tested rather than assumed true: pickle's
protocol magic bytes turned out to be a concrete, verifiable, low-false-positive
signal. Worth remembering as a pattern — a declined item is worth revisiting if the
stated reason was never directly tested.

- **Oracle SQLi UNION extraction** — Oracle requires a `FROM` clause on every `SELECT`
  including the injected half of a `UNION`, which the shared column-count/visible-column
  probe functions don't support for any vendor today (real surgery, not a one-line dict
  entry), and no Oracle instance was available anywhere to verify a fix against live.
- **GraphQL→SQLi pivot** — would need hand-rolling real GraphQL query parsing (nested
  field selections, arguments, aliases), meaningfully more novel and fragile surface
  area than anything else here.
- **JWT `alg` case-variant bypass** (`None`/`NONE`) — tests a narrow, library-specific
  historical quirk; building a "realistic" demo for it would mean writing a verifier
  with that exact flaw and then testing against it, a much weaker validation loop than
  everything above.

## Dependencies

Requires `requests` (hard dependency, no graceful degradation) and, optionally,
`mod_active_ai.py` for AI escalation and PoC generation (without it the core diffing
engine still runs fully and just skips those two pieces with a one-line notice), and
`playwright` + `python3 -m playwright install chromium` for the DOM-XSS check
specifically (every other check is unaffected if it's missing).
