# HAKUZA Practice Range

A small, deliberately vulnerable web app for safely validating `hakuza active`
against a target you own — no third-party dependencies, stdlib only (except
`/xmlpreview`, see the endpoint table below).

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

This also starts a second, separate listener on `--port + 1` (9912 by default) — a hand-rolled raw-socket HTTP responder for the request-smuggling demo. It's not part of the main `Handler` class at all; smuggling needs byte-level control over request parsing that `http.server` would normalize away.

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

Drop `--no-ai` if you have `ANTHROPIC_API_KEY` set and want to see the AI escalation path exercised too (it mainly matters for the boolean-blind SQLi and IDOR heuristic paths, where the signal is ambiguous enough to ask for a second opinion).

## What's vulnerable where

| Endpoint | Vulnerable param | Bug | What `hakuza active` should confirm |
|---|---|---|---|
| `/product?cat=` | `cat` | Real string-concatenated SQL query against SQLite (error-based, boolean-blind, and time-based via a registered `sleep()` SQL function) + the value is reflected into HTML unescaped | Reflected XSS, SQL Injection (error/boolean/time-based) |
| `/greet?name=` | `name` | User input is spliced into a template *string* before a `{{ expr }}`-style block is `eval()`'d — the same class of bug as real Jinja2/Twig SSTI | Server-Side Template Injection, and also Reflected XSS |
| `/doc?file=` | `file` | Filename joined onto a base directory with `os.path.join()`, no canonical-path containment check | Path Traversal / LFI |
| `/go?redirect=` | `redirect` | `Location` header set directly from the parameter, no allow-list | Open Redirect |
| `/go-filtered?redirect=` | `redirect` | A realistic naive filter — blocks a literal `http(s)://` prefix that doesn't match this app's own host, but never inspects a value that doesn't start with `http` | Open Redirect (filter-bypass technique) — `//canary-host/x`, `https://thishost@canary-host/x`, and `/\canary-host/x` all sail through |
| `/echo?msg=` | `msg` | Value placed into a custom response header with no CR/LF stripping | CRLF / HTTP Header Injection |
| `/user/<id>/profile` | path segment | No auth/session check of any kind | IDOR heuristic (numeric offset path) |
| `/order/<uuid>` | path segment | Same bug, UUID-keyed | IDOR heuristic (real-sibling cross-reference — needs the recon-data seeding step above) |
| `/api/account` | `Origin` header | The request's own `Origin` is reflected verbatim into `Access-Control-Allow-Origin`, paired with `Access-Control-Allow-Credentials: true` | CORS Misconfiguration |
| `/api/partner` | `Origin` header | Actually tries to restrict access, but via a naive `origin.startswith("http://" + host)` string check | CORS Misconfiguration, subdomain-prefix bypass |
| `/login?username=&password=` | `username`, `password` | Query string parsed with bracket notation (`username[$ne]=x` becomes a dict) and handed unsanitized to a naive "MongoDB-style" matcher | NoSQL Injection — per-parameter and all-parameters bypass (`/login?username[$ne]=x&password[$ne]=x` logs in as admin) |
| `/redeem?code=` | `code` | Read-then-write with no lock around a single-use coupon | Race Condition — 10 concurrent requests all redeem successfully |
| `/api/token` → `/api/profile` | `Authorization: Bearer` header | Real hand-rolled HS256 JWT issuer/verifier — accepts `alg=none`, and verifies against a weak secret (`secret123`) | JWT — `hakuza active .../api/profile --jwt <token>` finds both bugs |
| `/comments?text=` | `text` | Every submitted comment is appended to a shared list and rendered unescaped on every future load | Stored XSS |
| `/api/kid-token` → `/api/kid-profile` | `Authorization: Bearer` header | A second JWT verifier that looks the signing key up per-token via the header's own `kid` field, with a naive `os.path.join` | JWT `kid` path traversal |
| `/graphql?query=` | `query` | Minimal hand-rolled GraphQL responder, answers introspection for any anonymous caller | GraphQL Introspection Enabled |
| `/admin/login?username=&password=` | `username`, `password` | Plain equality check against a literal, never-changed `admin`/`admin` pair | Default Credentials |
| `http://127.0.0.1:9912/` (separate port, raw sockets) | — | Trusts `Content-Length` even when `Transfer-Encoding` is also present, genuinely blocks on `recv()` if the CL-bounded body isn't complete chunked framing | HTTP Request Smuggling (CL.TE) — a real ~5s hang |
| `/api/v1/pods` (also `/pods`, `/api/v1/namespaces`) | — | Real Kubernetes/kubelet API shape, anonymous-auth left enabled | Exposed Kubernetes/Kubelet API |
| `/domxss` (fragment and `?name=`) | `location.hash`, `location.search` — both client-side only | Two independent, zero-sanitization `.innerHTML` sinks; the server never reads `qs` for its response | DOM-based XSS — see `/domxss-safe` for the negative control |
| `/domxss-safe` | — (not vulnerable) | Same shape, `.textContent` instead of `.innerHTML` | Negative control |
| `/fetch?url=` | `url` | Hands the parameter straight to `urllib.request.urlopen()` with zero validation | SSRF — `file:///etc/passwd` for local file read, `http://169.254.169.254/latest/meta-data/` for cloud-metadata theft |
| `/fetch-safe?url=` | — (not vulnerable) | Scheme allow-list + host denylist before `urlopen` | Negative control |
| `/xmlpreview?data=` | `data` | Parses with lxml's `XMLParser(resolve_entities=True)` — needs `pip install lxml`, see `testlab/requirements.txt` | XXE — a DOCTYPE entity pointing at `file:///etc/passwd` resolves |
| `/xmlpreview-safe?data=` | — (not vulnerable) | `resolve_entities=False` + `load_dtd=False` | Negative control |
| `/hppdemo?msg=` | `msg` | Filter reads the FIRST occurrence of a duplicated parameter, the renderer reads the LAST | HTTP Parameter Pollution — `?msg=hello&msg=<script>...</script>` bypasses the filter |
| `/hppdemo-safe?msg=` | — (not vulnerable) | Filter and renderer consistently use the same occurrence | Negative control |
| `/dashboard` (also `/dashboard/*`, `/dashboard;*`) | path (routing) | Greedy prefix routing serves the identical personalized page for any suffix, with `Cache-Control: public, max-age=3600` | Web Cache Deception |
| `/dashboard-safe` | — (not vulnerable) | Exact-match routing only | Negative control |
| `/loadstate?data=` | `data` | Real, unmocked `pickle.loads()` on client-supplied base64 data — no dependency needed, `pickle` is stdlib | Insecure Deserialization — a crafted payload's `__reduce__` genuinely calls `os.system('sleep 4')`, proven via real timing (`--depth deep`) |
| `/loadstate-safe?data=` | — (not vulnerable) | Same feature via `json.loads()`, which can never invoke a callable | Negative control |

## Extending this range

Each endpoint is a small, independent method on `Handler` in
`vulnerable_site.py` — add a new one following the same pattern (unsanitized
param → the bug → return HTML) to test additional detection classes as
`hakuza active` grows new probes (deserialization is not covered yet — no
detector for it in `mod_active.py` as of this writing).

**→ [Full build journal](../docs/TESTLAB_NOTES.md)** — every real bug found while
building each demo or the detector it validates, and exactly how each fix was
verified (the IDOR similarity-band gap, the SQLi marker-collision bug, the
NoSQLi false-positive class, the DOM-XSS non-determinism bug, the 9-bug
independent adversarial audit, and more).
