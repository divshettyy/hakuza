#!/usr/bin/env python3
"""
testlab/vulnerable_site.py — HAKUZA Active Testing Practice Range

A small, deliberately vulnerable web application, built specifically to
exercise every vulnerability class `hakuza active` (mod_active.py) detects,
each on its own clearly-labeled endpoint. This exists so the tool can be
validated safely and legally against a target you own, instead of against
someone else's real infrastructure.

Zero third-party dependencies — stdlib only (http.server + sqlite3) — so it
runs anywhere Python 3 runs, with nothing to `pip install`.

*** DO NOT expose this to any network beyond localhost. It is intentionally
*** broken. It binds to 127.0.0.1 only and refuses to be told otherwise.

Run:
    python3 testlab/vulnerable_site.py [--port 9911]

Then point hakuza at it (from a throwaway/demo engagement — see
testlab/README.md for the exact commands):

    hakuza active "http://127.0.0.1:9911/product?cat=1" --depth deep --no-ai
    hakuza active "http://127.0.0.1:9911/greet?name=guest" --no-ai
    hakuza active "http://127.0.0.1:9911/doc?file=welcome.txt" --no-ai
    hakuza active "http://127.0.0.1:9911/go?redirect=" --no-ai
    hakuza active "http://127.0.0.1:9911/echo?msg=hello" --no-ai
    hakuza active "http://127.0.0.1:9911/user/1000/profile?tab=1" --no-ai
    hakuza active "http://127.0.0.1:9911/domxss?name=x" --no-ai

Or just: hakuza active --all --depth deep   (after `hakuza wayback` /
manually seeding these URLs into the engagement's recon data — see README).
"""

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# In-memory "database" — real SQLite, real string-concatenated queries, so
# error-based / boolean-blind / time-based SQLi are all genuinely exploitable
# (not simulated) against the /product endpoint.
# ---------------------------------------------------------------------------

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.create_function("sleep", 1, lambda secs: (time.sleep(float(secs)), 0)[1])
_DB.executescript(
    """
    CREATE TABLE products (id INTEGER PRIMARY KEY, category TEXT, name TEXT, price REAL);
    INSERT INTO products VALUES (1, '1', 'Wireless Mouse', 19.99);
    INSERT INTO products VALUES (2, '1', 'Mechanical Keyboard', 89.99);
    INSERT INTO products VALUES (3, '2', 'USB-C Hub', 34.50);

    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, ssn TEXT);
    INSERT INTO users VALUES (1000, 'alice',   'alice@example.com',   'REDACTED-000-11-1000');
    INSERT INTO users VALUES (1001, 'bob',     'bob@example.com',     'REDACTED-000-11-1001');
    INSERT INTO users VALUES (2000, 'charlie', 'charlie@example.com', 'REDACTED-000-11-2000');

    CREATE TABLE orders (uuid TEXT PRIMARY KEY, customer TEXT, total REAL, card_last4 TEXT);
    INSERT INTO orders VALUES ('3f2504e0-4f89-4e63-9a0c-0305e82c3301', 'alice',   142.50, '4242');
    INSERT INTO orders VALUES ('7c9e6679-7425-40de-944b-e07fc1f90ae7', 'bob',      89.99, '1881');
    INSERT INTO orders VALUES ('f47ac10b-58cc-4372-a567-0e02b2c3d479', 'charlie', 210.00, '9911');
    """
)
_DB.commit()

# UUID-shaped IDs can't be brute-forced (122 bits of randomness) — the only
# realistic way hakuza active's IDOR heuristic can test them is by
# cross-referencing OTHER real URLs already discovered in the engagement's
# own recon data. testlab/README.md documents seeding these three order
# URLs into a throwaway engagement's wayback_urls recon data before running
# `hakuza active` against one of them, to exercise that exact code path.
_ORDER_UUIDS = [
    "3f2504e0-4f89-4e63-9a0c-0305e82c3301",
    "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
]

_DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")
os.makedirs(_DOCS_DIR, exist_ok=True)
with open(os.path.join(_DOCS_DIR, "welcome.txt"), "w") as f:
    f.write("Welcome to the HAKUZA practice range document store.\n")

# -- NoSQL injection target -------------------------------------------------
# No MongoDB dependency needed to demonstrate the real bug: the vulnerable
# behavior is the QUERY-STRING PARSING, not the storage engine. Frameworks
# like Express's `qs` (and several PHP setups) turn `?username[$ne]=x` into
# a nested {"username": {"$ne": "x"}} object by default — this mimics that
# exact parsing, then a naive "MongoDB-style" matcher interprets the
# resulting dict as operators. That combination — automatic bracket-to-
# object parsing feeding straight into a query/match — is the actual root
# cause of real-world NoSQLi, independent of which database is behind it.
_LOGIN_USERS = [
    {"username": "admin", "password": "Sup3rS3cret!2026"},
]

# -- Default credentials target ------------------------------------------
# A second, separate login endpoint — this one for a real (depressingly
# common) bug: an admin panel shipped with its literal default
# username/password still enabled. /login above intentionally uses a
# strong password so it does NOT trigger the default-credentials check —
# that's the correct behavior for a real strong-password endpoint, not a
# gap in the check.
_ADMIN_CREDENTIALS = {"username": "admin", "password": "admin"}

# -- Race condition target --------------------------------------------------
# One redemption available, no lock around the read-check-write sequence —
# the entire bug. ThreadingHTTPServer runs each request in its own thread,
# so N concurrent requests can all read "1 remaining" before any of them
# writes the decrement. The 50ms sleep between read and write isn't padding
# for effect — it stands in for the real-world DB/network round-trip that
# creates this exact window in a real app, widening it enough to reliably
# demonstrate the race without needing hundreds of requests.
_COUPON_REMAINING = {"WELCOME10": 1}

# -- JWT target ---------------------------------------------------------
# A real, working hand-rolled HS256 JWT issuer/verifier — no PyJWT
# dependency needed to demonstrate the actual bugs, which are both
# implementation mistakes, not library bugs: (1) trusting the token's own
# declared "alg" header instead of enforcing one expected algorithm, and
# (2) signing with a short, guessable secret. Both are real, extremely
# common real-world JWT implementation bugs, not contrived for this range.
_JWT_SECRET = "secret123"  # deliberately weak — this IS the bug, don't "fix" it

# -- Stored XSS target --------------------------------------------------
# Shared, unbounded, unescaped — a real GET-based guestbook's entire
# storage layer in three words.
_COMMENTS = []


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _jwt_issue(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(_JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _jwt_verify(token: str):
    """Returns the payload dict if the token is accepted, None otherwise.
    Deliberately vulnerable two ways: trusts the token's own "alg" header
    (accepting "none" with no signature check at all) instead of enforcing
    HS256 specifically, and verifies real HS256 signatures against a weak,
    guessable secret."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None

    alg = header.get("alg")
    if alg == "none":
        return payload  # the bug: no signature required at all
    if alg == "HS256" and len(parts) == 3:
        h, p, s = parts
        expected = hmac.new(_JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if hmac.compare_digest(_b64url_encode(expected), s):
            return payload
    return None


# -- kid path-traversal target -------------------------------------------
# A SEPARATE, differently-vulnerable JWT verifier: instead of one fixed
# global secret, this one looks the signing key up per-token via the
# header's own "kid" field — a real, common pattern for multi-key/
# key-rotation setups — but builds the filesystem path with a naive
# os.path.join and no containment check. kid="../../../../dev/null"
# escapes the intended keys/ directory entirely and reads a real,
# predictable zero-byte file, so signing with an empty-bytes secret
# forges a valid signature.
_JWT_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jwt_keys")
os.makedirs(_JWT_KEYS_DIR, exist_ok=True)
with open(os.path.join(_JWT_KEYS_DIR, "default.key"), "wb") as f:
    f.write(b"realsigningkey-9f3a2c7e")


def _jwt_issue_kid(payload: dict, kid: str = "default.key") -> str:
    with open(os.path.join(_JWT_KEYS_DIR, kid), "rb") as f:
        secret = f.read()
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _jwt_verify_kid(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    if header.get("alg") != "HS256":
        return None

    kid = header.get("kid", "default.key")
    # Deliberately vulnerable: no os.path.abspath/containment check against
    # _JWT_KEYS_DIR before opening — this join is the entire bug.
    key_path = os.path.join(_JWT_KEYS_DIR, kid)
    try:
        with open(key_path, "rb") as f:
            secret = f.read()
    except OSError:
        return None

    h, p, s = parts
    expected = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if hmac.compare_digest(_b64url_encode(expected), s):
        return payload
    return None


def _parse_nested_qs(query_string):
    """a[b]=c -> {"a": {"b": "c"}} instead of a flat "a[b]" string key —
    the exact parsing behavior that makes NoSQLi via query string possible."""
    result = {}
    for key, values in urllib.parse.parse_qs(query_string, keep_blank_values=True).items():
        m = re.match(r"^([^\[]+)\[([^\]]+)\]$", key)
        if m:
            base, sub = m.group(1), m.group(2)
            if not isinstance(result.get(base), dict):
                result[base] = {}
            result[base][sub] = values[0]
        else:
            result[key] = values[0]
    return result


def _mongo_style_match(stored_value, query_value):
    """Simplified operator matching: a plain string means equality; a dict
    means $ne / $regex / $gt — the handful of operators real-world NoSQLi
    payloads actually use."""
    if isinstance(query_value, dict):
        if "$ne" in query_value:
            return stored_value != query_value["$ne"]
        if "$regex" in query_value:
            try:
                return re.search(query_value["$regex"], stored_value) is not None
            except re.error:
                return False
        if "$gt" in query_value:
            return stored_value > query_value["$gt"]
        return False
    return stored_value == query_value


def _page(title, body):
    return (
        "<!doctype html><html><head><title>{}</title></head>"
        "<body style='font-family:sans-serif;max-width:700px;margin:40px auto'>"
        "{}"
        "<hr><p><a href='/'>&laquo; back to index</a></p>"
        "</body></html>"
    ).format(html.escape(title), body)


class Handler(BaseHTTPRequestHandler):
    server_version = "HakuzaPracticeRange/1.0"

    def log_message(self, fmt, *args):
        pass  # keep the console quiet; this is a practice target, not a service

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra_headers=None):
        payload = body.encode("utf-8", errors="ignore") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # --- extra_headers is where the deliberate CRLF-injection bug lives
        # (see /echo below) — send_header() writes "%s: %s\r\n" with NO
        # validation of embedded control characters, exactly like a real
        # hand-rolled header-setting bug in a real framework would.
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        path = parts.path

        try:
            if path == "/":
                self._index()
            elif path == "/product":
                self._product(qs)
            elif path == "/greet":
                self._greet(qs)
            elif path == "/doc":
                self._doc(qs)
            elif path == "/go":
                self._go(qs)
            elif path == "/echo":
                self._echo(qs)
            elif path == "/api/account":
                self._api_account()
            elif path == "/login":
                self._login(parts.query)
            elif path == "/admin/login":
                self._admin_login(qs)
            elif path == "/redeem":
                self._redeem(qs)
            elif path == "/api/token":
                self._api_token()
            elif path == "/api/profile":
                self._api_profile()
            elif path == "/comments":
                self._comments(qs)
            elif path == "/api/kid-token":
                self._api_kid_token()
            elif path == "/api/kid-profile":
                self._api_kid_profile()
            elif path == "/graphql":
                self._graphql(qs)
            elif path in ("/pods", "/api/v1/pods", "/api/v1/namespaces"):
                self._k8s_pods()
            elif path == "/domxss":
                self._domxss(qs)
            elif path == "/domxss-safe":
                self._domxss_safe(qs)
            elif re.match(r"^/user/\d+/profile$", path):
                self._profile(path, qs)
            elif re.match(r"^/order/[0-9a-f-]{36}$", path, re.I):
                self._order(path)
            else:
                self._send(404, _page("Not found", "<h1>404</h1><p>No such page.</p>"))
        except Exception as exc:
            # A genuinely broken app leaks exceptions; that's realistic too,
            # but we don't want a crash to kill the whole server thread.
            self._send(500, _page("Error", f"<pre>{html.escape(str(exc))}</pre>"))

    # -- / -------------------------------------------------------------
    def _index(self):
        body = """
        <h1>HAKUZA Practice Range</h1>
        <p>Every link below is <b>intentionally vulnerable</b> to one class
        `hakuza active` detects. Do not deploy this anywhere but localhost.</p>
        <ul>
          <li><a href="/product?cat=1">/product?cat=1</a>
              &mdash; SQL injection (error/boolean/time-based) + reflected XSS</li>
          <li><a href="/greet?name=guest">/greet?name=guest</a>
              &mdash; Server-Side Template Injection</li>
          <li><a href="/doc?file=welcome.txt">/doc?file=welcome.txt</a>
              &mdash; Path traversal / LFI</li>
          <li><a href="/go?redirect=/product">/go?redirect=/product</a>
              &mdash; Open redirect</li>
          <li><a href="/echo?msg=hello">/echo?msg=hello</a>
              &mdash; CRLF / HTTP header injection</li>
          <li><a href="/user/1000/profile?tab=1">/user/1000/profile?tab=1</a>
              &mdash; IDOR, numeric ID (try /user/1001/profile, /user/2000/profile)</li>
          <li><a href="/order/3f2504e0-4f89-4e63-9a0c-0305e82c3301">/order/&lt;uuid&gt;</a>
              &mdash; IDOR, UUID-keyed (3 real order UUIDs exist — see testlab/README.md
              for how to seed them into recon data so hakuza active can cross-reference
              them instead of guessing)</li>
          <li><a href="/api/account">/api/account</a>
              &mdash; CORS misconfiguration (reflects Origin + allows credentials — try
              curl -H "Origin: https://evil.example" to see it reflected back)</li>
          <li><a href="/login?username=admin&password=wrongpass">/login?username=&amp;password=</a>
              &mdash; NoSQL injection (try /login?username[$ne]=x&amp;password[$ne]=x
              to log in as admin without the real password)</li>
          <li><a href="/redeem?code=WELCOME10">/redeem?code=WELCOME10</a>
              &mdash; Race condition (one-time coupon, no lock around the read-check-write
              sequence &mdash; fire it many times at once and it redeems more than once)</li>
          <li><a href="/api/token">/api/token</a> &rarr; <a href="/api/profile">/api/profile</a>
              &mdash; JWT auth bypass (get a real token from /api/token, then try
              hakuza active .../api/profile --jwt &lt;token&gt; &mdash; accepts alg=none
              with no signature, and HS256 signed with the weak secret "secret123")</li>
          <li><a href="/comments?text=hello">/comments?text=hello</a>
              &mdash; Stored XSS (a GET-based guestbook &mdash; submit a &lt;script&gt;
              payload once, then any later visit with a DIFFERENT text value still
              renders it, unescaped)</li>
          <li><a href="/api/kid-token">/api/kid-token</a> &rarr;
              <a href="/api/kid-profile">/api/kid-profile</a>
              &mdash; JWT kid header path traversal (naive filesystem key lookup &mdash;
              try hakuza active .../api/kid-profile --jwt &lt;token&gt;)</li>
          <li><a href="/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D">/graphql?query=...</a>
              &mdash; GraphQL introspection enabled for anonymous callers</li>
          <li><a href="/admin/login?username=guest&password=wrong">/admin/login?username=&amp;password=</a>
              &mdash; Default credentials (admin/admin, never changed)</li>
          <li><a href="/api/v1/pods">/api/v1/pods</a>
              &mdash; Exposed Kubernetes/kubelet API (anonymous-auth enabled &mdash;
              leaks pod env vars including fake DB_PASSWORD/STRIPE_SECRET_KEY)</li>
          <li><a href="/domxss#&lt;img src=x onerror=alert(1)&gt;">/domxss#&lt;payload&gt;</a>
              &mdash; DOM-based XSS (location.hash and location.search &rarr; innerHTML,
              both entirely client-side &mdash; the fragment vector never even reaches
              this server; see also <a href="/domxss-safe">/domxss-safe</a>, the
              non-vulnerable textContent-based negative control)</li>
        </ul>
        """
        self._send(200, _page("HAKUZA Practice Range", body))

    # -- /product?cat= --------------------------------------------------
    # Real SQLi (string-concatenated query against real SQLite) AND
    # reflected XSS (the category value is echoed back unescaped).
    def _product(self, qs):
        cat = qs.get("cat", [""])[0]

        # Deliberately vulnerable: string concatenation instead of a
        # parameterized query. This is the entire bug.
        query = f"SELECT id, name, price FROM products WHERE category = '{cat}'"
        rows, error = [], None
        try:
            rows = _DB.execute(query).fetchall()
        except sqlite3.Error as e:
            # Real vendor-style error text, reachable via error-based SQLi.
            # Real DB error output is typically far more verbose than a bare
            # message (driver name, query fragment, traceback-style detail)
            # — matching that realism matters here, since hakuza active's
            # error-based gate requires a meaningfully different response
            # length from baseline, not just any error text, to avoid
            # false-firing on trivial length noise. Kept genuinely
            # SQLite-flavored (not generic/MySQL-sounding phrasing) so
            # hakuza active's vendor fingerprinting — which picks UNION
            # extraction syntax based on the exact wording — correctly
            # detects "sqlite" and not some other engine this app doesn't
            # actually run.
            error = (
                f"sqlite3.OperationalError: {e} "
                f"[pysqlite driver, query: {query!r}]"
            )

        # Deliberately vulnerable: cat is reflected into HTML with no
        # escaping at all (reflected XSS).
        #
        # Rendering below is defensive about non-numeric/NULL cell values on
        # purpose: a UNION-based SQLi injects its own row shape into this
        # query, and a naive f"{price:.2f}" would crash the whole page (a
        # 500) the moment an injected row's price-position value isn't a
        # real float. A silently-crashing app would get noticed and patched
        # fast; a stable one that just renders whatever came back is the
        # more realistic (and more dangerous) case, and the one worth
        # testing UNION extraction against.
        def _cell(v):
            return html.escape(str(v)) if v is not None else "NULL"

        def _price_cell(v):
            try:
                return f"${float(v):.2f}"
            except (TypeError, ValueError):
                return _cell(v)

        rows_html = "".join(
            f"<tr><td>{_cell(r[0])}</td><td>{_cell(r[1])}</td><td>{_price_cell(r[2])}</td></tr>"
            for r in rows
        )
        body = f"""
        <h1>Product catalog</h1>
        <p>Category filter: {cat}</p>
        {'<p style="color:red">Database error: ' + html.escape(error) + '</p>' if error else ''}
        <table border="1" cellpadding="6"><tr><th>ID</th><th>Name</th><th>Price</th></tr>
        {rows_html}
        </table>
        """
        self._send(200, _page("Product catalog", body))

    # -- /greet?name= ----------------------------------------------------
    # Real SSTI: user input is spliced directly into a template STRING
    # before evaluation, then {{ expr }} blocks are evaluated. This mirrors
    # the exact class of bug that produces SSTI in real templating engines
    # (Jinja2/Twig) when a developer does `render_template_string(user_input)`
    # instead of passing user input as template *data*.
    def _greet(self, qs):
        name = qs.get("name", ["guest"])[0]
        template = "<h1>Hello, " + name + "!</h1><p>Welcome back.</p>"

        def _eval_expr(match):
            expr = match.group(1)
            try:
                # Deliberately vulnerable: eval() on attacker-influenced
                # template source. This IS the vulnerability, not a helper
                # around it — do not "fix" this file, that's the point.
                return html.escape(str(eval(expr, {"__builtins__": {}}, {})))
            except Exception:
                return match.group(0)

        rendered = re.sub(r"\{\{(.*?)\}\}", _eval_expr, template)
        self._send(200, _page("Greeting", rendered))

    # -- /doc?file= -------------------------------------------------------
    # Real path traversal: the filename is joined onto the docs directory
    # with zero sanitization or canonical-path containment check.
    def _doc(self, qs):
        filename = qs.get("file", [""])[0]
        target_path = os.path.join(_DOCS_DIR, filename)  # deliberately unsafe join
        try:
            with open(target_path, "r", errors="replace") as f:
                content = f.read()
            self._send(200, _page("Document", f"<pre>{html.escape(content)}</pre>"))
        except FileNotFoundError:
            self._send(404, _page("Not found", "<p>No such document.</p>"))
        except (IsADirectoryError, PermissionError) as e:
            self._send(500, _page("Error", f"<pre>{html.escape(str(e))}</pre>"))

    # -- /go?redirect= ------------------------------------------------------
    # Real open redirect: the Location header is set directly from
    # unsanitized user input, with no allow-list check.
    def _go(self, qs):
        target = qs.get("redirect", ["/"])[0] or "/"
        self._send(302, "", extra_headers={"Location": target})

    # -- /echo?msg= -----------------------------------------------------
    # Real CRLF / header injection: msg is placed directly into a custom
    # response header with no control-character stripping. http.server's
    # send_header() does not validate embedded \r\n, so an attacker-supplied
    # "\r\nX-Injected: 1" genuinely becomes a second response header.
    def _echo(self, qs):
        msg = qs.get("msg", [""])[0]
        self._send(200, _page("Echo", f"<p>You said: {html.escape(msg)}</p>"),
                   extra_headers={"X-Echo": msg})

    # -- /api/account -----------------------------------------------------
    # Real CORS misconfiguration: the request's own Origin header is
    # reflected verbatim into Access-Control-Allow-Origin (instead of
    # checked against an allow-list), combined with
    # Access-Control-Allow-Credentials: true — the genuinely dangerous
    # pairing, since it means any origin can make a credentialed
    # cross-origin request and read session-scoped data back.
    def _api_account(self):
        origin = self.headers.get("Origin", "")
        body = '{"account_id": 4471, "balance_usd": 18320.55, "plan": "enterprise"}'
        headers = {"Access-Control-Allow-Credentials": "true"}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
        self._send(200, body, content_type="application/json", extra_headers=headers)

    # -- /login?username=&password= ----------------------------------------
    # Real NoSQL injection: the raw query string is parsed with bracket
    # notation (see _parse_nested_qs above), so `username[$ne]=x` becomes a
    # dict instead of a string, and that dict is handed straight to
    # _mongo_style_match with no type check at all — the entire bug.
    # Normal use: /login?username=admin&password=wrongpass -> rejected.
    # Bypass:     /login?username[$ne]=x&password[$ne]=x -> logged in as
    #             admin, without ever knowing the real password.
    def _login(self, raw_query):
        parsed = _parse_nested_qs(raw_query)
        username_q = parsed.get("username", "")
        password_q = parsed.get("password", "")
        for user in _LOGIN_USERS:
            if (_mongo_style_match(user["username"], username_q)
                    and _mongo_style_match(user["password"], password_q)):
                self._send(200, _page(
                    "Login",
                    f"<h1>Welcome, {html.escape(user['username'])}!</h1>"
                    f"<p>Login successful.</p>",
                ))
                return
        self._send(200, _page("Login", "<p>Invalid credentials.</p>"))

    # -- /admin/login?username=&password= -------------------------------
    # Real default-credentials bug: a plain equality check (no NoSQLi,
    # no other trick — this endpoint exists to demonstrate exactly one
    # thing in isolation) against a literal, never-changed admin/admin
    # pair. Depressingly common in the real world.
    def _admin_login(self, qs):
        username = qs.get("username", [""])[0]
        password = qs.get("password", [""])[0]
        if (username == _ADMIN_CREDENTIALS["username"]
                and password == _ADMIN_CREDENTIALS["password"]):
            self._send(200, _page(
                "Admin Login",
                "<h1>Welcome, admin!</h1><p>Login successful.</p>",
            ))
            return
        self._send(200, _page("Admin Login", "<p>Invalid credentials.</p>"))

    # -- /redeem?code= -------------------------------------------------
    # Real race condition: read-then-write with no lock around a
    # single-use resource. Fire this once and it behaves perfectly
    # (1 success, then "already used" forever after). Fire it N times
    # concurrently and multiple requests all see the resource as
    # available before any of them writes the decrement.
    def _redeem(self, qs):
        code = qs.get("code", [""])[0]
        remaining = _COUPON_REMAINING.get(code)
        if remaining is None:
            self._send(200, _page("Redeem", "<p>Invalid coupon code.</p>"))
            return
        if remaining <= 0:
            self._send(200, _page("Redeem", "<p>Coupon already used. Sorry!</p>"))
            return
        time.sleep(0.05)  # the real-world DB/network round-trip this simulates
        _COUPON_REMAINING[code] = remaining - 1
        self._send(200, _page(
            "Redeem",
            f"<h1>Success!</h1><p>10% discount applied using code "
            f"{html.escape(code)}.</p>",
        ))

    # -- /api/token ---------------------------------------------------------
    # Issues a real, correctly-signed JWT for a demo user — this is what a
    # legitimate login flow would return. hakuza has no login flow of its
    # own, so this stands in for "copy a real token out of your browser's
    # dev tools" for testing purposes.
    def _api_token(self):
        token = _jwt_issue({"sub": "alice", "role": "user", "uid": 1000})
        self._send(200, json.dumps({"token": token}), content_type="application/json")

    # -- /api/profile ---------------------------------------------------
    # Real JWT verification with two real bugs: trusts the token's own
    # declared alg (accepting "none" with zero signature check), and
    # verifies real HS256 signatures against a short, guessable secret.
    def _api_profile(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        payload = _jwt_verify(token) if token else None
        if payload is None:
            self._send(401, json.dumps({"error": "unauthorized"}),
                       content_type="application/json")
            return
        self._send(200, json.dumps({
            "username": payload.get("sub"),
            "role": payload.get("role"),
            "uid": payload.get("uid"),
            "note": "authenticated profile data",
        }), content_type="application/json")

    # -- /comments?text= ------------------------------------------------
    # Real stored XSS: a GET-based guestbook (an old but genuinely still-
    # seen pattern — plenty of real comment/feedback widgets are wired to
    # a plain GET form). Every submitted comment is appended to a shared
    # list and every future page load — including ones that never
    # submitted anything themselves — renders the FULL history, unescaped.
    # That's the whole bug: storage and rendering both trust the input.
    def _comments(self, qs):
        text = qs.get("text", [None])[0]
        if text:
            _COMMENTS.append(text)
        rendered = "".join(f"<li>{c}</li>" for c in _COMMENTS) or "<li><em>No comments yet.</em></li>"
        body = f"""
        <h1>Guestbook</h1>
        <ul>{rendered}</ul>
        <form>
          <input type="text" name="text" placeholder="Leave a comment">
          <button type="submit">Post</button>
        </form>
        """
        self._send(200, _page("Comments", body))

    # -- /api/kid-token -------------------------------------------------
    def _api_kid_token(self):
        token = _jwt_issue_kid({"sub": "alice", "role": "user", "uid": 1000})
        self._send(200, json.dumps({"token": token}), content_type="application/json")

    # -- /api/kid-profile -------------------------------------------------
    def _api_kid_profile(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        payload = _jwt_verify_kid(token) if token else None
        if payload is None:
            self._send(401, json.dumps({"error": "unauthorized"}),
                       content_type="application/json")
            return
        self._send(200, json.dumps({
            "username": payload.get("sub"),
            "role": payload.get("role"),
            "uid": payload.get("uid"),
            "note": "authenticated profile data (kid-based key lookup)",
        }), content_type="application/json")

    # -- /graphql?query= ------------------------------------------------
    # Real GraphQL introspection misconfiguration: any anonymous caller
    # can ask the schema to describe itself. This is a minimal hand-rolled
    # responder (no graphql-core dependency needed to demonstrate the
    # actual bug, which is a missing access check on introspection, not
    # anything about GraphQL's execution engine) that recognizes the
    # standard __schema introspection query shape and answers it exactly
    # like a real, misconfigured GraphQL server would.
    def _graphql(self, qs):
        query = qs.get("query", [""])[0]
        if "__schema" in query:
            response = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [
                            {"name": "Query", "kind": "OBJECT"},
                            {"name": "User", "kind": "OBJECT"},
                            {"name": "Order", "kind": "OBJECT"},
                            {"name": "AdminMutation", "kind": "OBJECT"},
                            {"name": "ResetPassword", "kind": "OBJECT"},
                            {"name": "String", "kind": "SCALAR"},
                            {"name": "Int", "kind": "SCALAR"},
                        ],
                    }
                }
            }
            self._send(200, json.dumps(response), content_type="application/json")
            return
        self._send(200, json.dumps({"data": {"message": "Hello from GraphQL"}}),
                   content_type="application/json")

    # -- /api/v1/pods (kubelet/Kubernetes API exposure demo) --------------
    # A real kubelet's /pods API is HTTPS with a self-signed cert;
    # reproducing that here would need either a third-party crypto library
    # or shelling out to openssl at startup, breaking this range's
    # zero-dependency, single-file philosophy for a detail that's
    # orthogonal to the actual bug: anonymous-auth left enabled, which
    # leaks this exact PodList shape regardless of which transport carries
    # it. Real, illustrative-but-fake secret/env-var names included so the
    # stakes of a leaked pod list are concrete, not abstract.
    def _k8s_pods(self):
        response = {
            "kind": "PodList",
            "apiVersion": "v1",
            "items": [
                {
                    "metadata": {"name": "payments-api-7d9f", "namespace": "prod"},
                    "spec": {
                        "containers": [{
                            "name": "payments-api",
                            "image": "internal-registry/payments-api:2.4.1",
                            "env": [
                                {"name": "DB_PASSWORD", "value": "REDACTED-DEMO-VALUE"},
                                {"name": "STRIPE_SECRET_KEY", "value": "REDACTED-DEMO-VALUE"},
                            ],
                        }],
                    },
                },
                {
                    "metadata": {"name": "redis-cache-2x", "namespace": "prod"},
                    "spec": {"containers": [{"name": "redis", "image": "redis:7.2"}]},
                },
            ],
        }
        self._send(200, json.dumps(response), content_type="application/json")

    # -- /domxss[?name=] -------------------------------------------------
    # Real DOM-based XSS. Deliberately different in kind from every other
    # bug on this range: the SERVER RESPONSE BODY here is byte-for-byte
    # IDENTICAL no matter what's in the query string or URL fragment — this
    # handler never reads `qs` at all for the response it sends. Two real,
    # independent client-side sinks live in the inline <script> below:
    #
    #   1. `location.hash` -> innerHTML. A URL fragment (`#...`) is never
    #      transmitted to the server by the browser at all (per the URL
    #      spec) — this handler has literally no way to know it was even
    #      sent. The vulnerability is 100% client-side.
    #   2. `location.search` (via URLSearchParams) -> innerHTML, read for
    #      the `name` parameter. The query string DOES reach this handler
    #      (visible in `qs`, unused on purpose) but the served HTML never
    #      echoes it — the browser's own JS re-reads it from
    #      `location.search` at render time and writes it into the DOM
    #      unescaped. A raw-response-text scanner sees nothing; only a
    #      real browser that actually runs the JS can find this one.
    #
    # Both sinks use .innerHTML with zero sanitization — the entire bug.
    def _domxss(self, qs):
        body = """
        <h1>DOM XSS demo</h1>
        <p>Two independent, genuinely client-side-only sinks below — the
        server never sees or echoes either payload; open this page's
        source (Ctrl+U) and note the query string / fragment are nowhere
        in it.</p>
        <div id="hash-output"></div>
        <div id="query-output"></div>
        <script>
          // Sink 1: URL fragment -> innerHTML. Never reaches the server.
          var hashPayload = location.hash.substring(1);
          if (hashPayload) {
            document.getElementById('hash-output').innerHTML =
                decodeURIComponent(hashPayload);
          }
          // Sink 2: query string ("name") -> innerHTML, read client-side.
          // Reaches the server on the wire, but this served HTML is
          // static regardless of its value -- the server-side handler
          // never puts it in the response body.
          var params = new URLSearchParams(location.search);
          var namePayload = params.get('name');
          if (namePayload) {
            document.getElementById('query-output').innerHTML = namePayload;
          }
        </script>
        """
        self._send(200, _page("DOM XSS demo", body))

    # -- /domxss-safe[?name=] ---------------------------------------------
    # Structurally identical page/sinks to /domxss above, EXCEPT both
    # writes use .textContent instead of .innerHTML — the safe DOM API
    # that never parses its argument as markup, so an <img onerror=...>
    # payload just renders as inert literal text, no alert() ever fires.
    # Exists specifically as a negative-test control: it guards against a
    # detector that's fooled by surface similarity (page structure, param
    # names, even the word "innerHTML" appearing in a comment/nearby
    # script) rather than genuinely proving live JavaScript execution.
    def _domxss_safe(self, qs):
        body = """
        <h1>DOM XSS demo (safe variant)</h1>
        <p>Same shape as /domxss, but both sinks use .textContent instead
        of .innerHTML -- inert by construction, not by luck.</p>
        <div id="hash-output"></div>
        <div id="query-output"></div>
        <script>
          var hashPayload = location.hash.substring(1);
          if (hashPayload) {
            document.getElementById('hash-output').textContent =
                decodeURIComponent(hashPayload);
          }
          var params = new URLSearchParams(location.search);
          var namePayload = params.get('name');
          if (namePayload) {
            document.getElementById('query-output').textContent = namePayload;
          }
        </script>
        """
        self._send(200, _page("DOM XSS demo (safe variant)", body))

    # -- /user/<id>/profile ------------------------------------------------
    # Real IDOR: no session/auth of any kind — whichever numeric ID is in
    # the path is looked up and returned, no ownership check.
    def _profile(self, path, qs):
        user_id = int(path.split("/")[2])
        row = _DB.execute(
            "SELECT username, email, ssn FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            self._send(404, _page("Not found", "<p>No such user.</p>"))
            return
        username, email, ssn = row
        body = (
            f"<h1>Profile: {html.escape(username)}</h1>"
            f"<p>Email: {html.escape(email)}</p>"
            f"<p>SSN: {html.escape(ssn)}</p>"
            f"<p><i>No authentication/session check was performed to reach this page "
            f"&mdash; that's the bug.</i></p>"
        )
        self._send(200, _page("Profile", body))

    # -- /order/<uuid> -------------------------------------------------
    # Same IDOR bug as /user/<id>/profile, but UUID-keyed instead of a
    # sequential integer — realistic for a well-built app, and a genuine
    # test case for hakuza active's real-sibling-ID cross-reference logic
    # rather than its numeric id-1/id+1000 offset logic. Whichever UUID is
    # in the path gets returned, no ownership check.
    def _order(self, path):
        order_uuid = path.split("/")[2].lower()
        row = _DB.execute(
            "SELECT customer, total, card_last4 FROM orders WHERE uuid = ?", (order_uuid,)
        ).fetchone()
        if row is None:
            self._send(404, _page("Not found", "<p>No such order.</p>"))
            return
        customer, total, card_last4 = row
        body = (
            f"<h1>Order for {html.escape(customer)}</h1>"
            f"<p>Total: ${total:.2f}</p>"
            f"<p>Card on file: **** **** **** {html.escape(card_last4)}</p>"
            f"<p><i>No authentication/session check was performed to reach this page "
            f"&mdash; that's the bug. The UUID can't be brute-forced, but if it's ever "
            f"been linked to (an email, a receipt page, a support ticket, a crawl), "
            f"whoever finds that link can pull this order.</i></p>"
        )
        self._send(200, _page("Order", body))


# -- HTTP request smuggling demo (raw sockets, NOT http.server) ------------
# Runs on a SEPARATE port. Hand-rolled at the byte level on purpose — this
# is the one bug class that http.server's own request parsing would
# normalize/reject before Handler ever saw it, so demonstrating the real
# ambiguity needs direct control over exactly which bytes get read and
# when.
#
# What it reproduces: when both Content-Length and Transfer-Encoding are
# present, this deliberately trusts Content-Length to bound the body read,
# then checks whether what it read forms COMPLETE, valid chunked framing
# (a real chunked body always ends with a "0" terminator chunk). If it
# doesn't — exactly what hakuza active's CL.TE/TE.CL probes send on
# purpose — it keeps waiting on the socket for the rest of what it thinks
# is an incomplete chunked message. Since the probing client already sent
# everything and is just waiting to read a response, that recv() call
# genuinely blocks on real missing bytes until its own timeout — not a
# hardcoded sleep(), the actual signature a real vulnerable parser
# produces. This validates hakuza active's timing-based detector against
# a real hang, not just against "did it avoid a false positive."
def _smuggle_demo_serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(20)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=_smuggle_demo_handle, args=(conn,), daemon=True).start()


def _smuggle_demo_handle(conn):
    conn.settimeout(10)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        header_end = buf.index(b"\r\n\r\n") + 4
        header_bytes, body_so_far = buf[:header_end], buf[header_end:]

        headers = {}
        for line in header_bytes.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower()] = v.strip()

        if b"content-length" in headers and b"transfer-encoding" in headers:
            try:
                cl = int(headers[b"content-length"])
            except ValueError:
                cl = 0
            while len(body_so_far) < cl:
                more = conn.recv(4096)
                if not more:
                    break
                body_so_far += more
            body = body_so_far[:cl]
            # A real, complete chunked body ends with a "0" terminator
            # chunk. hakuza active's probes deliberately send a
            # Content-Length-bounded slice that ISN'T complete chunked
            # framing — this genuinely blocks on that, not a fake sleep.
            looks_complete = body.rstrip(b"\r\n").endswith(b"0")
            if not looks_complete:
                conn.settimeout(5)
                try:
                    conn.recv(4096)  # blocks for real — nothing more is coming
                except Exception:
                    pass

        body = b"OK"
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        conn.sendall(resp)
    except Exception:
        pass
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--port", type=int, default=9911)
    args = parser.parse_args()

    smuggle_port = args.port + 1
    threading.Thread(target=_smuggle_demo_serve, args=(smuggle_port,), daemon=True).start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"HAKUZA Practice Range running at http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    print(f"HTTP smuggling demo (raw sockets) running at http://127.0.0.1:{smuggle_port}/")
    print("This target is intentionally vulnerable. Localhost-only. Do not expose it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
