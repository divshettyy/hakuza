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

Or just: hakuza active --all --depth deep   (after `hakuza wayback` /
manually seeding these URLs into the engagement's recon data — see README).
"""

import argparse
import html
import os
import re
import sqlite3
import sys
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--port", type=int, default=9911)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"HAKUZA Practice Range running at http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    print("This target is intentionally vulnerable. Localhost-only. Do not expose it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
