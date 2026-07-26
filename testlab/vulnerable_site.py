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
    """
)
_DB.commit()

_DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")
os.makedirs(_DOCS_DIR, exist_ok=True)
with open(os.path.join(_DOCS_DIR, "welcome.txt"), "w") as f:
    f.write("Welcome to the HAKUZA practice range document store.\n")


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
            elif re.match(r"^/user/\d+/profile$", path):
                self._profile(path, qs)
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
              &mdash; IDOR (try /user/1001/profile, /user/2000/profile)</li>
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
            error = f"You have an error in your SQL syntax near: {e}"

        # Deliberately vulnerable: cat is reflected into HTML with no
        # escaping at all (reflected XSS).
        rows_html = "".join(
            f"<tr><td>{r[0]}</td><td>{html.escape(r[1])}</td><td>${r[2]:.2f}</td></tr>"
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
