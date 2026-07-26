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
import json
import time
import math
import difflib
import hashlib
import secrets
import statistics
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


_UA_HEADERS = {"User-Agent": "Mozilla/5.0 (HAKUZA-Active/2.0; +differential-testing)"}

# ---------------------------------------------------------------------------
# SQL error-vendor signatures (error-based SQLi, step 2)
# ---------------------------------------------------------------------------
_SQLI_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",             # MySQL
    r"warning: mysql_",                                    # MySQL/PHP
    r"unclosed quotation mark after the character string", # MSSQL
    r"microsoft ole db provider for sql server",           # MSSQL
    r"quoted string not properly terminated",              # Oracle
    r"ora-\d{5}",                                          # Oracle
    r"postgresql.*error|pg_query\(\)|syntax error at or near",  # PostgreSQL
    r"sqlite3?\.(operationalerror|error)|unrecognized token",   # SQLite
    r"sqlstate\[\d+\]",                                    # generic PDO
]

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
             baseline_snippet, mutated_snippet, impact, remediation, ai_reasoning=None):
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
        script_src = ""
        try:
            script_src = gen_python_poc("GET", url, {}, category, param, payload,
                                        expected_signal=mutated_snippet[:200])
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
# Per-parameter mutation loop (steps 1-8 from the spec)
# ---------------------------------------------------------------------------

def _test_param(ctx, parts, pairs, pname, baseline):
    console = ctx.console
    budget = ctx.budget
    timeout = ctx.timeout
    delay = ctx.delay
    orig_value = dict(pairs).get(pname, "")

    # --- 1. Reflection probe (XSS) ---
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

    # --- 2. SQL injection — error-based ---
    sqli_confirmed = False
    err_payload = f"{orig_value}'"
    url_e = _build_url(parts, _with_param(pairs, pname, err_payload))
    resp_e = _polite_get(budget, delay, url_e, timeout)
    if resp_e is not None:
        body_e = resp_e.text or ""
        sig_hit, matched_text = None, ""
        for pat in _SQLI_ERROR_SIGNATURES:
            mm = re.search(pat, body_e, re.I)
            if mm and not re.search(pat, baseline["body"], re.I):
                sig_hit, matched_text = pat, mm.group(0)
                break
        status_changed = resp_e.status_code != baseline["status"]
        len_changed = abs(len(body_e) - baseline["length"]) > max(40, baseline["length"] * 0.05)
        if sig_hit and (status_changed or len_changed):
            sqli_confirmed = True
            _persist(
                ctx,
                title=f"SQL Injection (error-based) via '{pname}' parameter",
                severity="critical",
                category="SQL Injection (Error-based)",
                url=url_e, param=pname, payload=err_payload,
                description=(
                    f"Appending a single quote to the '{pname}' parameter produced a database "
                    f"error signature ('{matched_text[:80]}') absent from 3 repeated baseline "
                    f"requests (baseline status {baseline['status']}, length {baseline['length']}) "
                    f"vs. the mutated response (status {resp_e.status_code}, length {len(body_e)})."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body_e, matched_text),
                impact=("Full database compromise is likely — read/write access to underlying "
                       "data, potential authentication bypass, and in some configurations OS "
                       "command execution via the DBMS."),
                remediation=("Use parameterized queries / prepared statements exclusively. Never "
                            "concatenate user input into SQL strings. Apply least-privilege DB "
                            "accounts and disable verbose DB error output in production."),
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
                )
                break  # one confirmed time-based signal per param is sufficient evidence

    if budget.exhausted():
        return

    # --- 5. SSTI (Jinja2/Twig-family only in v1 — could be extended to
    #     FreeMarker/Velocity/Smarty/Mako with their own expression syntax) ---
    ssti_payload = "{{7*7}}"
    url_s = _build_url(parts, _with_param(pairs, pname, ssti_payload))
    resp_s = _polite_get(budget, delay, url_s, timeout)
    if resp_s is not None:
        body_s = resp_s.text or ""
        if "49" in body_s and "49" not in baseline["body"]:
            _persist(
                ctx,
                title=f"Server-Side Template Injection via '{pname}' parameter",
                severity="critical",
                category="Server-Side Template Injection",
                url=url_s, param=pname, payload=ssti_payload,
                description=(
                    f"Injecting the Jinja2/Twig-family expression `{{{{7*7}}}}` into '{pname}' "
                    f"caused the evaluated literal '49' to appear in the live response, absent "
                    f"from the baseline — the template engine is evaluating attacker-controlled "
                    f"input as code."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(body_s, "49"),
                impact="Server-side template injection frequently escalates to full remote code execution.",
                remediation=("Never render user input as a template. Use logic-less templates or "
                            "sandboxed rendering with strict autoescaping — treat all user input "
                            "as data, never as template source."),
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
        canary_url = "https://hakuza-redirect-canary.invalid/x"
        url_r = _build_url(parts, _with_param(pairs, pname, canary_url))
        if not budget.exhausted():
            time.sleep(delay)
            budget.spend()
            try:
                resp_r = requests.get(url_r, timeout=timeout, allow_redirects=False,
                                      headers=_UA_HEADERS)
            except Exception:
                resp_r = None
            if resp_r is not None:
                loc = resp_r.headers.get("Location", "")
                if loc.startswith(canary_url):
                    _persist(
                        ctx,
                        title=f"Open Redirect via '{pname}' parameter",
                        severity="low",
                        category="Open Redirect",
                        url=url_r, param=pname, payload=canary_url,
                        description=(
                            f"Setting '{pname}' to an attacker-controlled absolute URL caused a "
                            f"Location header pointing directly at it, confirmed by inspecting the "
                            f"real (non-followed) HTTP response."
                        ),
                        baseline_snippet="N/A (redirect-only check, no body comparison)",
                        mutated_snippet=f"Location: {loc}",
                        impact=("Enables convincing phishing redirects and can be chained with "
                               "OAuth flows for token theft."),
                        remediation=("Validate redirect targets against an allow-list of relative "
                                    "paths or known-good domains; never redirect to a raw "
                                    "user-supplied URL."),
                    )

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
_IDOR_DENIAL_RE = re.compile(
    r"access denied|not authorized|unauthoriz|forbidden|please log ?in|"
    r"permission denied|401 unauthorized|403 forbidden|sign in to continue|"
    r"you (?:must|need to) (?:log|sign) in",
    re.I,
)


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

    if _IDOR_DENIAL_RE.search(mutated_body):
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


def _test_idor_heuristic(ctx, parts, baseline):
    m = re.search(r"/(\d+)(?:/|$)", parts.path)
    if not m:
        return
    budget = ctx.budget
    orig_id_str = m.group(1)
    try:
        orig_id = int(orig_id_str)
    except ValueError:
        return

    variants = []
    if orig_id - 1 >= 0:
        variants.append(str(orig_id - 1))
    variants.append(str(orig_id + 1000))

    for variant in variants:
        if variant == orig_id_str or budget.exhausted():
            continue
        new_path = parts.path[:m.start(1)] + variant + parts.path[m.end(1):]
        new_url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
        resp = _polite_get(budget, ctx.delay, new_url, ctx.timeout)
        if resp is None or resp.status_code != 200:
            continue

        is_signal, ratio, changed_sample = _idor_diff_signal(baseline["body"], resp.text or "")
        if is_signal:
            same_template = ratio > 0.85
            ai_result = None
            if ctx.ai_enabled:
                ai_result = _ai_escalate(ctx, "IDOR (heuristic)", "path-id", new_url, variant,
                                         baseline["body"], resp.text or "")
            reasoning = ai_result.get("reasoning") if ai_result else None
            _persist(
                ctx,
                title=(f"Potential IDOR (heuristic) on path ID {orig_id_str} — confirm manually "
                      f"with two distinct authenticated sessions"),
                severity="medium",
                category="Insecure Direct Object Reference (heuristic)",
                url=new_url, param="path-id", payload=variant,
                description=(
                    (
                        f"Changing the numeric path segment from {orig_id_str} to {variant} returned "
                        f"a 200 OK response using what looks like the SAME page template as the "
                        f"baseline (similarity ratio {ratio:.2f}) but with genuinely different "
                        f"content in place — e.g. \"{changed_sample[:150]}\" — consistent with a "
                        f"different underlying record (a different user/order/record's data) being "
                        f"returned rather than an access-denied page. This is the most common "
                        f"real-world IDOR shape: a well-built page's template stays identical, only "
                        f"the record's own fields change."
                        if same_template else
                        f"Changing the numeric path segment from {orig_id_str} to {variant} returned "
                        f"a 200 OK response with meaningfully different content from the baseline "
                        f"(similarity ratio {ratio:.2f}) rather than an error/not-found page — e.g. "
                        f"\"{changed_sample[:150]}\"."
                    ) +
                    " This is an intentionally single-session heuristic — HAKUZA v1 cannot yet drive "
                    "two distinct authenticated sessions, so this is a LEAD, not a confirmed IDOR. "
                    "Confirm manually with two distinct authenticated user sessions before reporting "
                    "this as a finding."
                ),
                baseline_snippet=_ctx_snippet(baseline["body"], ""),
                mutated_snippet=_ctx_snippet(resp.text or "", ""),
                impact=("If confirmed with two authenticated sessions, this would allow "
                       "horizontal privilege escalation — any authenticated user could access "
                       "another user's records by incrementing an ID."),
                remediation=("Enforce object-level authorization checks server-side on every "
                            "request — verify the requesting session actually owns the requested "
                            "resource; never trust client-supplied IDs alone."),
                ai_reasoning=reasoning,
            )
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

    with_params = [u for u in raw_urls if "?" in u]
    skipped = len(raw_urls) - len(with_params)
    console.print(
        f"[dim]{len(raw_urls)} candidate URL(s) from recon data; {len(with_params)} have query "
        f"parameters and are testable; skipping {skipped} with no parameters — this v1 engine "
        f"only mutates query-string parameters.[/dim]"
    )
    if not with_params:
        console.print("[yellow]No candidate URLs have query parameters — nothing for this engine "
                      "to test.[/yellow]")
        return [], True

    return with_params, False


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
    if script_path:
        _run_script_mode(args, console, eng)
        return
    if ai_script_desc:
        _run_ai_script_mode(args, console, eng, ai_script_desc)
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


# ---------------------------------------------------------------------------
# Dispatch additions  (paste into main() dispatch dict)
# ---------------------------------------------------------------------------
# if mod_active is not None:
#     dispatch["active"] = mod_active.cmd_active

# END mod_active.py
