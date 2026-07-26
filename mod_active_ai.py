"""
mod_active_ai.py — HAKUZA Active-Testing AI Primitives

Provides the AI-escalation, proof-of-concept generation, and safe
script-execution primitives used by `hakuza active` — the live differential
HTTP testing engine implemented elsewhere in the codebase (mod_active.py).

This file is intentionally decoupled from the rest of HAKUZA: it does not
import hakuza.py or any lazy-import machinery, and every function that needs
AI takes an already-constructed `anthropic.Anthropic` client as a parameter.
That keeps the core differential-detection engine fully usable with zero AI
dependency — API-key-less environments still get PoC generation and safe
script execution, they just don't get AI-assisted confirmation or drafting.

Five primitives:
  - ai_confirm_finding    — second opinion on an ambiguous automated signal
  - gen_curl_poc          — shell-safe curl reproduction command
  - gen_python_poc        — standalone requests-based PoC/regression script
  - run_custom_script     — safe subprocess execution (no shell, no policy)
  - draft_ai_test_script  — AI-drafted test script text (never executed here)
"""

import json
import shlex
import subprocess
import sys
import urllib.parse
from typing import Optional

import anthropic

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Match the model identifier already used throughout hakuza.py.
_MODEL = "claude-sonnet-4-6"

_ALLOWED_VERDICTS = {"CONFIRMED", "LIKELY", "UNLIKELY", "FALSE_POSITIVE"}

_EVIDENCE_TRUNCATE = 1200


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_json_object(text: str) -> Optional[str]:
    """Find the first balanced {...} object in text via brace-counting.

    Models sometimes wrap JSON in markdown fences or add surrounding prose;
    this walks from the first '{' and tracks nesting depth (while skipping
    braces inside quoted strings) to find the matching closing brace.
    Returns None if no balanced object is found.
    """
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _response_text(response) -> str:
    """Concatenate all text blocks from a Messages API response."""
    out = ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            out += block.text
    return out


def _strip_code_fence(text: str) -> str:
    """Strip a leading/trailing ``` or ```python markdown fence, if present."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.split("\n")
    lines = lines[1:]  # drop opening fence line
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]  # drop closing fence line
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1. ai_confirm_finding
# ---------------------------------------------------------------------------

def ai_confirm_finding(
    client: "anthropic.Anthropic",
    vuln_class: str,
    param: str,
    url: str,
    payload: str,
    baseline_evidence: str,
    mutated_evidence: str,
) -> dict:
    """Ask Claude for a second opinion on an ambiguous automated signal.

    Used when the caller has a suggestive-but-not-certain result (e.g. a
    boolean-based blind SQLi diff, or an IDOR heuristic hit) and wants a
    human-pentester-style judgment call rather than a rigid template match.
    Truncates evidence defensively even though the caller should already
    have done so. Never raises — any parsing or API failure is caught and
    reported back as an UNLIKELY verdict so the caller can safely treat this
    as "no confirmation available" rather than crash the active-testing run.
    """
    baseline_evidence = (baseline_evidence or "")[:_EVIDENCE_TRUNCATE]
    mutated_evidence = (mutated_evidence or "")[:_EVIDENCE_TRUNCATE]

    system_prompt = (
        "You are a senior penetration tester reviewing an AMBIGUOUS automated "
        "finding — e.g. a boolean-based blind SQLi diff or an IDOR heuristic hit "
        "— that is suggestive but not conclusive. Reason like a human pentester: "
        "does the observed behavior actually indicate the claimed vulnerability, "
        "or is it noise?\n\n"
        "Be conservative. Automated differential HTTP testing produces frequent "
        "false positives from dynamic content, caching, CSRF tokens, timestamps, "
        "session identifiers, ads, and A/B-tested content — this is a real, "
        "documented problem this project has already hit with naive detection "
        "logic. Default to UNLIKELY or FALSE_POSITIVE unless the evidence is "
        "genuinely convincing. Overclaiming vulnerabilities in an automated tool "
        "is worse than under-claiming.\n\n"
        "Respond with STRICT JSON only, containing exactly these keys:\n"
        '  "verdict": one of "CONFIRMED", "LIKELY", "UNLIKELY", "FALSE_POSITIVE"\n'
        '  "reasoning": 1-3 sentences of plain text explaining the verdict\n'
        '  "next_payload": a string suggesting one concrete follow-up payload to '
        "further confirm, or null if verdict is already CONFIRMED/FALSE_POSITIVE "
        "and no further test is useful\n"
        "Return only the JSON object — no markdown fences, no extra prose."
    )

    user_prompt = (
        f"Vulnerability class under investigation: {vuln_class}\n"
        f"Parameter: {param}\n"
        f"URL: {url}\n"
        f"Payload used: {payload}\n\n"
        f"Baseline response evidence:\n{baseline_evidence}\n\n"
        f"Mutated (payload) response evidence:\n{mutated_evidence}\n\n"
        "Does this evidence confirm the vulnerability?"
    )

    try:
        response = client.with_options(timeout=30.0).messages.create(
            model=_MODEL,
            max_tokens=500,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text = _response_text(response)

        json_str = _extract_json_object(raw_text)
        if json_str is None:
            return {
                "verdict": "UNLIKELY",
                "reasoning": "AI confirmation unavailable: no JSON object found in model response",
                "next_payload": None,
            }

        parsed = json.loads(json_str)

        verdict = parsed.get("verdict")
        if verdict not in _ALLOWED_VERDICTS:
            verdict = "UNLIKELY"

        reasoning = parsed.get("reasoning")
        if not isinstance(reasoning, str):
            reasoning = ""

        next_payload = parsed.get("next_payload")
        if next_payload is not None and not isinstance(next_payload, str):
            next_payload = str(next_payload)

        return {
            "verdict": verdict,
            "reasoning": reasoning,
            "next_payload": next_payload,
        }
    except Exception as exc:  # noqa: BLE001 — must never propagate to caller
        return {
            "verdict": "UNLIKELY",
            "reasoning": f"AI confirmation unavailable: {exc}",
            "next_payload": None,
        }


# ---------------------------------------------------------------------------
# 2. gen_curl_poc
# ---------------------------------------------------------------------------

def gen_curl_poc(method: str, url: str, params: dict, headers: dict = None) -> str:
    """Build a single copy-pasteable, shell-safe curl PoC command.

    Params are frequently injection payloads themselves (e.g. `' OR '1'='1`
    or a backtick/`$()` command-injection string) — every dynamic piece of
    the command is run through shlex.quote() so pasting the output into a
    shell never executes anything beyond the intended curl invocation.
    """
    method_upper = (method or "GET").upper()

    query = urllib.parse.urlencode(params or {})
    full_url = f"{url}?{query}" if query else url

    lines = [f"curl -X {shlex.quote(method_upper)} {shlex.quote(full_url)}"]
    for name, value in (headers or {}).items():
        lines.append(f"  -H {shlex.quote(f'{name}: {value}')}")

    return " \\\n".join(lines)


# ---------------------------------------------------------------------------
# 3. gen_python_poc
# ---------------------------------------------------------------------------

def gen_python_poc(
    method: str,
    url: str,
    params: dict,
    vuln_class: str,
    param: str,
    payload: str,
    expected_signal: str,
    verify: bool = True,
) -> str:
    """Return the full text of a standalone, immediately-runnable PoC script.

    Only imports `requests` and stdlib `sys` — runs with nothing but
    `pip install requests`. Checks EXPECTED_SIGNAL as a plain substring of
    the response body and exits 0 on PASS / 1 on FAIL, so it doubles as a
    CI-style regression check. All caller-supplied strings (payload, param,
    url, expected_signal) are embedded via repr() so arbitrary attacker
    payload content can never break out of the generated source.

    `verify=False` is needed for checks like the exposed-Kubernetes-API one,
    whose targets (kubelet, K8s API server) are near-universally
    self-signed — without it the generated PoC raises SSLError on almost
    any real target regardless of whether the finding is still live.
    """
    method_upper = (method or "GET").upper()
    if method_upper == "POST":
        request_call = "requests.post(URL, data=PARAMS, timeout=15, verify=VERIFY)"
    else:
        request_call = "requests.get(URL, params=PARAMS, timeout=15, verify=VERIFY)"

    header = (
        "#!/usr/bin/env python3\n"
        f"# PoC: {vuln_class!r} vulnerability reproduction\n"
        f"# Parameter: {param!r}\n"
        f"# Payload:   {payload!r}\n"
        f"# Target:    {url!r}\n"
        "# Generated by hakuza active — HAKUZA active-testing engine.\n"
        "# Run: pip install requests && python3 <this file>\n"
    )

    body = f'''
import sys
import warnings
import requests

URL = {url!r}
PARAMS = {params!r}
EXPECTED_SIGNAL = {expected_signal!r}
VERIFY = {verify!r}

if not VERIFY:
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def main() -> int:
    try:
        resp = {request_call}
    except requests.RequestException as exc:
        print(f"[FAIL] Request failed: {{exc}}")
        return 1

    print(f"Status: {{resp.status_code}}")
    print(f"Body preview: {{resp.text[:300]!r}}")

    if EXPECTED_SIGNAL in resp.text:
        print("[PASS] Vulnerability reproduced")
        return 0

    print("[FAIL] Signal not found -- target may be patched or behavior changed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''

    return header + body


# ---------------------------------------------------------------------------
# 4. run_custom_script
# ---------------------------------------------------------------------------

def run_custom_script(script_path: str, timeout: int = 30) -> dict:
    """Execute a Python script safely and return its outcome as a dict.

    Pure execution primitive — the caller decides whether/when to invoke
    this; no policy decisions are made here. Never uses shell=True and
    never lets an exception propagate: timeouts, a missing script path, and
    any other unexpected failure all come back as the same dict shape.
    """
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        partial_stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        partial_stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "returncode": None,
            "stdout": partial_stdout,
            "stderr": partial_stderr,
            "timed_out": True,
        }
    except FileNotFoundError as exc:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": f"Script not found: {exc}",
            "timed_out": False,
        }
    except Exception as exc:  # noqa: BLE001 — must never propagate to caller
        return {
            "returncode": None,
            "stdout": "",
            "stderr": f"Unexpected error running script: {exc}",
            "timed_out": False,
        }


# ---------------------------------------------------------------------------
# 5. draft_ai_test_script
# ---------------------------------------------------------------------------

def draft_ai_test_script(
    client: "anthropic.Anthropic",
    description: str,
    target_url: str,
    engagement_context: str,
) -> str:
    """Ask Claude to draft a standalone test script from a plain-English description.

    Drafting and execution are deliberately separated — this function never
    executes the script it generates, so the calling code can enforce a
    mandatory human-review step before anything runs on the operator's
    machine. Returns "" on any failure (API error, empty/unusable response);
    never raises.
    """
    system_prompt = (
        "You are a senior penetration tester writing a standalone Python test "
        "script for an authorized security engagement. Given a plain-English "
        "test description, a target URL, and engagement context, write a "
        "complete, standalone, runnable Python script that implements the "
        "described test.\n\n"
        "Requirements:\n"
        "- Use only the `requests` library (via `requests.Session()` so it can "
        "handle cookies and multi-step flows) and the Python standard library. "
        "No other third-party dependencies.\n"
        "- The script must be immediately runnable with `pip install requests`.\n"
        "- Print a clear PASS/FAIL-style result with supporting evidence "
        "(status codes, key response values) — the same spirit as a hand-written "
        "regression PoC.\n"
        "- Do NOT include any destructive operations: no deletions, no payment "
        "or financial state changes beyond the minimum needed to demonstrate the "
        "described logic flaw, and no real data exfiltration.\n"
        "- Return ONLY the raw Python source code. Do not wrap it in markdown "
        "code fences and do not include any explanation before or after the code."
    )

    user_prompt = (
        f"Test description: {description}\n"
        f"Target URL: {target_url}\n"
        f"Engagement context: {engagement_context}\n\n"
        "Write the complete Python test script now."
    )

    try:
        response = client.with_options(timeout=60.0).messages.create(
            model=_MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = _response_text(response).strip()
        if not text:
            return ""
        return _strip_code_fence(text).strip()
    except Exception:  # noqa: BLE001 — must never propagate to caller
        return ""
