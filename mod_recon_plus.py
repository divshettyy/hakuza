"""
mod_recon_plus.py — HAKUZA Enhanced Reconnaissance & Workflow Module

Adds: cmd_wayback, cmd_secrets, cmd_fuzz, cmd_wizard, cmd_scope, cmd_config (replacement)

Drop into the same directory as hakuza.py.  The bottom of this file shows the
argparse additions and dispatch table entries needed in hakuza.py's build_parser()
and main() functions.
"""

# ---------------------------------------------------------------------------
# stdlib + optional deps
# ---------------------------------------------------------------------------
import os
import sys
import re
import json
import time
import shutil
import subprocess
import fnmatch
from datetime import datetime
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# HAKUZA core imports  (available when this module is loaded from hakuza.py context)
# These names are resolved at call-time from the hakuza module's global namespace.
# If loaded standalone for testing, they are imported lazily.
# ---------------------------------------------------------------------------

def _hakuza():
    """Lazy import of the hakuza module so this file is importable standalone."""
    import importlib
    return importlib.import_module("hakuza")


def _n(attr):
    """Fetch an attribute from the hakuza module at call-time."""
    return getattr(_hakuza(), attr)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_engagement(console):
    """Delegate to hakuza._require_engagement."""
    return _n("_require_engagement")(console)


def _get_client_or_none():
    return _n("get_client_or_none")()


def _get_client():
    return _n("get_client")()


def _stream(client, messages, max_tokens, console):
    return _n("stream_to_console")(client, messages, max_tokens, console)


def _ask(client, prompt, max_tokens=1500):
    return _n("ask_claude")(client, prompt, max_tokens)


def _add_finding(eng_id, **kwargs):
    return _n("add_finding")(eng_id, **kwargs)


def _add_recon(eng_id, data_type, content, source=None):
    return _n("add_recon_data")(eng_id, data_type, content, source)


def _run_tool(cmd, timeout=120, input_data=None):
    return _n("run_tool")(cmd, timeout, input_data)


def _check_tools():
    return _n("check_tools")()


def _extract_domain(target):
    return _n("_extract_domain")(target)


# Rich helpers resolved lazily
def _console_module():
    from rich.console import Console
    return Console


def _rich():
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    return Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box


# ---------------------------------------------------------------------------
# URL collection utilities (used by cmd_wayback)
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/api/v\d|/v\d/|/graphql|/\.env|/backup|/\.git|/config|"
    r"/actuator|/swagger|/metrics|/debug|/console|/manage|/phpmyadmin|"
    r"/wp-admin|/wp-login|/xmlrpc)",
    re.IGNORECASE,
)

_PARAM_URL_RE = re.compile(r"\?[^=\s]+=[^&\s]+")

_INTERESTING_EXT_RE = re.compile(
    r"\.(php|asp|aspx|jsp|jspx|bak|sql|config|conf|env|xml|log|backup|tar|gz|zip|rar)(\?|$)",
    re.IGNORECASE,
)

_API_PATH_RE = re.compile(r"/(api|v\d+|graphql|rest|gql|rpc)/", re.IGNORECASE)


def _categorise_urls(urls: list) -> dict:
    """Bucket a list of URL strings into categories."""
    cats = {
        "params": [],
        "admin_sensitive": [],
        "interesting_ext": [],
        "api_endpoints": [],
        "other": [],
    }
    seen = set()
    for url in urls:
        url = url.strip()
        if not url or url in seen:
            continue
        seen.add(url)
        if _PARAM_URL_RE.search(url):
            cats["params"].append(url)
        if _SENSITIVE_PATH_RE.search(url):
            cats["admin_sensitive"].append(url)
        if _INTERESTING_EXT_RE.search(url):
            cats["interesting_ext"].append(url)
        if _API_PATH_RE.search(url):
            cats["api_endpoints"].append(url)
        if not any([
            _PARAM_URL_RE.search(url),
            _SENSITIVE_PATH_RE.search(url),
            _INTERESTING_EXT_RE.search(url),
            _API_PATH_RE.search(url),
        ]):
            cats["other"].append(url)
    return cats


def _scan_url_for_secrets(url: str) -> list:
    """Check if a URL itself leaks secrets in query params."""
    found = []
    patterns = [
        ("JWT in URL", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
        ("AWS key in URL", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("Generic API key", re.compile(r"[aA][pP][iI][_\-]?[kK][eE][yY][=:][0-9A-Za-z]{16,}")),
        ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ]
    for label, pat in patterns:
        if pat.search(url):
            found.append({"type": label, "url": url})
    return found


# ---------------------------------------------------------------------------
# Secret scanning patterns (used by cmd_secrets)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9A-Za-z/+]{40}['\"]")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Generic API Key", re.compile(r"(?i)['\"]?api[_\-]?key['\"]?\s*[=:]\s*['\"][0-9A-Za-z\-_]{20,}['\"]")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Password in code", re.compile(r"(?i)password\s*[=:]\s*['\"][^'\"]{6,}['\"]")),
    ("Firebase URL", re.compile(r"https?://[a-zA-Z0-9\-]+\.firebaseio\.com")),
    ("Private key header", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("MongoDB URI", re.compile(r"mongodb(\+srv)?://[^\s'\"]+")),
    ("SMTP creds", re.compile(r"(?i)smtp.{0,30}password\s*[=:]\s*['\"][^'\"]{4,}['\"]")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_=]{20,}")),
    ("Basic auth in URL", re.compile(r"https?://[^:@\s]+:[^:@\s]+@")),
    ("Hardcoded secret", re.compile(r"(?i)(secret|token|auth)[_\-]?[kK]ey\s*[=:]\s*['\"][A-Za-z0-9\-_]{16,}['\"]")),
]

EXPOSED_FILE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/config",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/config.bak",
    "/wp-config.php.bak",
    "/.htpasswd",
    "/web.config.bak",
    "/application.properties",
    "/application.yml",
    "/settings.py",
]


def _http_get(url: str, timeout: int = 10) -> tuple:
    """
    Fetch URL content.  Returns (status_code: int, text: str, headers: dict).
    Uses requests if available, else curl subprocess.
    """
    if HAS_REQUESTS:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (HAKUZA/2.0)"})
            return resp.status_code, resp.text, dict(resp.headers)
        except Exception as exc:
            return 0, str(exc), {}
    else:
        stdout, stderr, rc = _run_tool(
            ["curl", "-sk", "-w", "\n%{http_code}", "-L", "--max-time", str(timeout), url],
            timeout=timeout + 5,
        )
        lines = stdout.rsplit("\n", 1)
        body = lines[0] if len(lines) > 1 else stdout
        try:
            status = int(lines[-1].strip()) if len(lines) > 1 else 0
        except ValueError:
            status = 0
        return status, body, {}


def _fetch_js_urls(base_url: str, console) -> list:
    """
    Fetch the HTML of base_url and extract all script src URLs.
    Returns list of absolute JS URLs.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()
    status, body, _ = _http_get(base_url)
    if status == 0 or not body:
        console.print(f"  [yellow]Could not fetch {base_url}[/yellow]")
        return []
    from urllib.parse import urljoin, urlparse
    parsed_base = urlparse(base_url)
    base = f"{parsed_base.scheme}://{parsed_base.netloc}"
    js_urls = []
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
        src = match.group(1)
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("//"):
            js_urls.append(f"{parsed_base.scheme}:{src}")
        else:
            js_urls.append(urljoin(base_url, src))
    console.print(f"  [dim]Found {len(js_urls)} script tags in {base_url}[/dim]")
    return js_urls


def _scan_text_for_secrets(text: str, source: str = "") -> list:
    """Scan arbitrary text content with SECRET_PATTERNS. Returns list of hit dicts."""
    hits = []
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0)
            if len(snippet) > 120:
                snippet = snippet[:120] + "..."
            hits.append({
                "type": label,
                "snippet": snippet,
                "source": source,
                "line": text.count("\n", 0, m.start()) + 1,
            })
    return hits


# ---------------------------------------------------------------------------
# cmd_wayback
# ---------------------------------------------------------------------------

def cmd_wayback(args, console) -> None:
    """
    hakuza wayback [--domain <override>] [--filter endpoints|params|secrets|all] [--save]

    Mine historical URLs for attack surface via waybackurls / gau / katana + AI analysis.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()
    eng = _require_engagement(console)

    target = getattr(args, "domain", None) or eng["target"]
    domain = _extract_domain(target)
    url_filter = getattr(args, "filter", "all") or "all"
    save_flag = getattr(args, "save", False)

    eng_dir = _n("ENGAGEMENTS_DIR") / eng["name"]
    recon_dir = eng_dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    console.print(
        Panel(
            f"[bold]Domain:[/bold]  {domain}\n"
            f"[bold]Filter:[/bold]  {url_filter}\n"
            f"[bold]Save:[/bold]    {'yes' if save_flag else 'no'}",
            title="[bold cyan]  HAKUZA Wayback — Historical URL Mining[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    all_urls: list = []

    # --- 1. waybackurls ---
    if shutil.which("waybackurls"):
        console.print("[cyan]  Running waybackurls...[/cyan]")
        stdout, _, rc = _run_tool(["waybackurls", domain], timeout=120)
        if stdout:
            wb_urls = [u.strip() for u in stdout.splitlines() if u.strip().startswith("http")]
            console.print(f"  [green]waybackurls: {len(wb_urls)} URLs[/green]")
            all_urls.extend(wb_urls)
    elif shutil.which("gau"):
        console.print("[cyan]  waybackurls not found — trying gau...[/cyan]")
        stdout, _, rc = _run_tool(["gau", domain], timeout=120)
        if stdout:
            gau_urls = [u.strip() for u in stdout.splitlines() if u.strip().startswith("http")]
            console.print(f"  [green]gau: {len(gau_urls)} URLs[/green]")
            all_urls.extend(gau_urls)
    else:
        console.print("[yellow]  Neither waybackurls nor gau installed — using AI URL prediction.[/yellow]")
        client_ai = _get_client_or_none()
        if client_ai:
            predicted_raw = _ask(
                client_ai,
                f"Predict 40 historically common URL patterns for the domain '{domain}'. "
                f"Focus on: API endpoints, admin paths, backup files, authentication URLs, "
                f"common CMS paths, configuration endpoints. Return only absolute URLs "
                f"(https://{domain}/...), one per line, no explanations.",
                max_tokens=800,
            )
            predicted = [u.strip() for u in predicted_raw.splitlines() if u.strip().startswith("http")]
            console.print(f"  [green]AI-predicted: {len(predicted)} URLs[/green]")
            all_urls.extend(predicted)

    # --- 2. katana JS crawl ---
    if shutil.which("katana"):
        console.print("[cyan]  Running katana (JS-aware crawl, depth=3)...[/cyan]")
        stdout, _, rc = _run_tool(
            ["katana", "-u", target, "-depth", "3", "-jc", "-silent", "-nc"],
            timeout=180,
        )
        if stdout:
            katana_urls = [u.strip() for u in stdout.splitlines() if u.strip().startswith("http")]
            console.print(f"  [green]katana: {len(katana_urls)} URLs[/green]")
            all_urls.extend(katana_urls)
    else:
        console.print("  [dim]katana not installed — skipping JS crawl[/dim]")

    if not all_urls:
        console.print("[yellow]No URLs collected.[/yellow]")
        return

    # De-duplicate
    all_urls = list(dict.fromkeys(all_urls))
    console.print(f"\n[bold]Total unique URLs:[/bold] {len(all_urls)}")

    # --- 3. Categorise ---
    cats = _categorise_urls(all_urls)

    # --- 4. Secret scanning in URLs ---
    url_secrets = []
    for url in all_urls:
        url_secrets.extend(_scan_url_for_secrets(url))

    # --- 5. Display results ---
    console.print()
    console.print(Rule("[bold]URL Categories[/bold]", style="dim"))

    category_map = {
        "params": ("URLs with Parameters", "yellow"),
        "admin_sensitive": ("Admin / Sensitive Paths", "red"),
        "interesting_ext": ("Interesting File Extensions", "orange3"),
        "api_endpoints": ("API Endpoints", "cyan"),
    }

    if url_filter == "all":
        show_cats = list(category_map.keys())
    elif url_filter == "endpoints":
        show_cats = ["admin_sensitive", "api_endpoints"]
    elif url_filter == "params":
        show_cats = ["params"]
    elif url_filter == "secrets":
        show_cats = []  # only show URL secrets below
    else:
        show_cats = list(category_map.keys())

    for cat_key in show_cats:
        items = cats.get(cat_key, [])
        label, color = category_map[cat_key]
        if not items:
            continue
        tbl = Table(
            title=f"[{color}]{label} ({len(items)})[/{color}]",
            box=box.SIMPLE,
            show_header=False,
            expand=False,
        )
        tbl.add_column("URL", overflow="fold", max_width=120)
        for u in items[:30]:
            tbl.add_row(u)
        if len(items) > 30:
            tbl.add_row(f"[dim]... and {len(items)-30} more[/dim]")
        console.print(tbl)

    if url_secrets:
        console.print()
        console.print(Rule("[bold red]Secrets Found in URLs[/bold red]", style="red"))
        for s in url_secrets[:20]:
            console.print(f"  [red]{s['type']}[/red]  {s['url'][:120]}")

    # --- 6. Save to DB ---
    interesting_urls = (
        cats["params"] + cats["admin_sensitive"] +
        cats["interesting_ext"] + cats["api_endpoints"]
    )
    if interesting_urls:
        _add_recon(eng["id"], "wayback_urls", "\n".join(interesting_urls[:500]), "wayback")
        console.print(f"\n[green]Saved {len(interesting_urls[:500])} interesting URLs to engagement DB.[/green]")

    if url_secrets:
        for s in url_secrets:
            _add_recon(eng["id"], "url_secret", json.dumps(s), "wayback_secret_scan")

    # Save to file if requested
    if save_flag:
        save_path = recon_dir / f"{domain}_wayback_{timestamp}.txt"
        save_path.write_text("\n".join(all_urls), encoding="utf-8")
        console.print(f"[green]All URLs saved to:[/green] {save_path}")

    # --- 7. AI analysis ---
    console.print()
    console.print(Rule("[bold cyan]AI Attack Surface Analysis[/bold cyan]", style="dim cyan"))
    client_ai = _get_client_or_none()
    if not client_ai:
        console.print("[dim]Set ANTHROPIC_API_KEY to enable AI analysis.[/dim]")
    else:
        sample_interesting = interesting_urls[:60]
        ai_prompt = (
            f"Given these historical/crawled URLs from '{domain}' (BFSI target):\n\n"
            + "\n".join(f"  {u}" for u in sample_interesting)
            + f"\n\nAlso found {len(url_secrets)} secrets in URLs.\n\n"
            f"Identify:\n"
            f"1. The 5 most valuable attack targets and why\n"
            f"2. Any parameter patterns suggesting SQLi, IDOR, or SSRF\n"
            f"3. Endpoints likely to have authentication bypasses\n"
            f"4. Recommended manual testing order\n"
            f"5. Any BFSI-specific sensitive patterns\n"
            f"Be specific and actionable."
        )
        _stream(client_ai, [{"role": "user", "content": ai_prompt}], 800, console)

    console.print()
    console.print(
        Panel(
            f"[bold green]Wayback mining complete![/bold green]\n\n"
            f"Total URLs: {len(all_urls)}  |  "
            f"With params: {len(cats['params'])}  |  "
            f"Admin/sensitive: {len(cats['admin_sensitive'])}  |  "
            f"API endpoints: {len(cats['api_endpoints'])}\n"
            f"Secrets in URLs: {len(url_secrets)}",
            title="[bold]Wayback Summary[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_secrets
# ---------------------------------------------------------------------------

def cmd_secrets(args, console) -> None:
    """
    hakuza secrets [--url <target>] [--js-only] [--deep]

    Hunt for exposed secrets: JS files, git exposure, env files, backup files.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()
    eng = _require_engagement(console)

    target = getattr(args, "url", None) or eng["target"]
    js_only = getattr(args, "js_only", False)
    deep = getattr(args, "deep", False)

    from urllib.parse import urlparse
    parsed = urlparse(target if target.startswith("http") else f"https://{target}")
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    console.print(
        Panel(
            f"[bold]Target:[/bold]  {base_url}\n"
            f"[bold]Mode:[/bold]    {'JS files only' if js_only else 'Full secret scan'}"
            f"{'  +  Deep' if deep else ''}",
            title="[bold cyan]  HAKUZA Secrets Hunter[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    all_findings = []

    # --- 1. JS file scanning ---
    console.print()
    console.print(Rule("[bold]JavaScript File Analysis[/bold]", style="dim"))
    js_urls = _fetch_js_urls(base_url, console)
    if deep:
        # Also try common JS paths
        common_js = [
            f"{base_url}/app.js", f"{base_url}/main.js", f"{base_url}/bundle.js",
            f"{base_url}/static/js/main.chunk.js", f"{base_url}/assets/index.js",
            f"{base_url}/js/app.js", f"{base_url}/dist/bundle.js",
        ]
        js_urls = list(dict.fromkeys(js_urls + common_js))

    for js_url in js_urls[:25]:
        status, body, _ = _http_get(js_url, timeout=8)
        if status == 200 and body:
            hits = _scan_text_for_secrets(body, js_url)
            if hits:
                console.print(f"  [red]SECRETS in {js_url[:80]}:[/red]")
                for h in hits[:5]:
                    console.print(f"    [{h['type']}] line {h['line']}: {h['snippet'][:80]}")
                all_findings.extend(hits)
            else:
                console.print(f"  [green]Clean:[/green] {js_url[:80]}")

    if not js_only:
        # --- 2. Exposed files check ---
        console.print()
        console.print(Rule("[bold]Exposed File Check[/bold]", style="dim"))
        check_paths = EXPOSED_FILE_PATHS[:]
        if deep:
            check_paths += [
                "/config/database.yml", "/config/secrets.yml",
                "/.aws/credentials", "/docker-compose.yml",
                "/Dockerfile", "/.travis.yml", "/circle.yml",
            ]

        exposed_tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        exposed_tbl.add_column("Path", style="yellow")
        exposed_tbl.add_column("Status", width=8)
        exposed_tbl.add_column("Finding", style="red")

        exposed_count = 0
        for fpath in check_paths:
            full_url = base_url.rstrip("/") + fpath
            status, body, headers = _http_get(full_url, timeout=6)
            if status == 200 and body and len(body) > 10:
                hits = _scan_text_for_secrets(body, full_url)
                finding_summary = f"{len(hits)} secret(s)" if hits else "Content exposed"
                exposed_tbl.add_row(fpath, f"[red]{status}[/red]", finding_summary)
                exposed_count += 1
                all_findings.extend(hits)
                # Add as a proper finding
                _add_finding(
                    eng["id"],
                    title=f"Exposed Sensitive File: {fpath}",
                    severity="high" if hits else "medium",
                    url=full_url,
                    description=f"Sensitive file {fpath} is publicly accessible at {full_url}. "
                                f"Content length: {len(body)} bytes.",
                    evidence=body[:500],
                    impact="Exposed configuration, credentials, or source code could allow full system compromise.",
                    remediation=f"Restrict access to {fpath} via server configuration. "
                                f"Add to .gitignore and rotate any exposed credentials immediately.",
                    tool="hakuza-secrets",
                )
                _add_recon(eng["id"], "exposed_file", full_url, "secrets-scan")
            elif status == 200:
                exposed_tbl.add_row(fpath, "[yellow]200[/yellow]", "Empty/minimal response")
            # Skip non-200 silently (expected)

        if exposed_count:
            console.print(exposed_tbl)
        else:
            console.print("  [green]No exposed sensitive files found.[/green]")

        # --- 3. Git exposure ---
        console.print()
        console.print(Rule("[bold].git Exposure Check[/bold]", style="dim"))
        git_status, git_body, _ = _http_get(f"{base_url}/.git/config", timeout=6)
        if git_status == 200 and "[core]" in (git_body or ""):
            console.print(f"  [bold red]CRITICAL: .git/config exposed at {base_url}/.git/config[/bold red]")
            console.print(f"  [dim]{git_body[:200]}[/dim]")
            _add_finding(
                eng["id"],
                title=".git Repository Exposed",
                severity="critical",
                url=f"{base_url}/.git/config",
                description="The .git directory is publicly accessible. An attacker can reconstruct "
                            "the entire source code including secrets, credentials, and history.",
                evidence=git_body[:500],
                cvss_score=9.8,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe="CWE-538",
                impact="Full source code disclosure, credential exposure, potential RCE via source analysis.",
                remediation="Block access to /.git/ in web server config. "
                            "Use 'git filter-branch' or BFG to purge secrets from history.",
                tool="hakuza-secrets",
            )
            _add_recon(eng["id"], "git_exposed", f"{base_url}/.git/config", "secrets-scan")
        else:
            console.print(f"  [green].git/config not exposed (HTTP {git_status})[/green]")

    # --- 4. Deduplicate and display all findings ---
    if all_findings:
        console.print()
        console.print(Rule(f"[bold red]Total Secrets Found: {len(all_findings)}[/bold red]", style="red"))
        tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold red", expand=False)
        tbl.add_column("Type", style="red", width=22)
        tbl.add_column("Source", overflow="ellipsis", max_width=55)
        tbl.add_column("Line", width=6, justify="right")
        tbl.add_column("Snippet", overflow="fold", max_width=55)
        for h in all_findings[:40]:
            tbl.add_row(
                h["type"],
                h.get("source", "")[:55],
                str(h.get("line", "-")),
                h.get("snippet", "")[:55],
            )
        console.print(tbl)

        # Save to DB
        _add_recon(eng["id"], "secrets", json.dumps(all_findings[:100]), "hakuza-secrets")

        # Add consolidated finding
        if len(all_findings) > 0:
            _add_finding(
                eng["id"],
                title=f"Secrets Exposed in JavaScript/Files ({len(all_findings)} hits)",
                severity="high",
                url=base_url,
                description=f"Secret scanning found {len(all_findings)} potential secrets across "
                            f"JavaScript files and exposed configuration files at {base_url}.",
                evidence="\n".join(
                    f"[{h['type']}] {h.get('source','')} L{h.get('line','')} — {h.get('snippet','')[:80]}"
                    for h in all_findings[:20]
                ),
                impact="Exposed secrets may allow direct account compromise, infrastructure access, "
                       "or lateral movement across systems.",
                remediation="Remove secrets from client-side JS. Use server-side environment variables. "
                            "Rotate all exposed credentials immediately. Implement pre-commit secret scanning.",
                cwe="CWE-312",
                tool="hakuza-secrets",
            )
    else:
        console.print()
        console.print("[green]No secrets found.[/green]")

    console.print()
    console.print(
        Panel(
            f"[bold]{'Secrets found: ' + str(len(all_findings)) if all_findings else 'No secrets detected'}[/bold]\n"
            f"JS files scanned: {len(js_urls)}\n"
            f"Exposed paths checked: {len(EXPOSED_FILE_PATHS)}\n"
            f"[dim]Findings saved to engagement DB.[/dim]",
            title="[bold]Secrets Scan Complete[/bold]",
            border_style="green" if not all_findings else "red",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_fuzz
# ---------------------------------------------------------------------------

_TECH_WORDLISTS = {
    "spring":  ["/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
                "/actuator/mappings", "/v3/api-docs", "/swagger-ui.html"],
    "php":     ["/wp-admin/", "/wp-login.php", "/admin.php", "/config.php",
                "/phpinfo.php", "/phpmyadmin/", "/adminer.php"],
    "node":    ["/node_modules/", "/.npmrc", "/package.json", "/npm-debug.log"],
    "django":  ["/admin/", "/api/", "/static/", "/media/", "/__debug__/"],
    "laravel": ["/telescope", "/horizon", "/.env", "/storage/logs/laravel.log"],
}

_DEFAULT_DIRS = [
    "admin", "api", "login", "dashboard", "config", "backup", "test",
    "dev", "staging", "upload", "uploads", "files", "static", "assets",
    "v1", "v2", "graphql", "docs", "swagger", "metrics", "health",
    ".env", ".git", "robots.txt", "sitemap.xml",
]

_DEFAULT_PARAMS = [
    "id", "user", "file", "path", "url", "redirect", "next", "page",
    "search", "query", "cmd", "exec", "lang", "format", "type", "token",
]

_DEFAULT_API = [
    "users", "user", "accounts", "account", "profile", "settings", "admin",
    "auth", "login", "logout", "register", "token", "refresh", "reset",
    "password", "upload", "files", "data", "export", "import", "webhook",
]


def _detect_tech(target_url: str, console) -> str:
    """Detect technology stack from HTTP headers and body. Returns tech label."""
    status, body, headers = _http_get(target_url, timeout=8)
    if status == 0:
        return "generic"

    headers_str = json.dumps({k.lower(): v for k, v in headers.items()})
    body_lower = (body or "").lower()[:3000]
    all_text = headers_str + body_lower

    if "x-powered-by" in headers_str and "spring" in headers_str:
        return "spring"
    if "laravel" in all_text or "laravel_session" in all_text:
        return "laravel"
    if "django" in all_text or "csrfmiddlewaretoken" in all_text:
        return "django"
    if "x-powered-by: php" in headers_str.lower() or "<?php" in body_lower:
        return "php"
    if "node" in headers_str or "express" in headers_str:
        return "node"
    if "actuator" in body_lower or "spring" in body_lower:
        return "spring"
    return "generic"


def _parse_ffuf_json(output: str) -> list:
    """Parse ffuf -json output. Returns list of result dicts."""
    results = []
    try:
        data = json.loads(output)
        for item in data.get("results", []):
            results.append({
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "lines": item.get("lines", 0),
                "redirect": item.get("redirectlocation", ""),
            })
    except (json.JSONDecodeError, TypeError):
        pass
    return results


def cmd_fuzz(args, console) -> None:
    """
    hakuza fuzz [--url <target>] [--mode dirs|params|api|vhosts] [--wordlist <file>] [--threads 50]

    Smart fuzzing with tech detection, wordlist selection, and AI analysis.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()
    eng = _require_engagement(console)

    target = getattr(args, "url", None) or eng["target"]
    mode = getattr(args, "mode", "dirs") or "dirs"
    custom_wordlist = getattr(args, "wordlist", None)
    threads = getattr(args, "threads", 50)

    if not target.startswith("http"):
        target = f"https://{target}"

    domain = _extract_domain(target)

    console.print(
        Panel(
            f"[bold]Target:[/bold]  {target}\n"
            f"[bold]Mode:[/bold]    {mode}\n"
            f"[bold]Threads:[/bold] {threads}",
            title="[bold cyan]  HAKUZA Smart Fuzzer[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # Detect tech
    with _n("Progress")(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        t = prog.add_task("Detecting technology stack...", total=None)
        tech = _detect_tech(target, console)
        prog.update(t, completed=True)

    console.print(f"  [cyan]Detected tech:[/cyan] {tech}")

    # Build wordlist
    if custom_wordlist and Path(custom_wordlist).exists():
        wordlist_items = Path(custom_wordlist).read_text().splitlines()
        wl_source = custom_wordlist
    else:
        # Combine default + tech-specific
        if mode == "dirs":
            wordlist_items = _DEFAULT_DIRS + _TECH_WORDLISTS.get(tech, [])
        elif mode == "params":
            wordlist_items = _DEFAULT_PARAMS
        elif mode == "api":
            wordlist_items = _DEFAULT_API + _TECH_WORDLISTS.get(tech, [])
        else:
            wordlist_items = _DEFAULT_DIRS

        # Also check system wordlists
        system_wls = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            Path.home() / "wordlists" / "admin-paths.txt",
        ]
        wl_source = "built-in"
        for swl in system_wls:
            if Path(swl).exists():
                extra = [l.strip() for l in Path(swl).read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
                wordlist_items = list(dict.fromkeys(wordlist_items + extra[:500]))
                wl_source = str(swl)
                break

    console.print(f"  [dim]Wordlist: {len(wordlist_items)} entries from {wl_source}[/dim]")

    # Write temp wordlist
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(wordlist_items))
        tmp_wl = tmp.name

    results = []
    ffuf_available = shutil.which("ffuf")

    if ffuf_available:
        # Build ffuf command based on mode
        import tempfile as tf
        out_file = tf.NamedTemporaryFile(suffix=".json", delete=False).name

        if mode == "dirs":
            fuzz_url = target.rstrip("/") + "/FUZZ"
            cmd = ["ffuf", "-u", fuzz_url, "-w", tmp_wl, "-mc", "200,201,204,301,302,403",
                   "-t", str(threads), "-json", "-o", out_file, "-s"]
        elif mode == "params":
            fuzz_url = target + "?FUZZ=test"
            cmd = ["ffuf", "-u", fuzz_url, "-w", tmp_wl, "-mc", "200",
                   "-t", str(threads), "-json", "-o", out_file, "-s"]
        elif mode == "api":
            fuzz_url = target.rstrip("/") + "/FUZZ"
            cmd = ["ffuf", "-u", fuzz_url, "-w", tmp_wl, "-mc", "200,201,204",
                   "-t", str(threads), "-json", "-o", out_file, "-s"]
        elif mode == "vhosts":
            cmd = ["ffuf", "-u", target, "-H", f"Host: FUZZ.{domain}",
                   "-w", tmp_wl, "-mc", "200,301,302",
                   "-t", str(threads), "-json", "-o", out_file, "-s"]
        else:
            fuzz_url = target.rstrip("/") + "/FUZZ"
            cmd = ["ffuf", "-u", fuzz_url, "-w", tmp_wl, "-mc", "200,301,302,403",
                   "-t", str(threads), "-json", "-o", out_file, "-s"]

        console.print(f"\n[cyan]Running:[/cyan] {_n('_rich_escape')(' '.join(cmd[:6]))} ...")
        stdout, stderr, rc = _run_tool(cmd, timeout=300)

        if Path(out_file).exists():
            raw = Path(out_file).read_text()
            results = _parse_ffuf_json(raw)
            Path(out_file).unlink(missing_ok=True)

        console.print(f"  [green]ffuf: {len(results)} results[/green]")
    else:
        # Manual check without ffuf
        console.print("[yellow]ffuf not installed — running basic manual check...[/yellow]")
        for word in wordlist_items[:50]:
            check_url = target.rstrip("/") + "/" + word.lstrip("/")
            status, body, _ = _http_get(check_url, timeout=5)
            if status in (200, 201, 204, 301, 302, 403):
                results.append({"url": check_url, "status": status, "length": len(body or "")})

        console.print(f"  [green]Manual check: {len(results)} responses[/green]")

    Path(tmp_wl).unlink(missing_ok=True)

    # Display results
    if results:
        console.print()
        tbl = Table(
            title=f"Fuzz Results — {mode.upper()} mode ({len(results)} hits)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        tbl.add_column("URL", overflow="fold", max_width=80)
        tbl.add_column("Status", width=8, justify="center")
        tbl.add_column("Length", width=10, justify="right")
        tbl.add_column("Redirect", overflow="fold", max_width=40)

        status_color = {200: "green", 201: "green", 204: "green",
                        301: "yellow", 302: "yellow", 403: "orange3"}
        for r in results[:50]:
            sc = r.get("status", 0)
            color = status_color.get(sc, "white")
            tbl.add_row(
                r.get("url", "")[:80],
                f"[{color}]{sc}[/{color}]",
                str(r.get("length", "")),
                (r.get("redirect") or "")[:40],
            )
        console.print(tbl)

        # Save interesting hits
        interesting = [r for r in results if r.get("status") in (200, 201, 204)]
        if interesting:
            _add_recon(
                eng["id"],
                "fuzz_hits",
                "\n".join(f"{r['status']} {r['url']}" for r in interesting),
                f"ffuf-{mode}",
            )

        # AI analysis
        console.print()
        console.print(Rule("[bold cyan]AI Result Analysis[/bold cyan]", style="dim cyan"))
        client_ai = _get_client_or_none()
        if client_ai:
            results_text = "\n".join(
                f"  {r['status']} {r['url']} (len={r.get('length',0)})"
                for r in results[:30]
            )
            ai_prompt = (
                f"These paths were discovered on {target} (tech: {tech}) via {mode} fuzzing:\n\n"
                f"{results_text}\n\n"
                f"Which of these look most interesting for further testing? "
                f"Focus on: admin panels, API endpoints, backup files, debug interfaces. "
                f"Suggest next manual testing steps for the top 3. Be specific."
            )
            _stream(client_ai, [{"role": "user", "content": ai_prompt}], 600, console)
    else:
        console.print("[yellow]No results found.[/yellow]")

    console.print()
    console.print(
        Panel(
            f"[bold]Mode:[/bold] {mode}  |  [bold]Tech:[/bold] {tech}  |  "
            f"[bold]Results:[/bold] {len(results)}\n"
            f"[dim]Run with --mode api or --mode vhosts for additional coverage.[/dim]",
            title="[bold]Fuzz Complete[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_scope
# ---------------------------------------------------------------------------

def _load_scope(eng: dict) -> list:
    scope_file = _n("ENGAGEMENTS_DIR") / eng["name"] / "scope.txt"
    if not scope_file.exists():
        return []
    return [l.strip() for l in scope_file.read_text().splitlines() if l.strip() and not l.startswith("#")]


def _save_scope(eng: dict, entries: list) -> None:
    scope_file = _n("ENGAGEMENTS_DIR") / eng["name"] / "scope.txt"
    scope_file.parent.mkdir(parents=True, exist_ok=True)
    scope_file.write_text("\n".join(entries) + "\n", encoding="utf-8")


def _url_in_scope(url: str, scope_entries: list) -> bool:
    """Check if url matches any scope entry (glob wildcard / domain / substring match)."""
    url_lower = url.lower()
    for entry in scope_entries:
        entry_lower = entry.lower().strip()
        if not entry_lower:
            continue
        # Wildcard domain: *.example.com
        if entry_lower.startswith("*.") and "/" not in entry_lower:
            base = entry_lower[2:]
            if url_lower.endswith(base) or f".{base}" in url_lower:
                return True
        # Any other glob pattern, e.g. https://example.com/*, https://example.com/api/*
        elif "*" in entry_lower or "?" in entry_lower:
            if fnmatch.fnmatch(url_lower, entry_lower):
                return True
            # Entry without a trailing wildcard segment still implies "and below"
            if not entry_lower.endswith("*") and fnmatch.fnmatch(url_lower, entry_lower + "*"):
                return True
        elif entry_lower in url_lower:
            return True
        elif url_lower in entry_lower:
            return True
    return False


def cmd_scope(args, console) -> None:
    """
    hakuza scope [--add <url>] [--check <url>] [--list] [--from-file <file>]

    Manage engagement scope — add, check, and list in-scope targets.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()
    eng = _require_engagement(console)

    add_url = getattr(args, "add", None)
    check_url = getattr(args, "check", None)
    list_flag = getattr(args, "list", False)
    from_file = getattr(args, "from_file", None)

    scope_file = _n("ENGAGEMENTS_DIR") / eng["name"] / "scope.txt"
    scope_entries = _load_scope(eng)

    # Default to --list if no action given
    if not any([add_url, check_url, from_file]) or list_flag:
        if not scope_entries:
            console.print("[yellow]No scope entries. Add with:[/yellow] hakuza scope --add <url>")
            console.print(f"[dim]Scope file:[/dim] {scope_file}")
        else:
            tbl = Table(
                title=f"Scope — {eng['name']} ({len(scope_entries)} entries)",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            tbl.add_column("#", width=4, justify="right")
            tbl.add_column("Entry")
            for i, entry in enumerate(scope_entries, 1):
                tbl.add_row(str(i), entry)
            console.print(tbl)
            console.print(f"[dim]Scope file: {scope_file}[/dim]")

    if add_url:
        if add_url not in scope_entries:
            scope_entries.append(add_url)
            _save_scope(eng, scope_entries)
            console.print(f"[green]Added to scope:[/green] {add_url}")
            _add_recon(eng["id"], "scope", add_url, "manual")
        else:
            console.print(f"[yellow]Already in scope:[/yellow] {add_url}")

    if from_file:
        fp = Path(from_file)
        if not fp.exists():
            console.print(f"[red]File not found:[/red] {from_file}")
        else:
            new_entries = [l.strip() for l in fp.read_text().splitlines()
                           if l.strip() and not l.startswith("#")]
            added = 0
            for entry in new_entries:
                if entry not in scope_entries:
                    scope_entries.append(entry)
                    added += 1
            _save_scope(eng, scope_entries)
            console.print(f"[green]Imported {added} new scope entries from {fp.name}.[/green]")

    if check_url:
        if not scope_entries:
            console.print(f"[yellow]No scope defined — cannot check.[/yellow]")
            console.print("[yellow]Add scope entries first:[/yellow] hakuza scope --add <url>")
        elif _url_in_scope(check_url, scope_entries):
            console.print(
                Panel(
                    f"[bold green]IN SCOPE[/bold green]\n{check_url}\n\n"
                    f"Matched against {len(scope_entries)} scope entries.",
                    title="Scope Check",
                    border_style="green",
                    expand=False,
                )
            )
        else:
            console.print(
                Panel(
                    f"[bold red]OUT OF SCOPE[/bold red]\n{check_url}\n\n"
                    f"[yellow]WARNING: Do NOT test this target without authorization.[/yellow]",
                    title="Scope Check",
                    border_style="red",
                    expand=False,
                )
            )


# ---------------------------------------------------------------------------
# cmd_config  (enhanced replacement)
# ---------------------------------------------------------------------------

def cmd_config(args, console) -> None:
    """
    hakuza config [--show] [--set key=value] [--init]

    Improved config command with Rich table display, interactive setup wizard.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()

    show = getattr(args, "show", False)
    set_val = getattr(args, "set", None)
    init_flag = getattr(args, "init", False)

    cfg = _n("load_config")()
    defaults = _n("_DEFAULT_CONFIG")

    if init_flag:
        console.print(
            Panel(
                "[bold]Welcome to HAKUZA Setup[/bold]\n"
                "Let's configure your environment. Press Enter to keep current value.",
                title="[bold cyan]  HAKUZA Configuration Wizard[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
        )
        fields = [
            ("tester_name", "Your name (shown in reports)", "Divith D Shetty"),
            ("api_key", "Anthropic API key (sk-ant-...)", ""),
            ("proxy", "Burp proxy (e.g. http://127.0.0.1:8080)", ""),
            ("output_dir", "Output directory for engagements", str(_n("ENGAGEMENTS_DIR"))),
        ]
        for key, label, fallback in fields:
            current = cfg.get(key, fallback)
            if key == "api_key" and current:
                display_current = current[:4] + "..." + current[-4:]
            else:
                display_current = current or "(not set)"
            val = Prompt.ask(f"[bold]{label}[/bold]", default=current or fallback)
            cfg[key] = val
        _n("save_config")(cfg)
        console.print("[green]Configuration saved.[/green]")
        show = True  # fall through to display

    if set_val:
        if "=" not in set_val:
            console.print("[red]Usage:[/red] hakuza config --set key=value")
            return
        key, _, val = set_val.partition("=")
        key, val = key.strip(), val.strip()
        cfg[key] = val
        _n("save_config")(cfg)
        console.print(f"[green]Set[/green] [bold]{key}[/bold] = {val if 'key' not in key.lower() else val[:4]+'...'}")
        return

    # Default / --show: pretty table
    tbl = Table(
        title="HAKUZA Configuration",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    tbl.add_column("Key", style="bold white", width=20)
    tbl.add_column("Value", width=38)
    tbl.add_column("Status", width=10)

    for key in sorted(set(list(defaults.keys()) + list(cfg.keys()))):
        raw_val = cfg.get(key, "")
        is_default = raw_val == defaults.get(key, "") or not raw_val

        # Mask sensitive values
        if "key" in key.lower() and raw_val and len(raw_val) > 8:
            display_val = raw_val[:7] + "***" + raw_val[-4:]
        else:
            display_val = str(raw_val) if raw_val else "[dim](not set)[/dim]"

        if raw_val and not is_default:
            status = "[bold green]set[/bold green]"
        elif raw_val and is_default:
            status = "[dim]default[/dim]"
        else:
            status = "[dim]· default[/dim]"

        tbl.add_row(key, display_val, status)

    console.print(tbl)
    console.print(f"\n[dim]Config file: {_n('CONFIG_PATH')}[/dim]")
    console.print("[dim]Edit with: [bold]hakuza config --set key=value[/bold] or [bold]hakuza config --init[/bold][/dim]")


# ---------------------------------------------------------------------------
# cmd_wizard  —  interactive guided demo wizard
# ---------------------------------------------------------------------------

_WIZARD_STEPS = [
    ("Create Engagement", "Set up a new pentest engagement with client and target details."),
    ("Run Quick Recon", "Enumerate subdomains, live hosts, and open ports."),
    ("Scan for Vulnerabilities", "Run automated vulnerability scanning with nuclei."),
    ("AI Analysis", "Use Claude to analyse findings and suggest attack chains."),
    ("Add Manual Finding", "Record a manually discovered vulnerability."),
    ("Generate Report", "Produce a professional penetration testing report."),
]


def _wizard_step_header(step_num: int, title: str, desc: str, console) -> None:
    Panel, *_ = _rich()
    console.print()
    console.print(
        Panel(
            f"[bold]{desc}[/bold]",
            title=f"[bold cyan]Step {step_num}/{len(_WIZARD_STEPS)}: {title}[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )


def cmd_wizard(args, console) -> None:
    """
    hakuza wizard

    Interactive guided walkthrough — create engagement, recon, scan, analyse,
    add finding, generate report. Ideal for live demos and onboarding.
    """
    Panel, Rule, Table, Markdown, Prompt, Confirm, Progress, SpinnerColumn, TextColumn, box = _rich()

    console.print(
        Panel(
            "[bold cyan]HAKUZA Engagement Wizard[/bold cyan]\n\n"
            "Let's walk through a complete pentest engagement from start to first finding.\n"
            "Each step explains what we're doing and why — perfect for demos.\n\n"
            "[dim]Press Ctrl+C at any time to exit.[/dim]",
            title="[bold]Welcome to HAKUZA[/bold]",
            border_style="cyan",
            expand=False,
        )
    )

    steps_display = Table(box=box.SIMPLE, show_header=False, expand=False)
    steps_display.add_column("Step", style="bold cyan", width=8)
    steps_display.add_column("Title", style="bold")
    for i, (title, _) in enumerate(_WIZARD_STEPS, 1):
        steps_display.add_row(f"  {i}/{len(_WIZARD_STEPS)}", title)
    console.print(steps_display)
    console.print()

    if not Confirm.ask("[bold]Start the wizard?[/bold]", default=True):
        console.print("[yellow]Wizard cancelled.[/yellow]")
        return

    # ---- Step 1: Create engagement ----
    _wizard_step_header(1, "Create Engagement",
                        "We create a named engagement that tracks all findings, recon data, "
                        "and artifacts. Everything in HAKUZA lives inside an engagement.", console)

    eng_name = Prompt.ask("[bold]Engagement name[/bold] (e.g. acme-web-2026)",
                          default="wizard-demo")
    client_name = Prompt.ask("[bold]Client name[/bold]", default="Acme Bank")
    target_url = Prompt.ask("[bold]Target URL[/bold]", default="https://demo.acme.com")

    # Check if engagement already exists
    existing = _n("get_engagement")(eng_name)
    if not existing:
        eng = _n("create_engagement")(eng_name, client_name, target_url, target_url, "web",
                                      _n("get_config_value")("tester_name", "Divith D Shetty"))
        _n("set_current_engagement")(eng_name)
        eng_dir = _n("ENGAGEMENTS_DIR") / eng_name
        for sub in ["evidence", "reports", "recon", "artifacts"]:
            (eng_dir / sub).mkdir(parents=True, exist_ok=True)
        console.print(f"\n[green]Engagement '[bold]{eng_name}[/bold]' created and set as active.[/green]")
    else:
        eng = existing
        _n("set_current_engagement")(eng_name)
        console.print(f"\n[yellow]Engagement '[bold]{eng_name}[/bold]' already exists — switched to it.[/yellow]")

    console.print(f"  [dim]Client: {eng['client']}  Target: {eng['target']}  Type: web[/dim]")

    if not Confirm.ask("\n[bold]Continue to Step 2?[/bold]", default=True):
        console.print("[yellow]Wizard paused. Resume with:[/yellow] hakuza wizard")
        return

    # ---- Step 2: Quick Recon ----
    _wizard_step_header(2, "Run Quick Recon",
                        "Recon maps the attack surface: subdomains, live hosts, open ports. "
                        "The more we know about the target, the better we can prioritise.", console)

    domain = _extract_domain(target_url)
    console.print(f"[cyan]Running recon on:[/cyan] {domain}")

    tools = _check_tools()

    with _n("Progress")(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        if tools.get("subfinder"):
            t = prog.add_task("Running subfinder...", total=None)
            stdout, _, _ = _run_tool(["subfinder", "-d", domain, "-silent"], timeout=60)
            subs = [s.strip() for s in stdout.splitlines() if s.strip()][:10]
            prog.update(t, completed=True)
        else:
            subs = [f"api.{domain}", f"app.{domain}", f"admin.{domain}", f"mobile.{domain}"]
            console.print(f"  [dim]subfinder not installed — using predicted subdomains[/dim]")

    for s in subs[:5]:
        console.print(f"  [cyan]  {s}[/cyan]")
    if subs:
        _add_recon(eng["id"], "subdomains", "\n".join(subs), "wizard-recon")
        console.print(f"  [green]Found {len(subs)} subdomains — saved to DB[/green]")

    console.print()
    console.print(f"  [dim]In a full test we'd now run httpx for live probing and nmap for port scanning.[/dim]")
    console.print(f"  [dim]Run 'hakuza recon' for the full recon workflow.[/dim]")

    if not Confirm.ask("\n[bold]Continue to Step 3?[/bold]", default=True):
        console.print("[yellow]Wizard paused.[/yellow]")
        return

    # ---- Step 3: Scan ----
    _wizard_step_header(3, "Scan for Vulnerabilities",
                        "We run automated scanners to find low-hanging fruit quickly. "
                        "nuclei uses community templates for CVEs, misconfigs, and exposures.", console)

    if tools.get("nuclei"):
        console.print(f"[cyan]Would run:[/cyan] nuclei -u {target_url} -tags cves,misconfigurations -json")
        console.print("[dim]  (skipping live scan in wizard mode — run 'hakuza scan' for real scan)[/dim]")
    else:
        console.print("[yellow]nuclei not installed.[/yellow]")
        console.print(f"[dim]Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]")
        console.print()
        console.print("[dim]For demo purposes, adding a simulated finding...[/dim]")

    # Simulate a finding for demo purposes
    sim_finding = _add_finding(
        eng["id"],
        title="[DEMO] Security Headers Missing",
        severity="medium",
        url=target_url,
        description="Multiple security headers are absent: X-Frame-Options, X-Content-Type-Options, "
                    "Content-Security-Policy. This is a common misconfiguration.",
        evidence="HTTP/1.1 200 OK\nContent-Type: text/html\n[No security headers present]",
        cvss_score=5.3,
        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cwe="CWE-693",
        impact="Missing headers enable clickjacking, MIME sniffing, and XSS amplification.",
        remediation="Add: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, "
                    "Content-Security-Policy: default-src 'self'",
        tool="wizard-demo",
    )
    console.print(f"  [green]Simulated finding added: [{sim_finding['short_id']}] {sim_finding['title'][:60]}[/green]")

    if not Confirm.ask("\n[bold]Continue to Step 4?[/bold]", default=True):
        return

    # ---- Step 4: AI Analysis ----
    _wizard_step_header(4, "AI Analysis",
                        "Claude analyses all findings, identifies attack chains, and suggests "
                        "what to test next — saving hours of manual triage.", console)

    client_ai = _get_client_or_none()
    if client_ai:
        findings = _n("list_findings")(eng["id"])
        ftext = _n("findings_to_summary_text")(findings)
        ai_prompt = (
            f"Brief analysis for a pentest demo engagement:\n"
            f"Target: {target_url}\nClient: {client_name}\n\n"
            f"Findings:\n{ftext}\n\n"
            f"Provide a 3-point triage: top risk, likely next finding, recommended immediate action."
        )
        console.print("[cyan]Asking Claude...[/cyan]\n")
        _stream(client_ai, [{"role": "user", "content": ai_prompt}], 400, console)
    else:
        console.print("[dim]AI analysis requires ANTHROPIC_API_KEY.[/dim]")
        console.print("[dim]Set it with: hakuza config --set api_key=sk-ant-...[/dim]")
        console.print("\n[bold]What AI would say:[/bold]")
        console.print("  1. [bold red]Top risk:[/bold red] Missing security headers enable clickjacking on login page")
        console.print("  2. [bold orange3]Next target:[/bold orange3] Test for CSRF — same headers missing suggests weak defence posture")
        console.print("  3. [bold green]Immediate action:[/bold green] Run 'hakuza secrets' to check for exposed .env files")

    if not Confirm.ask("\n[bold]Continue to Step 5?[/bold]", default=True):
        return

    # ---- Step 5: Add Manual Finding ----
    _wizard_step_header(5, "Add Manual Finding",
                        "Automated tools miss business logic flaws and complex vulnerabilities. "
                        "Manual findings are the difference between a 9.5 and a generic scan report.", console)

    console.print("[dim]Let's add a manual finding to demonstrate the workflow.[/dim]")
    console.print()

    add_title = Prompt.ask("[bold]Finding title[/bold]", default="Insecure Direct Object Reference on /api/accounts/{id}")
    add_sev = Prompt.ask("[bold]Severity[/bold]", choices=["critical", "high", "medium", "low"], default="high")
    add_url_val = Prompt.ask("[bold]Affected URL[/bold]", default=f"{target_url}/api/accounts/1234")

    manual_f = _add_finding(
        eng["id"],
        title=add_title,
        severity=add_sev,
        url=add_url_val,
        description=f"Changing the account ID in {add_url_val} returns another user's account data. "
                    f"No authorisation check is performed server-side.",
        evidence=f"GET {add_url_val.replace('1234','9999')}\n"
                 f"HTTP/1.1 200 OK\n"
                 f"{{\"id\": 9999, \"name\": \"Jane Doe\", \"balance\": 42000}}",
        cvss_score=7.5,
        cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cwe="CWE-639",
        owasp="API3:2023 Broken Object Property Level Authorization",
        impact="Attacker can access any customer's account data by iterating account IDs.",
        remediation="Implement server-side authorisation checks on every object access. "
                    "Validate that the requesting user owns the requested resource.",
        tool="manual",
    )

    console.print(f"\n[green]Finding added:[/green] [{manual_f['short_id']}] {manual_f['title'][:70]}")
    console.print(f"  [dim]Severity: {add_sev.upper()}  CVSS: {manual_f.get('cvss_score')}[/dim]")

    if not Confirm.ask("\n[bold]Continue to Step 6?[/bold]", default=True):
        return

    # ---- Step 6: Report ----
    _wizard_step_header(6, "Generate Report",
                        "HAKUZA generates a full professional report with executive summary, "
                        "technical findings, CVSS scores, and remediation roadmap.", console)

    findings = _n("list_findings")(eng["id"])
    counts = _n("get_finding_count")(eng["id"])

    console.print(f"  [bold]Findings in engagement:[/bold]")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        cnt = counts.get(sev, 0)
        if cnt:
            color = {"critical": "red", "high": "orange3", "medium": "yellow",
                     "low": "green", "informational": "blue"}.get(sev, "white")
            console.print(f"    [{color}]{sev.upper()}: {cnt}[/{color}]")

    console.print()
    console.print(f"[dim]To generate the full report, run:[/dim]")
    console.print(f"[bold cyan]  hakuza report --html --output {eng_name}_report.md[/bold cyan]")
    console.print()
    console.print(
        "[dim]The report includes: Executive Summary, Risk Matrix, Full Findings Detail, "
        "Attack Chains, Remediation Timeline, and Regulatory Impact (PCI-DSS, RBI, SEBI).[/dim]"
    )

    # Final summary
    console.print()
    console.print(
        Panel(
            f"[bold green]Wizard complete![/bold green]\n\n"
            f"Engagement [bold]{eng_name}[/bold] is set up and ready.\n"
            f"  {sum(counts.values())} finding(s) recorded\n"
            f"  {len(subs)} subdomains discovered\n\n"
            f"[bold]Next steps:[/bold]\n"
            f"  hakuza recon           — Full recon (subfinder + httpx + nmap)\n"
            f"  hakuza scan            — Nuclei vulnerability scan\n"
            f"  hakuza secrets         — Hunt for exposed secrets\n"
            f"  hakuza wayback         — Mine historical URLs\n"
            f"  hakuza fuzz            — Smart directory/API fuzzing\n"
            f"  hakuza analyze --save  — Deep AI analysis\n"
            f"  hakuza report --html   — Generate final report",
            title="[bold]Wizard Complete[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# Argparse additions  (paste into hakuza.py build_parser() before return)
# ---------------------------------------------------------------------------
# NOTE: The code below is informational.  To integrate, add these blocks
# inside build_parser() and update the dispatch dict in main().
# ---------------------------------------------------------------------------

def register_argparse(sub):
    """
    Call this from hakuza.build_parser() after existing sub-parsers are defined:
        from mod_recon_plus import register_argparse
        register_argparse(sub)
    """
    # wayback
    p_wb = sub.add_parser("wayback", help="Mine historical URLs for attack surface")
    p_wb.add_argument("--domain", default=None, help="Override domain to mine")
    p_wb.add_argument("--filter", dest="filter",
                      choices=["endpoints", "params", "secrets", "all"], default="all")
    p_wb.add_argument("--save", action="store_true", help="Save all URLs to file")

    # secrets
    p_sec = sub.add_parser("secrets", help="Hunt exposed secrets in JS files and config")
    p_sec.add_argument("--url", default=None, help="Override target URL")
    p_sec.add_argument("--js-only", dest="js_only", action="store_true",
                       help="Scan JS files only, skip path checks")
    p_sec.add_argument("--deep", action="store_true", help="Extended path list + extra JS discovery")

    # fuzz
    p_fz = sub.add_parser("fuzz", help="Smart fuzzing: dirs, params, api endpoints, vhosts")
    p_fz.add_argument("--url", default=None, help="Override target URL")
    p_fz.add_argument("--mode", choices=["dirs", "params", "api", "vhosts"], default="dirs")
    p_fz.add_argument("--wordlist", default=None, help="Custom wordlist file")
    p_fz.add_argument("--threads", type=int, default=50)

    # wizard
    sub.add_parser("wizard", help="Guided engagement walkthrough — ideal for demos")

    # scope
    p_scope = sub.add_parser("scope", help="Manage engagement scope")
    p_scope.add_argument("--add", default=None, metavar="URL", help="Add URL to scope")
    p_scope.add_argument("--check", default=None, metavar="URL", help="Check if URL is in scope")
    p_scope.add_argument("--list", dest="list", action="store_true", help="List all scope entries")
    p_scope.add_argument("--from-file", dest="from_file", default=None,
                         help="Import scope entries from file (one per line)")

    # config (override existing)
    p_cfg = sub.add_parser("config", help="Get/set HAKUZA configuration (enhanced)")
    p_cfg.add_argument("--show", action="store_true", help="Show all config values")
    p_cfg.add_argument("--set", default=None, metavar="key=value", help="Set a config key")
    p_cfg.add_argument("--init", action="store_true", help="Interactive setup wizard")


# ---------------------------------------------------------------------------
# Dispatch additions  (paste into main() dispatch dict)
# ---------------------------------------------------------------------------
# "wayback": cmd_wayback,
# "secrets": cmd_secrets,
# "fuzz":    cmd_fuzz,
# "wizard":  cmd_wizard,
# "scope":   cmd_scope,
# "config":  cmd_config,       # replaces existing config handler

# END mod_recon_plus.py
