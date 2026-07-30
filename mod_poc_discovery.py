#!/usr/bin/env python3
"""
HAKUZA PoC Discovery Module — Auto-discover exploits for CVEs
Searches GitHub for public PoC code and links to known vulnerabilities
"""

import subprocess
import json
import re
from typing import Optional, List, Dict, Any
from datetime import datetime

# GitHub Search API (free tier, no auth required)
# Rate limit: 10 req/min unauthenticated
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


def search_github_poc(cve_id: str, limit: int = 3) -> List[Dict[str, str]]:
    """
    Search GitHub for public PoC repositories matching a CVE ID.

    Returns list of {url, stars, language, description}
    """
    results = []

    # Query: "CVE-XXXX" in code with Python/Bash/Shell preference
    query = f'"{cve_id}" in:description,readme language:python OR language:shell OR language:bash'

    try:
        # Use curl to avoid adding requests dependency
        cmd = [
            "curl",
            "-s",
            "-H", "Accept: application/vnd.github.v3+json",
            f"{GITHUB_SEARCH_URL}?q={query}&sort=stars&order=desc&per_page={limit}",
        ]

        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        data = json.loads(output)

        if "items" not in data:
            return []

        for repo in data["items"][:limit]:
            results.append({
                "url": repo.get("html_url", ""),
                "name": repo.get("name", ""),
                "stars": repo.get("stargazers_count", 0),
                "language": repo.get("language", "Unknown"),
                "description": repo.get("description", ""),
                "last_updated": repo.get("updated_at", ""),
            })

    except Exception as e:
        # Silently fail — network issue or rate limit
        pass

    return results


def extract_poc_links(cve_id: str) -> List[str]:
    """
    Extract direct PoC/exploit links from known public sources.
    Primarily from GitHub via search + fallback to known registries.
    """
    links = []

    # GitHub search results
    github_pocs = search_github_poc(cve_id, limit=3)
    for poc in github_pocs:
        links.append({
            "source": "GitHub",
            "url": poc["url"],
            "metadata": f"{poc['language']} • {poc['stars']} stars",
            "title": poc.get("description", poc["name"]),
        })

    # NVD reference links (parse from CVE if available)
    # This would ideally query NVD, but that requires more context
    # For now, we just return what we found

    return links


def cmd_poc_discover(args) -> None:
    """Discover PoC code for a given CVE."""
    cve_id = args.cve_id.upper()

    # Validate CVE format
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        console.print(f"[red]Invalid CVE format: {cve_id}[/red]")
        console.print("[dim]Expected format: CVE-YYYY-NUMBER[/dim]")
        return

    console.print(f"\n[bold cyan]Searching for PoC: {cve_id}[/bold cyan]")
    console.print("[dim]Querying GitHub repositories...[/dim]")

    pocs = extract_poc_links(cve_id)

    if not pocs:
        console.print(f"[yellow]No public PoC found for {cve_id}[/yellow]")
        console.print("[dim]Try searching manually on GitHub or ExploitDB[/dim]")
        return

    console.print(f"\n[bold]Found {len(pocs)} PoC(s):[/bold]\n")

    for i, poc in enumerate(pocs, 1):
        console.print(f"[bold]{i}. {poc.get('title', 'Unknown')}[/bold]")
        console.print(f"   Source: {poc['source']}")
        console.print(f"   URL: {poc['url']}")
        if poc.get('metadata'):
            console.print(f"   Metadata: {poc['metadata']}")
        console.print()


def enrich_finding_with_poc(finding_id: str, engagement_db, cve_id: str) -> bool:
    """
    Update a finding with auto-discovered PoC links.
    Attach as finding.poc_links (JSON array)
    """
    if not cve_id:
        return False

    pocs = extract_poc_links(cve_id)
    if not pocs:
        return False

    try:
        conn = engagement_db
        poc_json = json.dumps(pocs)

        conn.execute(
            "UPDATE findings SET poc_links = ? WHERE id = ?",
            (poc_json, finding_id),
        )
        conn.commit()
        return True

    except Exception as e:
        # Silently fail if DB update doesn't work
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In build_parser(), inside the sub-commands block, add:

#   p_poc = sub.add_parser("poc-discover",
#       help="Auto-discover public PoC code for a CVE",
#       description="Search GitHub and known registries for working exploits"
#   )
#   p_poc.add_argument("cve_id", help="CVE ID (e.g., CVE-2021-44228)")
#   p_poc.set_defaults(func=cmd_poc_discover)

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In main(), in the dispatch dict, add:

#   "poc-discover": cmd_poc_discover,
