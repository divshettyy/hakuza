#!/usr/bin/env python3
"""
HAKUZA Techniques Module — Load and manage ATT&CK technique library
Provides technique lookup, filtering, and orchestration hints
"""

import yaml
import json
from pathlib import Path
from typing import Optional, List, Dict, Any

TECHNIQUES_FILE = Path(__file__).parent / "techniques.yaml"

_techniques_cache: Optional[List[Dict[str, Any]]] = None


def load_techniques() -> List[Dict[str, Any]]:
    """Load techniques from techniques.yaml and cache in memory."""
    global _techniques_cache

    if _techniques_cache is not None:
        return _techniques_cache

    if not TECHNIQUES_FILE.exists():
        console.print(f"[yellow]Warning: {TECHNIQUES_FILE} not found[/yellow]")
        return []

    with open(TECHNIQUES_FILE, 'r') as f:
        data = yaml.safe_load(f)

    _techniques_cache = data.get("techniques", [])
    return _techniques_cache


def get_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single technique by its id."""
    techniques = load_techniques()
    for t in techniques:
        if t.get("id") == technique_id:
            return t
    return None


def find_techniques_by_tags(tags: List[str]) -> List[Dict[str, Any]]:
    """Find techniques matching ANY of the given tags (applicability_tags)."""
    techniques = load_techniques()
    results = []
    for t in techniques:
        t_tags = t.get("applicability_tags", [])
        if any(tag in t_tags for tag in tags):
            results.append(t)
    return results


def find_techniques_by_severity(severity: str) -> List[Dict[str, Any]]:
    """Find techniques matching severity level."""
    techniques = load_techniques()
    return [t for t in techniques if t.get("severity") == severity]


def get_technique_summary(technique: Dict[str, Any]) -> str:
    """Return a one-line summary for display."""
    return f"{technique.get('id'):25} {technique.get('name'):40} [{technique.get('severity', 'unknown').upper():8}]"


def cmd_list_techniques(args) -> None:
    """List all loaded techniques with optional filtering."""
    techniques = load_techniques()

    if not techniques:
        console.print("[red]No techniques loaded[/red]")
        return

    # Filter by tags if provided
    if args.tag:
        techniques = find_techniques_by_tags(args.tag.split(","))

    # Filter by severity if provided
    if args.severity:
        techniques = find_techniques_by_severity(args.severity.lower())

    console.print(f"\n[bold cyan]Loaded Techniques ({len(techniques)})[/bold cyan]")
    console.print("─" * 100)
    console.print(f"{'Technique ID':<25} {'Name':<40} {'Severity':<10}")
    console.print("─" * 100)

    for t in techniques:
        severity_color = SEV_COLORS.get(t.get("severity", "info"), "blue")
        severity_badge = f"[{severity_color}]{t.get('severity', 'info').upper()}[/{severity_color}]"
        console.print(
            f"{t.get('id', 'unknown'):<25} "
            f"{t.get('name', 'unknown'):<40} "
            f"{severity_badge}"
        )

    console.print()


def cmd_show_technique(args) -> None:
    """Display detailed information about a specific technique."""
    technique = get_technique_by_id(args.technique_id)

    if not technique:
        console.print(f"[red]Technique '{args.technique_id}' not found[/red]")
        return

    console.print()
    console.print(f"[bold cyan]{technique.get('name')}[/bold cyan]")
    console.print(f"[dim]ID: {technique.get('id')}[/dim]")
    console.print()

    console.print(f"[bold]Description:[/bold]")
    console.print(f"  {technique.get('description', 'N/A')}")
    console.print()

    console.print(f"[bold]MITRE ATT&CK:[/bold]")
    for tid in technique.get("mitre", []):
        console.print(f"  • {tid}")
    console.print()

    console.print(f"[bold]Applicability Tags:[/bold]")
    tags = technique.get("applicability_tags", [])
    console.print(f"  {', '.join(tags) if tags else 'N/A'}")
    console.print()

    console.print(f"[bold]Prerequisites:[/bold]")
    reqs = technique.get("prerequisites", [])
    for req in reqs:
        console.print(f"  • {req}")
    console.print()

    console.print(f"[bold]Procedure:[/bold]")
    console.print(f"  {technique.get('procedure', 'N/A')}")
    console.print()

    console.print(f"[bold]Expected Artifacts:[/bold]")
    artifacts = technique.get("expected_artifacts", [])
    for art in artifacts:
        console.print(f"  • {art}")
    console.print()

    severity_color = SEV_COLORS.get(technique.get("severity", "info"), "blue")
    console.print(f"[bold]Severity:[/bold] [{severity_color}]{technique.get('severity', 'unknown').upper()}[/{severity_color}]")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In build_parser(), inside the sub-commands block, add:

#   p_list_tech = sub.add_parser("list-techniques",
#       help="List all ATT&CK-mapped techniques available for orchestration",
#       description="List loaded techniques with optional filtering by tag/severity"
#   )
#   p_list_tech.add_argument("--tag", help="Filter by applicability tag (CSV)")
#   p_list_tech.add_argument("--severity", help="Filter by severity (critical/high/medium/low/info)")
#   p_list_tech.set_defaults(func=cmd_list_techniques)
#
#   p_show_tech = sub.add_parser("show-technique",
#       help="Display detailed information about a technique",
#       description="Show full details including procedure, prerequisites, and artifacts"
#   )
#   p_show_tech.add_argument("technique_id", help="Technique ID (e.g., sqli_error)")
#   p_show_tech.set_defaults(func=cmd_show_technique)

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In main(), in the dispatch dict, add:

#   "list-techniques": cmd_list_techniques,
#   "show-technique": cmd_show_technique,
