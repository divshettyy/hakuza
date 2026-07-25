"""
mod_ai_batch.py — AI-powered batch operations on findings for HAKUZA.

Commands:
    hakuza deduplicate  [--dry-run] [--auto]
    hakuza enrich       [--all] [--missing-cvss] [--missing-cwe] [--finding <id>]
    hakuza prioritize   [--format table|matrix|timeline] [--bfsi]
    hakuza matrix       [--save]

All AI calls use cached SYSTEM_PROMPT via ask_claude() / stream_to_console().
All DB writes use the shared get_db() singleton.
"""

import json
import re
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.text import Text
from rich.prompt import Confirm

# ---------------------------------------------------------------------------
# Interfaces imported from the host module at runtime (hakuza.py).
# Declared here only for IDE navigation; the module is run inside hakuza's
# namespace so all names are already in scope when these functions execute.
# ---------------------------------------------------------------------------
# _require_engagement, get_client, ask_claude, stream_to_console
# list_findings, get_finding_count, get_db
# SYSTEM_PROMPT, sev_badge, print_findings_table, print_risk_summary
# Panel, Rule, Table, Markdown, Prompt, Confirm
# Progress, SpinnerColumn, TextColumn, BarColumn, box
# datetime, json, re

# ---------------------------------------------------------------------------
# INTERNAL HELPERS
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}


def _serialize_findings_for_ai(findings: list) -> str:
    """Serialize findings list to compact text for AI prompts."""
    lines = [f"Total findings: {len(findings)}\n"]
    for f in findings:
        cvss = f.get("cvss_score")
        lines.append(
            f"ID:{f.get('short_id', f['id'][:8])}  "
            f"SEV:{(f.get('severity') or 'info').upper()}  "
            f"CVSS:{cvss if cvss is not None else 'N/A'}  "
            f"TITLE:{f.get('title', '?')}  "
            f"URL:{(f.get('url') or '')[:80]}  "
            f"DESC:{(f.get('description') or '')[:120]}"
        )
    return "\n".join(lines)


def _parse_json_from_response(raw: str) -> object:
    """
    Attempt to extract a JSON object or array from an AI response.
    Strips markdown code fences if present.
    Returns the parsed object, or None on failure.
    """
    # Strip ```json ... ``` or ``` ... ``` fences
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().rstrip("`").strip()
    # Try to locate the first [ or {
    for start_char, end_char in [("[", "]"), ("{", "}")]:
        idx = cleaned.find(start_char)
        if idx != -1:
            # Find matching closing bracket
            depth = 0
            for i, ch in enumerate(cleaned[idx:], start=idx):
                if ch == start_char:
                    depth += 1
                elif ch == end_char:
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(cleaned[idx: i + 1])
                        except json.JSONDecodeError:
                            break
    # Last resort — try parsing the whole cleaned string
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None


def _update_finding_in_db(
    finding_id: str,
    cvss_score=None,
    cvss_vector=None,
    cwe=None,
    owasp=None,
    impact=None,
    remediation=None,
) -> None:
    """Patch enrichment fields on a finding row."""
    db = get_db()
    now = datetime.now().isoformat()
    db.execute(
        """UPDATE findings
           SET cvss_score=?, cvss_vector=?, cwe=?, owasp=?,
               impact=?, remediation=?, updated_at=?
           WHERE id=?""",
        [cvss_score, cvss_vector, cwe, owasp, impact, remediation, now, finding_id],
    )
    db.commit()


def _mark_finding_status(finding_id: str, status: str) -> None:
    """Update the status field of a finding row."""
    db = get_db()
    now = datetime.now().isoformat()
    db.execute(
        "UPDATE findings SET status=?, updated_at=? WHERE id=?",
        [status, now, finding_id],
    )
    db.commit()


# ---------------------------------------------------------------------------
# cmd_deduplicate
# ---------------------------------------------------------------------------

def cmd_deduplicate(args, console: Console) -> None:
    """
    hakuza deduplicate [--dry-run] [--auto]

    Uses AI to find duplicate/overlapping findings and optionally merge them
    by marking duplicates with status='fp'.
    """
    eng = _require_engagement(console)

    try:
        client = get_client()
    except SystemExit:
        console.print(
            "[red]Anthropic API key required for deduplication.[/red]\n"
            "[dim]Set it with: hakuza config --set api_key=sk-...[/dim]"
        )
        return

    dry_run = getattr(args, "dry_run", False)
    auto = getattr(args, "auto", False)

    # Load open findings only
    all_findings = list_findings(eng["id"])
    open_findings = [f for f in all_findings if f.get("status") not in ("remediated", "fp")]

    if len(open_findings) < 2:
        console.print("[yellow]Fewer than 2 open findings — nothing to deduplicate.[/yellow]")
        return

    console.print(
        Panel(
            f"[bold]Engagement:[/bold] {eng['name']}\n"
            f"[bold]Open findings:[/bold] {len(open_findings)}\n"
            f"[bold]Mode:[/bold] {'Dry-run (no changes)' if dry_run else ('Auto-mark' if auto else 'Interactive')}",
            title="[bold cyan]  AI Deduplication[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # Serialize findings for AI
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Asking Claude to identify duplicates...", total=None)
        findings_text = _serialize_findings_for_ai(open_findings)

        dedup_prompt = f"""You are analysing penetration testing findings for duplicates and overlaps.

FINDINGS:
{findings_text}

Identify groups of duplicate or overlapping findings. Two findings are duplicates if they:
- Describe the same vulnerability class at the same URL/endpoint
- Have the same root cause even if worded differently
- Are variations of the same issue (e.g. reflected XSS on /search vs /search?q=test)

For each duplicate group, select the most complete finding as primary (prefer higher severity, more description).

Return ONLY valid JSON (no markdown, no explanation) in this exact format:
[
  {{
    "primary_id": "SHORT_ID_OR_UUID",
    "duplicate_ids": ["SHORT_ID_1", "SHORT_ID_2"],
    "merge_reason": "Brief explanation of why these are duplicates"
  }}
]

If no duplicates are found, return an empty array: []"""

        raw_response = ask_claude(client, dedup_prompt, max_tokens=2000)
        progress.update(task, completed=True)

    # Parse AI response
    groups = _parse_json_from_response(raw_response)

    if groups is None:
        console.print("[red]Failed to parse AI response as JSON.[/red]")
        console.print(f"[dim]Raw response:\n{raw_response[:500]}[/dim]")
        return

    if not isinstance(groups, list):
        groups = []

    if not groups:
        console.print("[green]No duplicate findings detected by AI.[/green]")
        return

    # Build lookup: short_id / partial uuid → full finding dict
    id_map: dict = {}
    for f in open_findings:
        id_map[f["short_id"]] = f
        id_map[f["id"]] = f
        id_map[f["id"][:8]] = f

    # Validate groups — resolve IDs
    valid_groups = []
    for group in groups:
        primary_key = group.get("primary_id", "")
        dup_keys = group.get("duplicate_ids", [])
        reason = group.get("merge_reason", "")

        primary_f = id_map.get(primary_key)
        if not primary_f:
            # Fuzzy search by short_id prefix
            for key, f in id_map.items():
                if key.startswith(primary_key) or primary_key.startswith(key):
                    primary_f = f
                    break

        if not primary_f:
            console.print(f"[yellow]  Could not resolve primary ID '{primary_key}' — skipping group.[/yellow]")
            continue

        dup_findings = []
        for dk in dup_keys:
            df = id_map.get(dk)
            if not df:
                for key, f in id_map.items():
                    if key.startswith(dk) or dk.startswith(key):
                        df = f
                        break
            if df and df["id"] != primary_f["id"]:
                dup_findings.append(df)

        if dup_findings:
            valid_groups.append({
                "primary": primary_f,
                "duplicates": dup_findings,
                "reason": reason,
            })

    if not valid_groups:
        console.print("[yellow]AI identified potential duplicates, but could not match IDs to findings.[/yellow]")
        console.print(f"[dim]Raw AI output:\n{raw_response[:600]}[/dim]")
        return

    # Display table
    table = Table(
        title=f"Duplicate Groups Found ({len(valid_groups)})",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Primary Finding", ratio=2, overflow="ellipsis")
    table.add_column("Sev", width=9)
    table.add_column("Duplicates", ratio=2, overflow="fold")
    table.add_column("Reason", ratio=3, overflow="fold")

    for g in valid_groups:
        pf = g["primary"]
        dup_titles = "\n".join(
            f"{d.get('short_id', d['id'][:8])}: {d.get('title', '')[:50]}"
            for d in g["duplicates"]
        )
        table.add_row(
            f"{pf.get('short_id', pf['id'][:8])}: {pf.get('title', '')[:60]}",
            sev_badge(pf.get("severity", "info")),
            dup_titles,
            g["reason"][:120],
        )

    console.print(table)

    if dry_run:
        total_dups = sum(len(g["duplicates"]) for g in valid_groups)
        console.print(
            f"\n[yellow]Dry-run:[/yellow] Would mark [bold]{total_dups}[/bold] finding(s) as duplicates "
            f"across {len(valid_groups)} group(s). No changes made."
        )
        return

    # Apply deduplication
    marked_count = 0
    kept_count = 0

    for g in valid_groups:
        pf = g["primary"]
        apply = True

        if not auto:
            console.print(
                f"\n[bold]Group:[/bold] Keep [cyan]{pf.get('short_id', pf['id'][:8])}[/cyan] "
                f"— [italic]{pf.get('title', '')}[/italic]"
            )
            for df in g["duplicates"]:
                console.print(
                    f"  Mark duplicate: [red]{df.get('short_id', df['id'][:8])}[/red] "
                    f"— {df.get('title', '')[:60]}"
                )
            apply = Confirm.ask("  Mark these as duplicates?", default=True)

        if apply:
            for df in g["duplicates"]:
                _mark_finding_status(df["id"], "fp")
                marked_count += 1
            kept_count += 1
        else:
            console.print("  [dim]Skipped.[/dim]")

    console.print(
        Panel(
            f"[bold green]Deduplication complete![/bold green]\n\n"
            f"[bold]Groups processed:[/bold] {kept_count}\n"
            f"[bold]Findings marked as duplicate:[/bold] {marked_count}\n"
            f"[bold]Findings kept as primary:[/bold] {kept_count}\n\n"
            f"[dim]Duplicates are now status='fp' (false positive / duplicate).[/dim]\n"
            f"[dim]Run [bold]hakuza findings[/bold] to review the cleaned list.[/dim]",
            title="[bold]Deduplication Summary[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_enrich
# ---------------------------------------------------------------------------

_ENRICH_PROMPT_TEMPLATE = """\
Enrich this finding with precise CVSS v3.1 scoring and categorization.
Title: {title}
Description: {description}
URL: {url}

Return ONLY valid JSON (no markdown):
{{
  "cvss_score": <float 0-10>,
  "cvss_vector": "AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X",
  "cwe": "CWE-XXX: Name",
  "owasp": "A01:2021 - Name",
  "impact": "<2 sentence business impact>",
  "remediation": "<specific actionable fix with code/config if applicable>"
}}"""


def _needs_enrichment(f: dict, mode: str) -> bool:
    """Return True if this finding needs enrichment based on the requested mode."""
    if mode == "missing-cvss":
        return f.get("cvss_score") is None
    if mode == "missing-cwe":
        return not f.get("cwe")
    # Default: any missing field counts
    return (
        f.get("cvss_score") is None
        or not f.get("cwe")
        or not f.get("remediation")
    )


def cmd_enrich(args, console: Console) -> None:
    """
    hakuza enrich [--all] [--missing-cvss] [--missing-cwe] [--finding <id>]

    Batch AI enrichment of findings missing CVSS/CWE/impact/remediation.
    """
    eng = _require_engagement(console)

    try:
        client = get_client()
    except SystemExit:
        console.print(
            "[red]Anthropic API key required for enrichment.[/red]\n"
            "[dim]Set it with: hakuza config --set api_key=sk-...[/dim]"
        )
        return

    enrich_all = getattr(args, "all", False)
    missing_cvss = getattr(args, "missing_cvss", False)
    missing_cwe = getattr(args, "missing_cwe", False)
    specific_id = getattr(args, "finding", None)

    all_findings = list_findings(eng["id"])

    # Determine which findings to enrich
    if specific_id:
        target_findings = [
            f for f in all_findings
            if f.get("short_id") == specific_id
            or f["id"] == specific_id
            or f["id"].startswith(specific_id)
        ]
        if not target_findings:
            console.print(f"[red]Finding '{specific_id}' not found in current engagement.[/red]")
            return
        mode = "all"
    elif enrich_all:
        target_findings = all_findings
        mode = "all"
    elif missing_cvss:
        target_findings = [f for f in all_findings if f.get("cvss_score") is None]
        mode = "missing-cvss"
    elif missing_cwe:
        target_findings = [f for f in all_findings if not f.get("cwe")]
        mode = "missing-cwe"
    else:
        # Default: findings with any missing enrichment field
        target_findings = [f for f in all_findings if _needs_enrichment(f, "default")]
        mode = "default"

    if not target_findings:
        console.print("[green]All findings already have the requested enrichment fields.[/green]")
        return

    console.print(
        Panel(
            f"[bold]Engagement:[/bold] {eng['name']}\n"
            f"[bold]Findings to enrich:[/bold] {len(target_findings)}\n"
            f"[bold]Mode:[/bold] {mode}",
            title="[bold cyan]  AI Batch Enrichment[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )

    # Before/after tracking
    enriched_results = []
    failed = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Enriching findings...", total=len(target_findings)
        )

        for f in target_findings:
            progress.update(
                task,
                description=f"Enriching: {f.get('short_id', f['id'][:8])} — {f.get('title', '')[:40]}...",
            )

            prompt = _ENRICH_PROMPT_TEMPLATE.format(
                title=f.get("title", "Unknown"),
                description=(f.get("description") or "No description provided.")[:600],
                url=f.get("url") or "N/A",
            )

            raw = ask_claude(client, prompt, max_tokens=600)
            parsed = _parse_json_from_response(raw)

            if parsed and isinstance(parsed, dict):
                # Coerce CVSS score to float safely
                try:
                    cvss_score = float(parsed.get("cvss_score", 0) or 0)
                    cvss_score = round(min(max(cvss_score, 0.0), 10.0), 1)
                except (TypeError, ValueError):
                    cvss_score = f.get("cvss_score")

                enriched = {
                    "id": f["id"],
                    "short_id": f.get("short_id", f["id"][:8]),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "info"),
                    # Before
                    "before_cvss": f.get("cvss_score"),
                    "before_cwe": f.get("cwe"),
                    "before_remediation": (f.get("remediation") or "")[:60],
                    # After
                    "cvss_score": cvss_score,
                    "cvss_vector": parsed.get("cvss_vector", f.get("cvss_vector")),
                    "cwe": parsed.get("cwe", f.get("cwe")),
                    "owasp": parsed.get("owasp", f.get("owasp")),
                    "impact": parsed.get("impact", f.get("impact")),
                    "remediation": parsed.get("remediation", f.get("remediation")),
                }

                _update_finding_in_db(
                    finding_id=f["id"],
                    cvss_score=enriched["cvss_score"],
                    cvss_vector=enriched["cvss_vector"],
                    cwe=enriched["cwe"],
                    owasp=enriched["owasp"],
                    impact=enriched["impact"],
                    remediation=enriched["remediation"],
                )
                enriched_results.append(enriched)
            else:
                failed.append(f.get("short_id", f["id"][:8]))

            progress.advance(task)

    # Print before/after comparison table
    if enriched_results:
        console.print()
        table = Table(
            title="Enrichment Results",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("ID", width=14, no_wrap=True)
        table.add_column("Sev", width=9, no_wrap=True)
        table.add_column("Title", ratio=2, overflow="ellipsis", no_wrap=True)
        table.add_column("CVSS Before", width=12, justify="center")
        table.add_column("CVSS After", width=11, justify="center")
        table.add_column("CWE", ratio=1, overflow="ellipsis")
        table.add_column("OWASP", ratio=1, overflow="ellipsis")

        for r in enriched_results:
            before_cvss = str(r["before_cvss"]) if r["before_cvss"] is not None else "[dim]-[/dim]"
            after_cvss = (
                f"[bold green]{r['cvss_score']}[/bold green]"
                if r["cvss_score"] is not None else "[dim]-[/dim]"
            )
            table.add_row(
                r["short_id"],
                sev_badge(r["severity"]),
                r["title"][:50],
                before_cvss,
                after_cvss,
                (r["cwe"] or "-")[:30],
                (r["owasp"] or "-")[:25],
            )

        console.print(table)

    summary_lines = [
        f"[bold green]Enrichment complete![/bold green]\n",
        f"[bold]Findings enriched:[/bold] {len(enriched_results)}",
    ]
    if failed:
        summary_lines.append(f"[bold yellow]Failed (AI parse error):[/bold yellow] {', '.join(failed)}")
    summary_lines.append(
        "\n[dim]Run [bold]hakuza findings --full[/bold] to see enriched details.[/dim]"
    )

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold]Enrichment Summary[/bold]",
            border_style="green",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_prioritize
# ---------------------------------------------------------------------------

_BFSI_REGULATORY = {
    "critical": "24 hours (PCI-DSS 6.3.3 / RBI Cybersecurity Framework)",
    "high":     "30 days  (PCI-DSS 6.3.3 / RBI CFD guidelines)",
    "medium":   "90 days  (ISO 27001 Annex A / SEBI CSCRF)",
    "low":      "Next release cycle / quarterly review",
}

_EFFORT_LABEL = {
    "quick":        "[bold green]Quick Fix[/bold green]   (< 1 day)",
    "moderate":     "[bold yellow]Moderate[/bold yellow]     (1-5 days)",
    "architectural":"[bold red]Architectural[/bold red]  (> 1 week)",
}


def cmd_prioritize(args, console: Console) -> None:
    """
    hakuza prioritize [--format table|matrix|timeline] [--bfsi]

    AI-powered remediation prioritization with CVSS, exploitability,
    business impact, effort, and attack-chain potential.
    """
    eng = _require_engagement(console)

    try:
        client = get_client()
    except SystemExit:
        console.print(
            "[red]Anthropic API key required for prioritization.[/red]\n"
            "[dim]Set it with: hakuza config --set api_key=sk-...[/dim]"
        )
        return

    fmt = getattr(args, "format", "table") or "table"
    bfsi = getattr(args, "bfsi", False)

    findings = list_findings(eng["id"])
    open_findings = [f for f in findings if f.get("status") not in ("remediated", "fp")]

    if not open_findings:
        console.print("[yellow]No open findings to prioritize.[/yellow]")
        return

    counts = get_finding_count(eng["id"])
    console.print()
    console.print(Rule("[bold cyan]AI Remediation Prioritization[/bold cyan]", style="dim cyan"))
    print_risk_summary(counts, console)
    console.print()

    findings_text = _serialize_findings_for_ai(open_findings)
    bfsi_context = (
        "\nBFSI CONTEXT: This is a Banking/Financial Services engagement. "
        "Factor in: PCI-DSS compliance deadlines, RBI Cybersecurity Framework, "
        "SEBI CSCRF, data breach notification obligations (72h under GDPR/RBI), "
        "and the elevated financial fraud risk from any auth/injection/IDOR issues."
        if bfsi else ""
    )

    prioritize_prompt = f"""You are a senior VAPT consultant prioritizing remediation for: {eng['name']}
Client: {eng.get('client', 'N/A')} | Target: {eng.get('target', 'N/A')}{bfsi_context}

OPEN FINDINGS:
{findings_text}

Analyze each finding and produce a prioritization with these exact fields for every finding:
- priority_rank: integer starting from 1 (1 = fix first)
- short_id: use the ID from the data
- title: finding title
- cvss: numeric score or estimate
- effort: "quick" | "moderate" | "architectural"
- business_risk: "Critical" | "High" | "Medium" | "Low"
- deadline: realistic deadline string
- rationale: one sentence why this rank

Also provide:
- fix_this_first: short_id of the single finding whose fix provides the MOST risk reduction overall
- fix_this_first_reason: 2-3 sentence explanation

Return ONLY valid JSON (no markdown, no preamble):
{{
  "prioritized": [
    {{
      "priority_rank": 1,
      "short_id": "...",
      "title": "...",
      "cvss": 9.8,
      "effort": "quick",
      "business_risk": "Critical",
      "deadline": "24 hours",
      "rationale": "..."
    }}
  ],
  "fix_this_first": "SHORT_ID",
  "fix_this_first_reason": "..."
}}"""

    console.print("[cyan]Asking Claude to prioritize findings...[/cyan]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("AI prioritization in progress...", total=None)
        raw = ask_claude(client, prioritize_prompt, max_tokens=3000)
        progress.update(task, completed=True)

    parsed = _parse_json_from_response(raw)

    if not parsed or not isinstance(parsed, dict):
        console.print("[red]Failed to parse AI prioritization response.[/red]")
        console.print(f"[dim]{raw[:500]}[/dim]")
        return

    prioritized = parsed.get("prioritized", [])
    fix_first_id = parsed.get("fix_this_first", "")
    fix_first_reason = parsed.get("fix_this_first_reason", "")

    if not prioritized:
        console.print("[yellow]AI returned no prioritized items.[/yellow]")
        return

    # Render based on requested format
    if fmt == "table":
        _render_priority_table(prioritized, bfsi, console)

    elif fmt == "matrix":
        _render_priority_matrix(prioritized, console)

    elif fmt == "timeline":
        _render_priority_timeline(prioritized, bfsi, console)

    else:
        _render_priority_table(prioritized, bfsi, console)

    # Always show "Fix This First" recommendation
    console.print()
    console.print(Rule("[bold red]Fix This First[/bold red]", style="dim red"))
    console.print(
        Panel(
            f"[bold]Finding:[/bold] [cyan]{fix_first_id}[/cyan]\n\n"
            f"{fix_first_reason}",
            title="[bold red]  Highest Risk-Reduction Fix[/bold red]",
            border_style="red",
            expand=False,
        )
    )


def _render_priority_table(prioritized: list, bfsi: bool, console: Console) -> None:
    """Render prioritized findings as a table."""
    table = Table(
        title="Remediation Priority Order",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Finding", ratio=3, overflow="ellipsis", no_wrap=True)
    table.add_column("CVSS", width=6, justify="center")
    table.add_column("Effort", width=14)
    table.add_column("Business Risk", width=14)
    table.add_column("Deadline" if bfsi else "Target", width=28)
    table.add_column("Rationale", ratio=2, overflow="fold")

    effort_style = {
        "quick": "[bold green]Quick Fix[/bold green]",
        "moderate": "[bold yellow]Moderate[/bold yellow]",
        "architectural": "[bold red]Architectural[/bold red]",
    }
    risk_style = {
        "Critical": "[bold red]Critical[/bold red]",
        "High": "[bold orange3]High[/bold orange3]",
        "Medium": "[bold yellow]Medium[/bold yellow]",
        "Low": "[bold green]Low[/bold green]",
    }

    for item in prioritized:
        rank = str(item.get("priority_rank", "?"))
        sid = item.get("short_id", "")
        title = item.get("title", "")[:60]
        cvss = str(item.get("cvss", "-"))
        effort_key = str(item.get("effort", "")).lower()
        effort_str = effort_style.get(effort_key, effort_key)
        risk_key = item.get("business_risk", "")
        risk_str = risk_style.get(risk_key, risk_key)
        deadline = item.get("deadline", "")
        rationale = item.get("rationale", "")[:100]

        table.add_row(rank, f"{sid}: {title}", cvss, effort_str, risk_str, deadline, rationale)

    console.print(table)


def _render_priority_matrix(prioritized: list, console: Console) -> None:
    """Render a 2x2 impact-vs-effort matrix with findings placed in quadrants."""
    # Quadrant assignment
    q1, q2, q3, q4 = [], [], [], []  # High/Low effort × High/Low impact

    for item in prioritized:
        effort_key = str(item.get("effort", "moderate")).lower()
        risk_key = str(item.get("business_risk", "medium")).lower()
        is_high_impact = risk_key in ("critical", "high")
        is_quick = effort_key == "quick"

        entry = f"{item.get('short_id', '?')}: {item.get('title', '')[:35]}"

        if is_high_impact and is_quick:
            q1.append(entry)          # Quick Wins
        elif is_high_impact and not is_quick:
            q2.append(entry)          # Major Projects
        elif not is_high_impact and is_quick:
            q3.append(entry)          # Fill-Ins
        else:
            q4.append(entry)          # Deprioritize

    def _fmt_quadrant(items: list, max_rows: int = 8) -> str:
        if not items:
            return "[dim](none)[/dim]"
        shown = items[:max_rows]
        lines = [f"  • {i}" for i in shown]
        if len(items) > max_rows:
            lines.append(f"  [dim]... +{len(items) - max_rows} more[/dim]")
        return "\n".join(lines)

    console.print(
        Panel(
            f"[bold]IMPACT vs EFFORT MATRIX[/bold]\n\n"
            f"{'─' * 60}\n"
            f"[bold]HIGH IMPACT + LOW EFFORT[/bold]   [green]→ Quick Wins (Do Now)[/green]\n"
            f"{_fmt_quadrant(q1)}\n\n"
            f"[bold]HIGH IMPACT + HIGH EFFORT[/bold]  [yellow]→ Major Projects (Plan)[/yellow]\n"
            f"{_fmt_quadrant(q2)}\n\n"
            f"[bold]LOW IMPACT + LOW EFFORT[/bold]    [blue]→ Fill-Ins (If Time)[/blue]\n"
            f"{_fmt_quadrant(q3)}\n\n"
            f"[bold]LOW IMPACT + HIGH EFFORT[/bold]   [dim]→ Deprioritize / Accept Risk[/dim]\n"
            f"{_fmt_quadrant(q4)}",
            title="[bold cyan]  Impact vs Effort Matrix[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )


def _render_priority_timeline(prioritized: list, bfsi: bool, console: Console) -> None:
    """Render prioritized findings bucketed into timeline groups."""
    # Bucket by deadline/business_risk
    week1, month1, quarter1, longterm = [], [], [], []

    for item in prioritized:
        risk = str(item.get("business_risk", "medium")).lower()
        effort = str(item.get("effort", "moderate")).lower()
        entry = f"{item.get('short_id', '?')}: {item.get('title', '')[:50]}"

        if risk == "critical" or (risk == "high" and effort == "quick"):
            week1.append(entry)
        elif risk == "high" or (risk == "medium" and effort == "quick"):
            month1.append(entry)
        elif risk == "medium":
            quarter1.append(entry)
        else:
            longterm.append(entry)

    def _bucket(label: str, items: list, color: str, deadline: str) -> str:
        header = f"[{color}][bold]{label}[/bold][/{color}]  [dim]{deadline}[/dim]"
        if not items:
            return f"{header}\n  [dim](none)[/dim]"
        return header + "\n" + "\n".join(f"  [{color}]•[/{color}] {i}" for i in items)

    w1_deadline = _BFSI_REGULATORY.get("critical", "0-7 days") if bfsi else "0-7 days"
    m1_deadline = _BFSI_REGULATORY.get("high", "7-30 days") if bfsi else "7-30 days"
    q1_deadline = _BFSI_REGULATORY.get("medium", "30-90 days") if bfsi else "30-90 days"
    lt_deadline = _BFSI_REGULATORY.get("low", "Long-term") if bfsi else "Long-term / Next release"

    body = "\n\n".join([
        _bucket("WEEK 1 — Emergency", week1, "red", w1_deadline),
        _bucket("MONTH 1 — Urgent", month1, "orange3", m1_deadline),
        _bucket("QUARTER 1 — Planned", quarter1, "yellow", q1_deadline),
        _bucket("LONG-TERM — Hardening", longterm, "green", lt_deadline),
    ])

    console.print(
        Panel(
            body,
            title="[bold cyan]  Remediation Timeline[/bold cyan]"
            + (" [dim](BFSI regulatory deadlines)[/dim]" if bfsi else ""),
            border_style="cyan",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# cmd_matrix
# ---------------------------------------------------------------------------

_CHAIN_SYMBOL = {
    "directly chainable":   "●",
    "indirectly related":   "○",
    "no chain":             "×",
}

_CHAIN_STYLE = {
    "●": "[bold green]●[/bold green]",
    "○": "[bold yellow]○[/bold yellow]",
    "×": "[dim]×[/dim]",
}


def cmd_matrix(args, console: Console) -> None:
    """
    hakuza matrix [--save]

    Generate a full attack-chain matrix showing which findings can be combined,
    plus the top 3 chains with step-by-step exploitation.
    """
    eng = _require_engagement(console)

    try:
        client = get_client()
    except SystemExit:
        console.print(
            "[red]Anthropic API key required for matrix generation.[/red]\n"
            "[dim]Set it with: hakuza config --set api_key=sk-...[/dim]"
        )
        return

    save = getattr(args, "save", False)

    findings = list_findings(eng["id"])
    open_findings = [f for f in findings if f.get("status") not in ("remediated", "fp")]

    if len(open_findings) < 2:
        console.print("[yellow]Need at least 2 open findings to build an attack chain matrix.[/yellow]")
        return

    # Cap at 20 findings to keep the matrix readable
    matrix_findings = open_findings[:20]
    if len(open_findings) > 20:
        console.print(
            f"[yellow]Capping matrix to the top 20 findings "
            f"(of {len(open_findings)} open). Highest severity selected.[/yellow]"
        )

    console.print()
    console.print(Rule("[bold cyan]AI Attack Chain Matrix[/bold cyan]", style="dim cyan"))
    console.print(f"[dim]Analysing {len(matrix_findings)} findings for chain relationships...[/dim]\n")

    findings_text = _serialize_findings_for_ai(matrix_findings)

    # Build ID list for matrix
    id_list = ", ".join(
        f.get("short_id", f["id"][:8]) for f in matrix_findings
    )

    matrix_prompt = f"""You are a senior penetration tester building an attack chain matrix.

FINDINGS:
{findings_text}

Finding IDs in order: {id_list}

TASK 1 — Attack Chain Matrix:
For every pair of findings (A, B), classify their relationship:
- "directly chainable": exploiting A directly enables or escalates B (e.g. SSRF→RCE, IDOR→data exfil)
- "indirectly related": A provides useful context or partial access for B
- "no chain": no meaningful attack relationship

Return the matrix as a JSON object where keys are "ID1|ID2" pairs (both orderings, A|B and B|A).

TASK 2 — Top 3 Attack Chains:
Describe the top 3 most dangerous complete attack chains, each with:
- chain_title: descriptive name
- severity: Critical/High/Medium
- steps: list of step strings (each is "Action — specific command or payload")
- end_impact: specific final impact
- cvss_chain_score: estimated combined CVSS float

Return ONLY valid JSON (no markdown):
{{
  "matrix": {{
    "ID1|ID2": "directly chainable",
    "ID2|ID1": "directly chainable",
    "ID1|ID3": "no chain",
    "ID3|ID1": "no chain"
  }},
  "top_chains": [
    {{
      "chain_title": "...",
      "severity": "Critical",
      "steps": ["Step 1 — ...", "Step 2 — ..."],
      "end_impact": "...",
      "cvss_chain_score": 9.8
    }}
  ]
}}"""

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress_task = progress.add_task("Building attack chain matrix...", total=None)
        raw = ask_claude(client, matrix_prompt, max_tokens=4000)
        progress.update(progress_task, completed=True)

    parsed = _parse_json_from_response(raw)

    if not parsed or not isinstance(parsed, dict):
        console.print("[red]Failed to parse AI matrix response.[/red]")
        console.print(f"[dim]{raw[:500]}[/dim]")
        return

    matrix_data = parsed.get("matrix", {})
    top_chains = parsed.get("top_chains", [])

    # Build ordered list of short_ids
    short_ids = [f.get("short_id", f["id"][:8]) for f in matrix_findings]
    # Truncate to 12 chars for display
    display_ids = [sid[:12] for sid in short_ids]

    # Render the matrix table
    if matrix_data and len(short_ids) >= 2:
        _render_chain_matrix_table(short_ids, display_ids, matrix_data, matrix_findings, console)
    else:
        console.print("[yellow]Insufficient matrix data returned by AI.[/yellow]")

    # Render top chains
    if top_chains:
        console.print()
        console.print(Rule("[bold red]Top Attack Chains[/bold red]", style="dim red"))
        _render_top_chains(top_chains, console)

    # Legend
    console.print(
        "\n[dim]"
        "[bold green]●[/bold green] Directly chainable (escalates impact)  "
        "[bold yellow]○[/bold yellow] Indirectly related (provides context)  "
        "[dim]×[/dim] No meaningful chain"
        "[/dim]"
    )

    # Save to file if requested
    if save:
        _save_matrix_to_file(eng, short_ids, matrix_data, top_chains, matrix_findings, console)


def _render_chain_matrix_table(
    short_ids: list,
    display_ids: list,
    matrix_data: dict,
    findings: list,
    console: Console,
) -> None:
    """Render the attack chain matrix as a Rich table."""
    # Map full short_id → display_id
    id_to_display = dict(zip(short_ids, display_ids))

    # Column width: need space for row labels + N columns
    max_cols = min(len(short_ids), 15)  # hard cap for terminal width
    col_ids = short_ids[:max_cols]
    col_displays = display_ids[:max_cols]

    table = Table(
        title="Attack Chain Matrix",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=False,
        padding=(0, 1),
    )

    # Add header columns
    table.add_column("Finding", style="dim", width=14, no_wrap=True)
    for did in col_displays:
        table.add_column(did, width=6, justify="center", no_wrap=True)

    # Build row for each finding
    sev_abbr = {"critical": "C", "high": "H", "medium": "M", "low": "L", "informational": "I", "info": "I"}

    for row_f in findings:
        row_sid = row_f.get("short_id", row_f["id"][:8])
        row_sev = (row_f.get("severity") or "info").lower()
        sev_label = sev_abbr.get(row_sev, "?")
        row_label = f"{row_sid[:10]} [{sev_label}]"

        cells = []
        for col_sid in col_ids:
            if col_sid == row_sid:
                cells.append("[dim] — [/dim]")
            else:
                # Look up relationship in both directions
                rel = matrix_data.get(f"{row_sid}|{col_sid}") or matrix_data.get(f"{col_sid}|{row_sid}", "")
                rel_lower = rel.lower()
                if "directly" in rel_lower or "direct" in rel_lower:
                    cells.append(_CHAIN_STYLE["●"])
                elif "indirect" in rel_lower or "related" in rel_lower:
                    cells.append(_CHAIN_STYLE["○"])
                else:
                    cells.append(_CHAIN_STYLE["×"])

        table.add_row(row_label, *cells)

    console.print(table)


def _render_top_chains(top_chains: list, console: Console) -> None:
    """Render the top attack chains as panels."""
    sev_colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}

    for i, chain in enumerate(top_chains[:3], start=1):
        sev = (chain.get("severity") or "medium").lower()
        color = sev_colors.get(sev, "cyan")
        cvss = chain.get("cvss_chain_score", "?")
        steps = chain.get("steps", [])
        steps_text = "\n".join(f"  {j}. {s}" for j, s in enumerate(steps, start=1))

        body = (
            f"[bold]Severity:[/bold] {sev_badge(sev)}  [bold]CVSS Chain:[/bold] {cvss}\n\n"
            f"[bold underline]Steps:[/bold underline]\n{steps_text}\n\n"
            f"[bold]End Impact:[/bold] {chain.get('end_impact', 'N/A')}"
        )

        console.print(
            Panel(
                body,
                title=f"[bold {color}]  Chain {i}: {chain.get('chain_title', 'Unknown')}[/bold {color}]",
                border_style=color,
                expand=False,
            )
        )


def _save_matrix_to_file(
    eng: dict,
    short_ids: list,
    matrix_data: dict,
    top_chains: list,
    findings: list,
    console: Console,
) -> None:
    """Serialize the matrix and chains to a markdown file in the engagement dir."""
    from pathlib import Path

    eng_name = eng.get("name", "engagement")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path.home() / ".hakuza" / "engagements" / eng_name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"attack_matrix_{ts}.md"

    lines = [
        f"# Attack Chain Matrix — {eng_name}\n",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n",
        f"**Findings analysed:** {len(findings)}\n\n",
        "---\n\n",
        "## Matrix\n\n",
        "| Finding | " + " | ".join(sid[:12] for sid in short_ids) + " |\n",
        "|---------|" + "|".join("--------" for _ in short_ids) + "|\n",
    ]

    for row_f in findings:
        row_sid = row_f.get("short_id", row_f["id"][:8])
        cells = []
        for col_sid in short_ids:
            if col_sid == row_sid:
                cells.append(" - ")
            else:
                rel = matrix_data.get(f"{row_sid}|{col_sid}") or matrix_data.get(f"{col_sid}|{row_sid}", "")
                rel_l = rel.lower()
                if "directly" in rel_l or "direct" in rel_l:
                    cells.append(" ● ")
                elif "indirect" in rel_l or "related" in rel_l:
                    cells.append(" ○ ")
                else:
                    cells.append(" × ")
        lines.append(f"| {row_sid[:12]} | {'|'.join(cells)} |\n")

    lines.append("\n**Legend:** ● Directly chainable  ○ Indirectly related  × No chain\n\n")
    lines.append("---\n\n## Top Attack Chains\n\n")

    for i, chain in enumerate(top_chains, start=1):
        lines.append(f"### Chain {i}: {chain.get('chain_title', 'Unknown')}\n\n")
        lines.append(f"**Severity:** {chain.get('severity', '?')} | **CVSS:** {chain.get('cvss_chain_score', '?')}\n\n")
        lines.append("**Steps:**\n")
        for j, step in enumerate(chain.get("steps", []), start=1):
            lines.append(f"{j}. {step}\n")
        lines.append(f"\n**End Impact:** {chain.get('end_impact', 'N/A')}\n\n")

    out_path.write_text("".join(lines), encoding="utf-8")
    console.print(f"\n[green]Matrix saved:[/green] {out_path}")


# ---------------------------------------------------------------------------
# ARGPARSE REGISTRATION
# ---------------------------------------------------------------------------
# To wire these commands into hakuza.py's build_parser() and dispatch table,
# add the following snippet inside build_parser() and in the dispatch dict.
#
# ── build_parser() additions ────────────────────────────────────────────────
#
#   # --- deduplicate ---
#   p_dedup = sub.add_parser("deduplicate", help="AI deduplication of findings")
#   p_dedup.add_argument("--dry-run", action="store_true", dest="dry_run",
#                        help="Show what would be merged without making changes")
#   p_dedup.add_argument("--auto", action="store_true",
#                        help="Auto-mark duplicates without confirmation")
#
#   # --- enrich ---
#   p_enrich = sub.add_parser("enrich", help="AI batch enrichment of findings")
#   p_enrich.add_argument("--all", action="store_true", dest="all",
#                         help="Enrich all findings regardless of missing fields")
#   p_enrich.add_argument("--missing-cvss", action="store_true", dest="missing_cvss",
#                         help="Only enrich findings missing CVSS score")
#   p_enrich.add_argument("--missing-cwe", action="store_true", dest="missing_cwe",
#                         help="Only enrich findings missing CWE")
#   p_enrich.add_argument("--finding", default=None,
#                         help="Enrich a single finding by short ID or UUID prefix")
#
#   # --- prioritize ---
#   p_prio = sub.add_parser("prioritize", help="AI remediation prioritization")
#   p_prio.add_argument("--format", choices=["table", "matrix", "timeline"],
#                       default="table", help="Output format")
#   p_prio.add_argument("--bfsi", action="store_true",
#                       help="Apply BFSI regulatory deadlines (PCI-DSS/RBI)")
#
#   # --- matrix ---
#   p_matrix = sub.add_parser("matrix", help="Generate attack chain matrix")
#   p_matrix.add_argument("--save", action="store_true",
#                         help="Save matrix to engagement directory as markdown")
#
# ── dispatch dict additions ──────────────────────────────────────────────────
#
#   "deduplicate": cmd_deduplicate,   # from mod_ai_batch
#   "enrich":      cmd_enrich,        # from mod_ai_batch
#   "prioritize":  cmd_prioritize,    # from mod_ai_batch
#   "matrix":      cmd_matrix,        # from mod_ai_batch

# END mod_ai_batch.py
