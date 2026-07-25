"""
mod_dashboard.py — HAKUZA Live Dashboard
Full-screen TUI dashboard for the HAKUZA pentest platform.

Usage: hakuza dashboard [--refresh <seconds>] [--no-ai]

Imports everything it needs from the hakuza module when used standalone,
or relies on the shared namespace when imported by hakuza.py.
"""

import shutil
import time
import threading
from datetime import datetime
from typing import Optional

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box
from rich.padding import Padding

# ---------------------------------------------------------------------------
# These names are resolved at call time from the hakuza module namespace.
# When this file is exec'd/imported inside hakuza.py they already exist.
# ---------------------------------------------------------------------------
# _require_engagement, get_client_or_none, list_findings, get_finding_count,
# get_db, SEVERITY_ORDER, SEV_COLORS, HAKUZA_DIR, ENGAGEMENTS_DIR,
# sev_badge, ask_claude, SYSTEM_PROMPT
# ---------------------------------------------------------------------------

# Key tools to probe with shutil.which()
_DASHBOARD_TOOLS = [
    "nmap",
    "nuclei",
    "sqlmap",
    "subfinder",
    "httpx",
    "ffuf",
    "jadx",
    "gobuster",
]

# ---------------------------------------------------------------------------
# RISK GAUGE
# ---------------------------------------------------------------------------

def _render_risk_gauge(score: int, width: int = 36) -> Text:
    """
    Return a Rich Text object that draws an ASCII progress bar
    with a colour-coded label based on the score (0-100).
    """
    score = max(0, min(100, score))
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)

    if score >= 70:
        color = "red"
        label = "CRITICAL RISK"
    elif score >= 40:
        color = "orange3"
        label = "HIGH RISK"
    elif score >= 20:
        color = "yellow"
        label = "MEDIUM RISK"
    else:
        color = "green"
        label = "LOW RISK"

    t = Text()
    t.append(bar, style=color)
    t.append(f"  {score}/100  {label}", style=f"bold {color}")
    return t


def _compute_risk_score(counts: dict) -> int:
    """
    Derive a 0-100 risk score from finding counts.
    Weighting: critical=25, high=10, medium=4, low=1 (capped at 100).
    """
    score = (
        counts.get("critical", 0) * 25
        + counts.get("high", 0) * 10
        + counts.get("medium", 0) * 4
        + counts.get("low", 0) * 1
    )
    return min(100, score)


# ---------------------------------------------------------------------------
# TOOL STATUS
# ---------------------------------------------------------------------------

def _check_tool_status() -> dict:
    """Return {tool_name: bool} for each dashboard tool using shutil.which."""
    return {tool: shutil.which(tool) is not None for tool in _DASHBOARD_TOOLS}


# ---------------------------------------------------------------------------
# SEVERITY BAR (ASCII histogram)
# ---------------------------------------------------------------------------

def _sev_bar(count: int, max_count: int, width: int = 16) -> Text:
    """Return a coloured block bar scaled to max_count."""
    if max_count == 0:
        filled = 0
    else:
        filled = max(1, int(count / max_count * width)) if count > 0 else 0
    bar = "█" * filled + " " * (width - filled)
    return Text(bar)


# ---------------------------------------------------------------------------
# PANEL BUILDERS
# ---------------------------------------------------------------------------

def _build_header_panel(eng: dict, refresh_count: int) -> Panel:
    """Top header bar: HAKUZA | engagement name | client | LIVE indicator."""
    name = eng.get("name", "unknown")
    client = eng.get("client", "")
    target = eng.get("target", "")
    eng_type = eng.get("type", "web").upper()

    t = Text(justify="center")
    t.append("  HAKUZA  ", style="bold cyan on black")
    t.append("  |  ", style="dim white")
    t.append(name, style="bold white")
    t.append("  |  ", style="dim white")
    t.append(client, style="bold yellow")
    t.append("  |  ", style="dim white")
    t.append(target[:40], style="dim cyan")
    t.append("  |  ", style="dim white")
    t.append(eng_type, style="bold magenta")
    t.append("  |  ", style="dim white")
    t.append("● LIVE", style="bold red blink")
    t.append(f"  [refresh #{refresh_count}]", style="dim")

    return Panel(t, style="bold cyan", padding=(0, 1))


def _build_gauge_panel(counts: dict) -> Panel:
    """Left panel: risk score gauge."""
    score = _compute_risk_score(counts)
    gauge = _render_risk_gauge(score, width=34)

    total = sum(counts.values())
    action_text = (
        "Immediate action required" if score >= 70
        else "Urgent remediation needed" if score >= 40
        else "Monitor and plan remediation" if score >= 20
        else "Risk within acceptable range"
    )

    content = Text()
    content.append("\n  Risk Score\n\n", style="bold white")
    content.append("  ")
    content.append_text(gauge)
    content.append(f"\n\n  {action_text}\n", style="dim italic")
    content.append(f"\n  Total findings: ", style="dim")
    content.append(str(total), style="bold white")

    return Panel(
        content,
        title="[bold]RISK GAUGE[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_severity_panel(counts: dict) -> Panel:
    """Right panel: severity breakdown with ASCII bar chart."""
    sev_order = ["critical", "high", "medium", "low", "informational"]
    sev_display = {
        "critical": ("CRITICAL", "bold red"),
        "high": ("HIGH    ", "bold orange3"),
        "medium": ("MEDIUM  ", "bold yellow"),
        "low": ("LOW     ", "bold green"),
        "informational": ("INFO    ", "bold blue"),
    }

    max_count = max((counts.get(s, 0) for s in sev_order), default=1) or 1

    table = Table(
        box=None,
        show_header=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("sev", width=10)
    table.add_column("bar", ratio=1)
    table.add_column("cnt", width=5, justify="right")

    for sev in sev_order:
        label, style = sev_display[sev]
        cnt = counts.get(sev, 0)
        bar = _sev_bar(cnt, max_count, width=18)
        bar.stylize(style)
        table.add_row(
            Text(label, style=style),
            bar,
            Text(str(cnt), style=style),
        )

    return Panel(
        table,
        title="[bold]SEVERITY BREAKDOWN[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_findings_panel(findings: list) -> Panel:
    """Findings table: top 8 by severity."""
    top8 = findings[:8]

    if not top8:
        return Panel(
            Align.center(Text("No findings yet.", style="dim italic"), vertical="middle"),
            title="[bold]RECENT FINDINGS[/bold]  [dim](top 8 by severity)[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("ID", width=14, no_wrap=True)
    table.add_column("SEV", width=10, no_wrap=True)
    table.add_column("Title", ratio=3, overflow="ellipsis", no_wrap=True)
    table.add_column("CVSS", width=6, justify="right", no_wrap=True)
    table.add_column("Status", width=11, no_wrap=True)

    sev_row_style = {
        "critical": "on dark_red",
        "high": "on dark_orange",
        "medium": "",
        "low": "",
        "informational": "",
        "info": "",
    }

    for f in top8:
        sev = (f.get("severity") or "informational").lower()
        color = SEV_COLORS.get(sev, "white")
        row_style = sev_row_style.get(sev, "")
        cvss_val = f.get("cvss_score")
        cvss_str = f"{cvss_val:.1f}" if cvss_val is not None else "-"
        short_id = f.get("short_id") or (f.get("id") or "")[:8]
        status = f.get("status", "open")

        table.add_row(
            Text(short_id, style=f"dim {row_style}"),
            Text(sev.upper(), style=f"{color} {row_style}"),
            Text(f.get("title", "")[:55], style=row_style),
            Text(cvss_str, style=f"bold {color} {row_style}"),
            Text(status, style=f"dim {row_style}"),
        )

    return Panel(
        table,
        title="[bold]RECENT FINDINGS[/bold]  [dim](top 8 by severity)[/dim]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_tools_panel(tools_status: dict) -> Panel:
    """Tool availability panel."""
    table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    table.add_column("tool", width=12, no_wrap=True)
    table.add_column("status", width=14, no_wrap=True)

    for tool, installed in tools_status.items():
        if installed:
            status_text = Text("✓ installed", style="bold green")
        else:
            status_text = Text("✗ missing", style="bold red")
        table.add_row(Text(tool, style="white"), status_text)

    return Panel(
        table,
        title="[bold]TOOL STATUS[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_timeline_panel(eng: dict, counts: dict, findings: list) -> Panel:
    """Engagement timeline and stats panel."""
    start_date = eng.get("start_date", "unknown")
    end_date = eng.get("end_date") or "ongoing"
    tester = eng.get("tester", "")
    eng_type = eng.get("type", "web")
    target = eng.get("target", "")

    total = sum(counts.values())
    critical_open = sum(
        1 for f in findings
        if (f.get("severity") or "").lower() == "critical"
        and f.get("status", "open") in ("open", "confirmed")
    )
    high_confirmed = sum(
        1 for f in findings
        if (f.get("severity") or "").lower() == "high"
        and f.get("status", "open") == "confirmed"
    )
    remediated = sum(
        1 for f in findings
        if f.get("status", "open") == "remediated"
    )

    # Duration calculation
    duration_str = ""
    try:
        start_dt = datetime.fromisoformat(start_date)
        delta = datetime.now() - start_dt
        days = delta.days
        hours = delta.seconds // 3600
        duration_str = f"{days}d {hours}h"
    except (ValueError, TypeError):
        duration_str = "N/A"

    lines = Text()
    lines.append("  Started:    ", style="dim")
    lines.append(f"{start_date}\n", style="bold white")
    lines.append("  Duration:   ", style="dim")
    lines.append(f"{duration_str}\n", style="bold white")
    lines.append("  End date:   ", style="dim")
    lines.append(f"{end_date}\n", style="white")
    lines.append("  Type:       ", style="dim")
    lines.append(f"{eng_type}\n", style="bold cyan")
    lines.append("  Tester:     ", style="dim")
    lines.append(f"{tester}\n\n", style="white")
    lines.append("  Findings:   ", style="dim")
    lines.append(f"{total} total\n", style="bold white")
    lines.append("  Critical:   ", style="dim")
    lines.append(f"{counts.get('critical', 0)} ", style="bold red")
    lines.append(f"({critical_open} open)\n", style="dim red")
    lines.append("  High:       ", style="dim")
    lines.append(f"{counts.get('high', 0)} ", style="bold orange3")
    lines.append(f"({high_confirmed} confirmed)\n", style="dim orange3")
    lines.append("  Remediated: ", style="dim")
    lines.append(f"{remediated}\n", style="bold green")

    return Panel(
        lines,
        title="[bold]ENGAGEMENT TIMELINE[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_next_steps_panel(counts: dict, ai_notes: Optional[str]) -> Panel:
    """Next steps panel with static heuristics + optional AI notes."""
    suggestions = []

    if counts.get("critical", 0) > 0:
        suggestions.append(("[bold red]1.[/bold red]", "Verify and exploit all CRITICAL findings immediately"))
    if counts.get("high", 0) > 0:
        suggestions.append(("[bold orange3]2.[/bold orange3]", "Manually confirm HIGH findings — check for chains"))
    if counts.get("critical", 0) == 0 and counts.get("high", 0) == 0:
        suggestions.append(("[bold yellow]1.[/bold yellow]", "Run nuclei full profile: nuclei -u <target> -tags cves"))
        suggestions.append(("[bold yellow]2.[/bold yellow]", "Fuzz API endpoints: ffuf -w params.txt -u <url>/FUZZ"))
    suggestions.append(("[bold cyan]3.[/bold cyan]", "hakuza analyze  — AI deep dive on all findings"))
    suggestions.append(("[bold cyan]4.[/bold cyan]", "hakuza report   — generate the pentest report"))
    suggestions.append(("[bold cyan]5.[/bold cyan]", "hakuza chain    — build exploit chains"))

    content = Text()
    for num, step in suggestions[:5]:
        content.append_text(Text.from_markup(f"  {num} "))
        content.append(f"{step}\n", style="white")

    if ai_notes:
        content.append("\n  [AI] ", style="bold cyan")
        content.append(ai_notes[:120], style="dim italic")

    return Panel(
        content,
        title="[bold]NEXT STEPS[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_footer_panel(last_refresh: str, refresh_interval: int) -> Panel:
    """Footer keybindings and last refresh timestamp."""
    t = Text(justify="center")
    t.append("  [q] quit  ", style="bold white")
    t.append(" | ", style="dim")
    t.append("  [r] refresh  ", style="bold white")
    t.append(" | ", style="dim")
    t.append("  [a] AI analysis  ", style="bold cyan")
    t.append(" | ", style="dim")
    t.append(f"  auto-refresh every {refresh_interval}s  ", style="dim")
    t.append(" | ", style="dim")
    t.append(f"  last: {last_refresh}  ", style="dim green")
    return Panel(t, style="dim", padding=(0, 0))


# ---------------------------------------------------------------------------
# FULL RENDERABLE BUILDER
# ---------------------------------------------------------------------------

def _render_dashboard(
    eng: dict,
    findings: list,
    counts: dict,
    tools_status: dict,
    refresh_count: int,
    refresh_interval: int,
    ai_notes: Optional[str] = None,
) -> Group:
    """
    Assemble and return a Rich Group that represents the full dashboard.
    Uses stacked Panels rather than Layout so it degrades gracefully on
    any terminal width.
    """
    last_refresh = datetime.now().strftime("%H:%M:%S")

    header = _build_header_panel(eng, refresh_count)

    # Stats row: gauge left, severity right
    gauge_panel = _build_gauge_panel(counts)
    sev_panel = _build_severity_panel(counts)

    stats_table = Table(box=None, show_header=False, padding=(0, 0), expand=True)
    stats_table.add_column("left", ratio=2)
    stats_table.add_column("right", ratio=3)
    stats_table.add_row(gauge_panel, sev_panel)
    stats_row = Panel(stats_table, box=box.SIMPLE, padding=(0, 0), style="")

    findings_panel = _build_findings_panel(findings)

    # Bottom row: tools left, timeline right
    tools_panel = _build_tools_panel(tools_status)
    timeline_panel = _build_timeline_panel(eng, counts, findings)

    bottom_table = Table(box=None, show_header=False, padding=(0, 0), expand=True)
    bottom_table.add_column("left", ratio=1)
    bottom_table.add_column("right", ratio=1)
    bottom_table.add_row(tools_panel, timeline_panel)
    bottom_row = Panel(bottom_table, box=box.SIMPLE, padding=(0, 0), style="")

    next_steps = _build_next_steps_panel(counts, ai_notes)
    footer = _build_footer_panel(last_refresh, refresh_interval)

    return Group(
        header,
        stats_row,
        findings_panel,
        bottom_row,
        next_steps,
        footer,
    )


# ---------------------------------------------------------------------------
# AI ANALYSIS (background thread)
# ---------------------------------------------------------------------------

def _fetch_ai_notes(eng: dict, findings: list, counts: dict, result_holder: list) -> None:
    """
    Called in a background thread.  Fetches a short AI triage summary
    and stores it in result_holder[0].
    """
    try:
        client = get_client_or_none()
        if client is None:
            result_holder[0] = "[no API key]"
            return

        summary = (
            f"Engagement: {eng['name']} | Client: {eng['client']} | "
            f"Target: {eng['target']} | Type: {eng.get('type','web')}\n"
            f"Critical: {counts.get('critical',0)}  High: {counts.get('high',0)}  "
            f"Medium: {counts.get('medium',0)}  Low: {counts.get('low',0)}\n"
            f"Top findings: "
            + ", ".join(f.get("title","?") for f in findings[:5])
        )

        prompt = (
            f"Given this engagement state:\n{summary}\n\n"
            f"In ONE sentence (max 120 chars), state the single most critical "
            f"action the tester should take right now. No preamble."
        )
        note = ask_claude(client, prompt, max_tokens=80)
        result_holder[0] = note.strip()
    except Exception as exc:
        result_holder[0] = f"[AI error: {exc}]"


# ---------------------------------------------------------------------------
# MAIN COMMAND
# ---------------------------------------------------------------------------

def cmd_dashboard(args, console: Console) -> None:
    """
    hakuza dashboard [--refresh <seconds>] [--no-ai]

    Opens a full-screen Rich Live dashboard that auto-refreshes every N seconds
    (default 3).  Press q to quit, r to force refresh, a to trigger AI analysis.
    """
    eng = _require_engagement(console)

    refresh_interval = int(getattr(args, "refresh", None) or 3)
    no_ai = bool(getattr(args, "no_ai", False))

    # Shared mutable state
    quit_flag = [False]
    force_refresh = [False]
    trigger_ai = [False]
    ai_notes: list = [None]           # ai_notes[0] holds the latest AI line
    ai_running = [False]

    refresh_count = 0

    # Initial data fetch
    findings = list_findings(eng["id"])
    counts = get_finding_count(eng["id"])
    tools_status = _check_tool_status()

    # Non-blocking keyboard input (best-effort on Linux/macOS)
    def _kb_listener():
        """Read single characters from stdin without echo (Unix only)."""
        import sys
        import termios
        import tty
        import select

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while not quit_flag[0]:
                ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                if ready:
                    ch = sys.stdin.read(1)
                    if ch in ("q", "Q"):
                        quit_flag[0] = True
                    elif ch in ("r", "R"):
                        force_refresh[0] = True
                    elif ch in ("a", "A"):
                        trigger_ai[0] = True
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    kb_thread = threading.Thread(target=_kb_listener, daemon=True)
    kb_thread.start()

    try:
        with Live(
            console=console,
            refresh_per_second=0.5,
            screen=True,
        ) as live:
            last_data_refresh = 0.0

            while not quit_flag[0]:
                now = time.monotonic()

                # AI trigger
                if trigger_ai[0] and not ai_running[0]:
                    trigger_ai[0] = False
                    ai_running[0] = True

                    def _ai_worker():
                        _fetch_ai_notes(eng, findings, counts, ai_notes)
                        ai_running[0] = False

                    threading.Thread(target=_ai_worker, daemon=True).start()

                # Data refresh
                if force_refresh[0] or (now - last_data_refresh) >= refresh_interval:
                    force_refresh[0] = False
                    last_data_refresh = now
                    refresh_count += 1
                    try:
                        findings = list_findings(eng["id"])
                        counts = get_finding_count(eng["id"])
                        # Re-fetch engagement in case it was updated
                        from hakuza import get_current_engagement  # noqa: F401 — available in ns
                        fresh_eng = get_current_engagement()
                        if fresh_eng:
                            eng = fresh_eng
                    except Exception:
                        pass  # Keep last good data on DB error

                renderable = _render_dashboard(
                    eng=eng,
                    findings=findings,
                    counts=counts,
                    tools_status=tools_status,
                    refresh_count=refresh_count,
                    refresh_interval=refresh_interval,
                    ai_notes=ai_notes[0],
                )
                live.update(renderable)
                time.sleep(0.2)

    except KeyboardInterrupt:
        pass
    finally:
        quit_flag[0] = True

    console.print("[dim]Dashboard closed.[/dim]")


# ---------------------------------------------------------------------------
# ARGPARSE ADDITIONS  (add to build_parser() in hakuza.py)
# ---------------------------------------------------------------------------
# In build_parser(), inside the sub-commands block, add:
#
#   # --- dashboard ---
#   p_dash = sub.add_parser("dashboard", help="Live full-screen TUI dashboard")
#   p_dash.add_argument(
#       "--refresh", type=int, default=3, metavar="SECONDS",
#       help="Auto-refresh interval in seconds (default: 3)"
#   )
#   p_dash.add_argument(
#       "--no-ai", dest="no_ai", action="store_true",
#       help="Disable AI analysis on startup"
#   )
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DISPATCH ADDITION  (add to the dispatch dict in main() in hakuza.py)
# ---------------------------------------------------------------------------
# Import at top of hakuza.py:
#   from mod_dashboard import cmd_dashboard
#
# In the dispatch dict:
#   "dashboard": cmd_dashboard,
# ---------------------------------------------------------------------------

# END mod_dashboard.py
