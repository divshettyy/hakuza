#!/usr/bin/env python3
"""
HAKUZA Orchestration Module — ReAct-style autonomous agent loop
Reads engagement state, decides next test, executes, repeats
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime
import anthropic

# Requires: mod_techniques to be loaded
try:
    from mod_technique_executors import execute_technique
    HAS_EXECUTORS = True
except ImportError:
    HAS_EXECUTORS = False

try:
    from mod_techniques import load_techniques
    HAS_TECHNIQUES = True
except ImportError:
    HAS_TECHNIQUES = False


# Lazy-load hakuza module helpers
def _n(attr):
    """Fetch attribute from hakuza module at call-time."""
    import importlib
    hakuza = importlib.import_module("hakuza")
    return getattr(hakuza, attr)


# Global console and other required references
console = None
Confirm = None
SYSTEM_PROMPT = """You are HAKUZA, an autonomous penetration testing orchestrator."""


def _init_globals():
    """Initialize global references from hakuza on first use."""
    global console, Confirm, SYSTEM_PROMPT
    if console is None:
        try:
            from rich.console import Console
            from rich.prompt import Confirm as RichConfirm
            console = Console()
            Confirm = RichConfirm
        except ImportError:
            import sys
            class SimpleConsole:
                def print(self, msg):
                    print(msg)
            class SimpleConfirm:
                @staticmethod
                def ask(msg):
                    return input(f"{msg} (y/n): ").lower().startswith('y')
            console = SimpleConsole()
            Confirm = SimpleConfirm
    return console


# Wrapper functions for hakuza module dependencies
def get_engagement(name: str = None) -> Optional[Dict[str, Any]]:
    """Wrapper for hakuza.get_engagement()."""
    try:
        return _n("get_engagement")(name)
    except Exception:
        return None


def list_findings(engagement_id: str, severity_filter: str = None) -> List[Dict]:
    """Wrapper for hakuza.list_findings()."""
    try:
        return _n("list_findings")(engagement_id, severity_filter)
    except Exception:
        return []


def get_config_value(key: str) -> Optional[str]:
    """Wrapper for hakuza.get_config_value()."""
    try:
        return _n("get_config_value")(key)
    except Exception:
        return None


def build_orchestration_prompt(engagement: Dict[str, Any], findings: List[Dict[str, Any]],
                               available_techniques: List[Dict[str, Any]]) -> str:
    """Build a ReAct prompt for the orchestrator to decide the next action."""

    findings_summary = ""
    if findings:
        findings_summary = "## Current Findings\n\n"
        for f in findings[:5]:  # Last 5 findings
            findings_summary += f"- [{f['severity'].upper()}] {f['title']}\n"
            if f.get('cve'):
                findings_summary += f"  CVE: {f['cve']}\n"
        if len(findings) > 5:
            findings_summary += f"... and {len(findings) - 5} more\n"

    techniques_list = ""
    for t in available_techniques[:10]:
        techniques_list += f"- {t['id']}: {t['name']} ({t['severity']})\n"

    prompt = f"""You are HAKUZA, an autonomous penetration testing agent operating in ReAct mode.

ENGAGEMENT CONTEXT:
- Target: {engagement.get('target', 'Unknown')}
- Type: {engagement.get('type', 'web')}
- Scope: {engagement.get('scope', 'Unknown')}
- Start Date: {engagement.get('start_date', 'Unknown')}

{findings_summary}

AVAILABLE TECHNIQUES (sample):
{techniques_list}

TASK: Decide the NEXT penetration test to execute. Choose wisely — prioritize:
1. High-severity vulnerabilities that haven't been tested yet
2. Common web vulnerabilities on untested parameters
3. Follow-up tests on discovered findings (e.g., if SSRF found, try cloud metadata)
4. Coverage of all major attack vectors before deep dives

RESPOND IN THIS EXACT JSON FORMAT (no markdown, no extra text):
{{
  "technique_id": "xss_reflected",
  "target_url": "https://target.com/search?q=test",
  "test_params": ["q", "sort"],
  "rationale": "High-value target parameter has not been XSS-tested yet",
  "expected_time_seconds": 30,
  "approval_required": false
}}

If you believe testing is complete, respond:
{{"status": "complete", "reason": "All major vectors tested"}}

If you hit a blocker, respond:
{{"status": "blocked", "reason": "Requires authentication that was not provided"}}
"""

    return prompt


def run_orchestration_loop(engagement_name: str, depth: int = 5, max_iterations: int = 10) -> None:
    """
    Run autonomous orchestration loop: read state → plan → execute → repeat
    """
    global console
    console = _init_globals()

    engagement = get_engagement(engagement_name)
    if not engagement:
        console.print(f"[red]Engagement not found: {engagement_name}[/red]")
        return

    console.print(f"\n[bold cyan]Starting Orchestration Loop[/bold cyan]")
    console.print(f"Target: {engagement['target']}")
    console.print(f"Depth: {depth} | Max iterations: {max_iterations}")
    console.print("─" * 80)

    client = anthropic.Anthropic()

    for iteration in range(max_iterations):
        console.print(f"\n[bold]Iteration {iteration + 1}/{max_iterations}[/bold]")

        # 1. Read current state
        findings = list_findings(engagement["id"])
        console.print(f"  Current findings: {len(findings)}")

        # 2. Load available techniques
        if HAS_TECHNIQUES:
            techniques = load_techniques()
        else:
            techniques = []

        if not techniques:
            console.print("  [red]No techniques loaded. Aborting.[/red]")
            break

        # 3. Ask LLM for next action
        prompt = build_orchestration_prompt(engagement, findings, techniques)

        try:
            message = client.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )

            response_text = message.content[0].text.strip()

        except Exception as e:
            console.print(f"[red]LLM error: {e}[/red]")
            break

        # 4. Parse response
        try:
            action = json.loads(response_text)
        except json.JSONDecodeError:
            console.print(f"[red]Invalid JSON response from LLM[/red]")
            console.print(f"[dim]{response_text[:200]}[/dim]")
            break

        # 5. Check for terminal states
        if action.get("status") == "complete":
            console.print(f"\n[green]✓ Orchestration complete[/green]")
            console.print(f"  Reason: {action.get('reason', 'N/A')}")
            break

        if action.get("status") == "blocked":
            console.print(f"\n[yellow]✗ Orchestration blocked[/yellow]")
            console.print(f"  Reason: {action.get('reason', 'N/A')}")
            break

        # 6. Display planned action
        technique_id = action.get("technique_id")
        target = action.get("target_url")
        rationale = action.get("rationale", "")

        console.print(f"  Technique: {technique_id}")
        console.print(f"  Target: {target}")
        console.print(f"  Rationale: {rationale}")

        # 7. Ask for approval if needed
        if action.get("approval_required"):
            if not Confirm.ask("    Approve this action?"):
                console.print("  [yellow]Action denied by user[/yellow]")
                continue

        # 8. Execute action using technique executors
        console.print("[dim]Executing...[/dim]")

        if HAS_EXECUTORS:
            # Prepare executor parameters
            test_params = action.get("test_params", [])
            target_url = action.get("target_url")

            # Execute the technique
            finding = execute_technique(
                technique_id=technique_id,
                target_url=target_url,
                params_list=test_params,
                eng_id=engagement["id"]
            )

            if finding:
                console.print(f"[green]✓ Vulnerability found: {finding.get('title', 'Unknown')}[/green]")
            else:
                console.print("[yellow]✓ Test executed - no vulnerability detected[/yellow]")
        else:
            console.print("[yellow]⚠ Executors not available - suggest manual testing[/yellow]")
            console.print(f"  Target: {action.get('target_url')}")
            console.print(f"  Technique: {technique_id}")
            console.print(f"  Parameters: {', '.join(action.get('test_params', []))}")

    console.print(f"\n[bold cyan]Orchestration Loop Complete[/bold cyan]")
    console.print(f"Total findings: {len(list_findings(engagement['id']))}")


def cmd_orchestrate(args) -> None:
    """Run autonomous orchestration loop."""
    engagement_name = args.engagement or get_config_value("current_engagement")

    if not engagement_name:
        console.print("[red]No engagement selected. Use 'hakuza switch' or 'hakuza orchestrate --engagement NAME'[/red]")
        return

    depth = args.depth or 5
    max_iter = args.max_iterations or 10

    run_orchestration_loop(engagement_name, depth=depth, max_iterations=max_iter)


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In build_parser(), inside the sub-commands block, add:

#   p_orch = sub.add_parser("orchestrate",
#       help="Run autonomous orchestration loop (ReAct agent)",
#       description="LLM-driven agent autonomously decides and executes tests based on engagement state"
#   )
#   p_orch.add_argument("--engagement", "-e", help="Engagement name (default: current)")
#   p_orch.add_argument("--depth", "-d", type=int, default=5, help="Search depth (default: 5)")
#   p_orch.add_argument("--max-iterations", "-i", type=int, default=10, help="Max iterations (default: 10)")
#   p_orch.add_argument("--dry-run", action="store_true", help="Plan only, don't execute")
#   p_orch.set_defaults(func=cmd_orchestrate)

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS
# ─────────────────────────────────────────────────────────────────────────────
# In main(), in the dispatch dict, add:

#   "orchestrate": cmd_orchestrate,
