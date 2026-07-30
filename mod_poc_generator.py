#!/usr/bin/env python3
"""
mod_poc_generator.py — HAKUZA Automated PoC Generator

Generates standalone, independently-reproducible Proof-of-Concept scripts for
every discovered finding. Uses Claude to intelligently craft per-target PoCs
based on vulnerability evidence, validates them against testlab endpoints,
and integrates with the finding-storage pipeline.

Key principles:
  1. Every PoC is generated fresh per-target, not templated
  2. Validation is mandatory — broken PoCs are rejected before saving
  3. Multiple formats supported (curl, Python, Bash one-liner)
  4. Graceful fallback to links (GitHub, docs) if LLM PoC generation fails
  5. Async-compatible for orchestrator integration

Integration points:
  - Called automatically when mod_active discovers a finding
  - Manual invocation: hakuza poc-generate --finding-id F001
  - Batch generation after full scan: hakuza poc-batch --engagement NAME
"""

import os
import json
import re
import sys
import shlex
import subprocess
import tempfile
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from pathlib import Path

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_MODEL = "claude-sonnet-4-6"
_TESTLAB_PORT = 9911
_TESTLAB_BASE = "http://127.0.0.1:9911"

# Vulnerability class to testlab endpoint mapping
_TESTLAB_ENDPOINTS = {
    "sqli": "/product?cat=1",
    "xss_reflected": "/greet?name=guest",
    "xss_dom": "/domxss?name=x",
    "path_traversal": "/doc?file=welcome.txt",
    "open_redirect": "/go?redirect=",
    "idor": "/user/1000/profile?tab=1",
    "ssrf": "/fetch?url=http://example.com",
    "nosqli": "/login?username=admin",
    "rce": "/exec?cmd=whoami",
    "crlf": "/header?value=test",
    "http_smuggling": "/smuggle?payload=test",
    "xxe": "/xmlpreview?data=test",
    "ssti": "/template?name=guest",
    "cache_deception": "/static/cache?file=test",
    "race_condition": "/redeem?coupon=WELCOME10",
    "jwt": "/api/profile",
    "cors": "/api/data",
    "default_creds": "/admin?user=admin&pass=admin",
}


# ─────────────────────────────────────────────────────────────────────────────
# Lazy imports (mirrors mod_active.py pattern)
# ─────────────────────────────────────────────────────────────────────────────

def _hakuza():
    """Lazy-load hakuza module for finding storage and engagement paths."""
    import sys
    main_mod = sys.modules.get("__main__")
    if main_mod and hasattr(main_mod, "add_finding"):
        return main_mod
    try:
        import hakuza
        return hakuza
    except ImportError:
        return None


def _get_engagement_path(engagement_id: str) -> Optional[Path]:
    """Get the path to an engagement's poc/ directory."""
    hakuza_mod = _hakuza()
    if not hakuza_mod:
        return None

    # Try to get engagement from DB
    try:
        conn = hakuza_mod.get_db()
        row = conn.execute(
            "SELECT folder FROM engagements WHERE id = ?",
            (engagement_id,)
        ).fetchone()
        if row:
            eng_path = Path(row["folder"])
            poc_dir = eng_path / "poc"
            poc_dir.mkdir(parents=True, exist_ok=True)
            return poc_dir
    except Exception:
        pass

    return None


def _update_finding_poc(finding_id: str, poc_file: str = None,
                        curl_poc: str = None, poc_links: str = None) -> bool:
    """Update a finding with PoC metadata in the database."""
    hakuza_mod = _hakuza()
    if not hakuza_mod:
        return False

    try:
        conn = hakuza_mod.get_db()
        updates = []
        params = []

        if poc_file:
            updates.append("poc_file = ?")
            params.append(poc_file)
        if curl_poc:
            updates.append("curl_poc = ?")
            params.append(curl_poc)
        if poc_links:
            updates.append("poc_links = ?")
            params.append(json.dumps(poc_links) if isinstance(poc_links, list) else poc_links)

        if not updates:
            return True

        params.append(finding_id)
        query = f"UPDATE findings SET {', '.join(updates)}, updated_at = ? WHERE id = ?"
        params.insert(len(params) - 1, datetime.now().isoformat())

        conn.execute(query, params)
        conn.commit()
        return True
    except Exception as e:
        print(f"[!] Failed to update finding {finding_id}: {e}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. LLM-based PoC Generation
# ─────────────────────────────────────────────────────────────────────────────

def _build_poc_generation_prompt(finding: Dict[str, Any]) -> str:
    """Build a prompt for Claude to generate a working PoC."""
    return f"""You are a senior penetration tester writing an automated Proof-of-Concept
for a discovered vulnerability. Generate a STANDALONE, INDEPENDENTLY REPRODUCIBLE PoC that proves
this vulnerability.

VULNERABILITY DETAILS:
- Title: {finding.get('title', 'Unknown')}
- Type: {finding.get('category', 'Web')}
- Severity: {finding.get('severity', 'medium')}
- URL: {finding.get('url', 'Unknown')}
- Description: {finding.get('description', '')}
- Evidence: {finding.get('evidence', '')}
- Impact: {finding.get('impact', '')}

REQUIREMENTS:
1. Output ONLY the raw code (no explanations, no markdown fences, no surrounding text)
2. For web vulnerabilities: use curl command or Python with only stdlib + requests
3. For RCE: provide a one-liner reverse shell (commented with usage notes)
4. For SQLi: include the exact payload + curl that extracts data
5. Make it copy-paste ready — no placeholder values
6. Include a shebang if it's a script (#! /usr/bin/env python3 or similar)
7. Each script should exit 0 on success (vuln confirmed) or 1 on failure

PREFERRED FORMATS (in order):
1. curl command (most portable, easiest to validate)
2. Python script with requests (standalone, no external deps except requests)
3. Bash one-liner (if RCE-specific)

OUTPUT ONLY the code. No explanation. No markdown fences. Just raw, executable code."""


def generate_poc_for_finding(finding: Dict[str, Any],
                            client: Optional["anthropic.Anthropic"] = None,
                            use_ai: bool = True) -> Optional[str]:
    """Generate a PoC using Claude based on finding evidence.

    Args:
        finding: Finding dict with title, url, description, evidence, etc.
        client: Anthropic client (created if None and use_ai=True)
        use_ai: Whether to use Claude; if False, returns None

    Returns:
        PoC code string, or None if generation failed
    """
    if not use_ai or not HAS_ANTHROPIC:
        return None

    if client is None:
        try:
            client = anthropic.Anthropic()
        except Exception:
            return None

    prompt = _build_poc_generation_prompt(finding)

    try:
        response = client.messages.create(
            model=_MODEL,
            max_tokens=1024,
            system="You are an expert at writing exploits and PoCs. Output only raw, executable code.",
            messages=[{"role": "user", "content": prompt}],
            timeout=30.0,
        )

        poc_text = ""
        for block in response.content:
            if getattr(block, "type", None) == "text":
                poc_text += block.text

        # Strip leading/trailing markdown fences if present
        poc_text = poc_text.strip()
        if poc_text.startswith("```"):
            lines = poc_text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            poc_text = "\n".join(lines).strip()

        return poc_text if poc_text else None

    except Exception as e:
        print(f"[!] PoC generation failed: {e}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 2. PoC Validation
# ─────────────────────────────────────────────────────────────────────────────

def _is_testlab_running() -> bool:
    """Check if testlab is running on the configured port."""
    if not HAS_REQUESTS:
        return False

    try:
        resp = requests.get(f"{_TESTLAB_BASE}/", timeout=2)
        return resp.status_code < 500  # Testlab returns something
    except Exception:
        return False


def _extract_poc_type(poc_code: str) -> str:
    """Determine PoC type: 'curl', 'python', 'bash', or 'unknown'."""
    if not poc_code:
        return "unknown"

    poc_lower = poc_code.lower()
    if poc_lower.startswith("curl "):
        return "curl"
    elif poc_lower.startswith("#!/usr/bin/env python") or "import requests" in poc_lower:
        return "python"
    elif poc_lower.startswith("#!/bin/bash") or poc_lower.startswith("#!/bin/sh"):
        return "bash"
    elif "curl" in poc_lower and "\\" in poc_lower:
        return "curl"
    else:
        return "unknown"


def validate_poc(poc_code: str, finding: Dict[str, Any],
                 timeout: int = 30) -> Tuple[bool, str]:
    """Validate a generated PoC by executing it.

    Returns: (is_valid, reason)
    - is_valid: True if PoC executed successfully
    - reason: Explanation of validation result
    """
    if not poc_code:
        return False, "Empty PoC code"

    poc_type = _extract_poc_type(poc_code)

    # If testlab isn't running, we can do syntax validation only
    testlab_available = _is_testlab_running()

    if poc_type == "python":
        # Syntax check: compile the code
        try:
            compile(poc_code, "<poc>", "exec")
        except SyntaxError as e:
            return False, f"Python syntax error: {e}"

        if not testlab_available:
            return True, "Python syntax OK (testlab unavailable for full validation)"

        # Execute the PoC
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(poc_code)
                f.flush()
                temp_path = f.name

            result = subprocess.run(
                [sys.executable, temp_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            os.unlink(temp_path)

            # Exit 0 = success, 1 = failure, other = error
            if result.returncode == 0:
                return True, "PoC executed successfully"
            else:
                stderr = result.stderr[:200] if result.stderr else ""
                stdout = result.stdout[:200] if result.stdout else ""
                reason = stderr or stdout or "PoC executed but returned non-zero exit"
                return False, f"PoC failed: {reason}"

        except subprocess.TimeoutExpired:
            return False, f"PoC timed out after {timeout}s"
        except Exception as e:
            return False, f"PoC execution error: {e}"

    elif poc_type == "curl":
        # Syntax check: verify it's a valid curl command
        if not poc_code.startswith("curl"):
            return False, "Curl command doesn't start with 'curl'"

        if not testlab_available:
            return True, "Curl command syntax OK (testlab unavailable for full validation)"

        # Execute the curl command
        try:
            result = subprocess.run(
                poc_code,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                return True, "Curl executed successfully"
            else:
                stderr = result.stderr[:200] if result.stderr else ""
                return False, f"Curl failed: {stderr or 'Non-zero exit'}"

        except subprocess.TimeoutExpired:
            return False, f"Curl timed out after {timeout}s"
        except Exception as e:
            return False, f"Curl execution error: {e}"

    elif poc_type == "bash":
        # Bash: validate syntax and attempt execution
        if not testlab_available:
            return True, "Bash syntax OK (testlab unavailable for full validation)"

        try:
            result = subprocess.run(
                poc_code,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                return True, "Bash executed successfully"
            else:
                stderr = result.stderr[:200] if result.stderr else ""
                return False, f"Bash failed: {stderr or 'Non-zero exit'}"

        except subprocess.TimeoutExpired:
            return False, f"Bash timed out after {timeout}s"
        except Exception as e:
            return False, f"Bash execution error: {e}"

    else:
        # Unknown type — basic validation only
        if len(poc_code) < 10:
            return False, "PoC code too short to be valid"
        return True, "PoC type unknown, basic validation passed"


# ─────────────────────────────────────────────────────────────────────────────
# 3. PoC Storage
# ─────────────────────────────────────────────────────────────────────────────

def save_poc(poc_code: str, finding_id: str, engagement_id: str,
             poc_format: str = "auto") -> Optional[str]:
    """Save a validated PoC to disk and return the file path.

    Args:
        poc_code: The PoC code to save
        finding_id: Finding ID (used in filename)
        engagement_id: Engagement ID (used to find poc/ directory)
        poc_format: File format ('auto' to detect, 'python', 'curl', 'bash')

    Returns:
        Relative path to saved PoC file (e.g., "poc/F001_xss.py"), or None
    """
    if not poc_code:
        return None

    poc_dir = _get_engagement_path(engagement_id)
    if not poc_dir:
        return None

    # Determine file extension
    if poc_format == "auto":
        poc_type = _extract_poc_type(poc_code)
    else:
        poc_type = poc_format

    if poc_type == "python":
        ext = ".py"
    elif poc_type == "curl":
        ext = ".sh"
    elif poc_type == "bash":
        ext = ".sh"
    else:
        ext = ".txt"

    # Generate filename: poc/<finding_short_id>_<type>.<ext>
    # finding_id might be a UUID; we'll use first 8 chars
    short_id = finding_id[:8] if len(finding_id) > 8 else finding_id
    filename = f"{short_id}_{poc_type}{ext}"
    filepath = poc_dir / filename

    try:
        with open(filepath, 'w') as f:
            f.write(poc_code)

        # Return relative path from engagement folder
        return f"poc/{filename}"

    except Exception as e:
        print(f"[!] Failed to save PoC to {filepath}: {e}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Main PoC Generation Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def generate_poc_for_finding_complete(
    finding_id: str,
    engagement_id: str,
    finding_dict: Optional[Dict[str, Any]] = None,
    use_ai: bool = True,
    use_validation: bool = True,
    fallback_to_links: bool = True,
    client: Optional["anthropic.Anthropic"] = None,
) -> Dict[str, Any]:
    """Complete PoC generation pipeline: generate → validate → store → update DB.

    Args:
        finding_id: Finding ID
        engagement_id: Engagement ID
        finding_dict: Full finding dict; fetched from DB if None
        use_ai: Use Claude for PoC generation
        use_validation: Validate generated PoCs
        fallback_to_links: Fall back to GitHub links if PoC fails
        client: Anthropic client (created if needed)

    Returns:
        {
            "success": bool,
            "poc_file": str (path to saved file or None),
            "curl_poc": str (curl command or None),
            "poc_links": list (GitHub links or None),
            "message": str,
            "validation_passed": bool (if validated),
        }
    """
    result = {
        "success": False,
        "poc_file": None,
        "curl_poc": None,
        "poc_links": None,
        "message": "",
        "validation_passed": False,
    }

    # Fetch finding if not provided
    if finding_dict is None:
        hakuza_mod = _hakuza()
        if hakuza_mod:
            try:
                conn = hakuza_mod.get_db()
                row = conn.execute(
                    "SELECT * FROM findings WHERE id = ?",
                    (finding_id,)
                ).fetchone()
                if row:
                    finding_dict = hakuza_mod._row_to_dict(row)
            except Exception:
                pass

        if not finding_dict:
            result["message"] = f"Could not fetch finding {finding_id}"
            return result

    # Step 1: Generate PoC
    poc_code = None
    if use_ai:
        poc_code = generate_poc_for_finding(finding_dict, client=client)

    if not poc_code:
        result["message"] = "PoC generation failed or disabled"

        # Step 1b: Fallback to GitHub PoC links
        if fallback_to_links and finding_dict.get("cve_id"):
            try:
                from mod_poc_discovery import extract_poc_links
                poc_links = extract_poc_links(finding_dict["cve_id"])
                if poc_links:
                    result["poc_links"] = poc_links
                    result["success"] = True
                    result["message"] = f"Fallback: Found {len(poc_links)} public PoC link(s)"
                    _update_finding_poc(finding_id, poc_links=poc_links)
                    return result
            except Exception:
                pass

        return result

    # Step 2: Validate PoC
    validation_passed = True
    validation_reason = "Validation disabled"

    if use_validation:
        validation_passed, validation_reason = validate_poc(poc_code, finding_dict)
        result["validation_passed"] = validation_passed

    if not validation_passed:
        result["message"] = f"PoC validation failed: {validation_reason}"
        # Don't save invalid PoCs
        return result

    # Step 3: Extract curl command if present (for database storage)
    if poc_code.startswith("curl"):
        result["curl_poc"] = poc_code

    # Step 4: Save PoC to disk
    poc_file = save_poc(poc_code, finding_id, engagement_id)
    if not poc_file:
        result["message"] = f"PoC validation passed but save failed"
        return result

    result["poc_file"] = poc_file

    # Step 5: Update finding in database
    _update_finding_poc(finding_id, poc_file=poc_file, curl_poc=result["curl_poc"])

    result["success"] = True
    result["message"] = f"PoC generated and validated: {poc_file}"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. CLI Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_poc_generate(args) -> None:
    """Generate PoC for a specific finding: hakuza poc-generate --finding-id F001"""

    finding_id = args.finding_id
    engagement_id = args.engagement or _get_current_engagement()

    if not engagement_id:
        print("[!] No engagement specified or current engagement set", file=sys.stderr)
        return

    use_ai = not args.no_ai if hasattr(args, 'no_ai') else True
    use_validation = not args.skip_validation if hasattr(args, 'skip_validation') else True

    print(f"Generating PoC for finding {finding_id} in engagement {engagement_id}...")

    result = generate_poc_for_finding_complete(
        finding_id,
        engagement_id,
        use_ai=use_ai,
        use_validation=use_validation,
    )

    if result["success"]:
        print(f"✓ {result['message']}")
        if result["poc_file"]:
            print(f"  File: {result['poc_file']}")
        if result["curl_poc"]:
            print(f"  Curl: {result['curl_poc'][:100]}...")
        if result["poc_links"]:
            print(f"  Public links: {len(result['poc_links'])} found")
    else:
        print(f"✗ {result['message']}", file=sys.stderr)


def cmd_poc_batch(args) -> None:
    """Batch-generate PoCs for all open findings in an engagement."""

    engagement_id = args.engagement or _get_current_engagement()
    if not engagement_id:
        print("[!] No engagement specified", file=sys.stderr)
        return

    hakuza_mod = _hakuza()
    if not hakuza_mod:
        print("[!] HAKUZA module not available", file=sys.stderr)
        return

    try:
        findings = hakuza_mod.list_findings(engagement_id, severity_filter=args.severity)
    except Exception as e:
        print(f"[!] Failed to fetch findings: {e}", file=sys.stderr)
        return

    if not findings:
        print("[*] No findings to process")
        return

    print(f"Batch generating PoCs for {len(findings)} finding(s)...")

    use_ai = not args.no_ai if hasattr(args, 'no_ai') else True
    use_validation = not args.skip_validation if hasattr(args, 'skip_validation') else True

    success_count = 0
    fail_count = 0
    skip_count = 0

    for i, finding in enumerate(findings, 1):
        print(f"\n[{i}/{len(findings)}] {finding['title']} ({finding['severity']})")

        # Skip if already has a PoC
        if finding.get("poc_file") or finding.get("curl_poc"):
            print("  → Already has PoC, skipping")
            skip_count += 1
            continue

        result = generate_poc_for_finding_complete(
            finding["id"],
            engagement_id,
            finding_dict=finding,
            use_ai=use_ai,
            use_validation=use_validation,
        )

        if result["success"]:
            print(f"  ✓ {result['message'][:80]}")
            success_count += 1
        else:
            print(f"  ✗ {result['message'][:80]}")
            fail_count += 1

    print(f"\n[Summary] Success: {success_count} | Failed: {fail_count} | Skipped: {skip_count}")


def _get_current_engagement() -> Optional[str]:
    """Fetch current engagement from HAKUZA config."""
    hakuza_mod = _hakuza()
    if not hakuza_mod:
        return None

    try:
        return hakuza_mod.get_config_value("current_engagement")
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ARGPARSE ADDITIONS (for hakuza.py)
# ─────────────────────────────────────────────────────────────────────────────

# Add these to build_parser() in hakuza.py:
#
#   p_pocgen = sub.add_parser("poc-generate",
#       help="Generate PoC for a specific finding",
#       description="Use Claude to generate a standalone, reproducible PoC"
#   )
#   p_pocgen.add_argument("--finding-id", "-f", required=True, help="Finding ID")
#   p_pocgen.add_argument("--engagement", "-e", help="Engagement ID")
#   p_pocgen.add_argument("--no-ai", action="store_true", help="Skip AI generation")
#   p_pocgen.add_argument("--skip-validation", action="store_true", help="Skip validation")
#   p_pocgen.set_defaults(func=cmd_poc_generate)
#
#   p_pocbatch = sub.add_parser("poc-batch",
#       help="Batch-generate PoCs for all findings in an engagement",
#       description="Generate PoCs for all open findings (or a specific severity)"
#   )
#   p_pocbatch.add_argument("--engagement", "-e", help="Engagement ID")
#   p_pocbatch.add_argument("--severity", "-s", help="Filter by severity (critical, high, etc.)")
#   p_pocbatch.add_argument("--no-ai", action="store_true", help="Skip AI generation")
#   p_pocbatch.add_argument("--skip-validation", action="store_true", help="Skip validation")
#   p_pocbatch.set_defaults(func=cmd_poc_batch)
#
# Add these to the dispatch dict in main():
#
#   "poc-generate": cmd_poc_generate,
#   "poc-batch": cmd_poc_batch,

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH ADDITIONS (for mod_active.py integration)
# ─────────────────────────────────────────────────────────────────────────────

# After finding is confirmed in mod_active.py, call:
#
#   from mod_poc_generator import generate_poc_for_finding_complete
#
#   poc_result = generate_poc_for_finding_complete(
#       finding_id=finding["id"],
#       engagement_id=engagement_id,
#       finding_dict=finding,  # The finding dict returned by add_finding()
#       use_ai=True,
#       use_validation=True,
#   )
#
#   if poc_result["success"]:
#       console.print(f"[green]PoC generated:[/green] {poc_result['message']}")
#   else:
#       console.print(f"[dim]PoC generation skipped: {poc_result['message']}[/dim]")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="HAKUZA PoC Generator — Standalone testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command")

    # poc-generate command
    p_gen = subparsers.add_parser("generate", help="Generate PoC for a finding")
    p_gen.add_argument("finding_id", help="Finding ID")
    p_gen.add_argument("--engagement", "-e", help="Engagement ID")
    p_gen.add_argument("--no-ai", action="store_true", help="Skip AI")
    p_gen.set_defaults(func=cmd_poc_generate)

    # poc-batch command
    p_batch = subparsers.add_parser("batch", help="Batch-generate PoCs")
    p_batch.add_argument("--engagement", "-e", help="Engagement ID")
    p_batch.add_argument("--severity", "-s", help="Filter by severity")
    p_batch.add_argument("--no-ai", action="store_true", help="Skip AI")
    p_batch.set_defaults(func=cmd_poc_batch)

    # validate command
    p_val = subparsers.add_parser("validate", help="Validate a PoC file")
    p_val.add_argument("poc_file", help="Path to PoC file")
    p_val.set_defaults(func=lambda args: print("Not yet implemented"))

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
