#!/usr/bin/env python3
"""
HAKUZA Assembler — merges base + modules into final hakuza.py
Run from ~/projects/hakuza/: python3 assemble.py
"""
import re
import sys
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colours (no external deps)
# ---------------------------------------------------------------------------
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[96m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_DIM    = "\033[2m"
C_BLUE   = "\033[94m"

def bold(s):   return f"{C_BOLD}{s}{C_RESET}"
def cyan(s):   return f"{C_CYAN}{s}{C_RESET}"
def green(s):  return f"{C_GREEN}{s}{C_RESET}"
def yellow(s): return f"{C_YELLOW}{s}{C_RESET}"
def red(s):    return f"{C_RED}{s}{C_RESET}"
def dim(s):    return f"{C_DIM}{s}{C_RESET}"
def blue(s):   return f"{C_BLUE}{s}{C_RESET}"

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
BASE   = Path("hakuza.py")
OUTPUT = Path("hakuza.py")          # assembled in-place

MODULES = [
    "mod_ad_network.py",
    "mod_dashboard.py",
    "mod_ai_batch.py",
    "mod_report.py",
    "mod_mobile_cloud.py",
    "mod_recon_plus.py",
]

# Expected new commands per module (for the summary line).
# Key = module filename, value = (description_suffix, list_of_commands)
MODULE_META = {
    "mod_ad_network.py":    ("+YY commands: ad, network, lateral",  ["ad", "network", "lateral"]),
    "mod_dashboard.py":     ("+1 command: dashboard",               ["dashboard"]),
    "mod_ai_batch.py":      ("+4 commands: deduplicate, enrich, prioritize, matrix",
                                                                     ["deduplicate", "enrich", "prioritize", "matrix"]),
    "mod_report.py":        ("replaces: report, +1: diff-report",   ["diff-report"]),
    "mod_mobile_cloud.py":  ("+4 commands: mobile, ios, cloud, iot",["mobile", "ios", "cloud", "iot"]),
    "mod_recon_plus.py":    ("+5 commands: wayback, secrets, fuzz, wizard, scope",
                                                                     ["wayback", "secrets", "fuzz", "wizard", "scope"]),
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def extract_imports(code: str) -> set:
    """Return the set of all import lines in *code*."""
    imports = set()
    for line in code.splitlines():
        s = line.strip()
        if s.startswith("import ") or s.startswith("from "):
            imports.add(s)
    return imports


def strip_duplicate_imports(module_code: str, existing_imports: set) -> str:
    """
    Remove top-level import lines from *module_code* that already appear in
    *existing_imports*.

    Rules:
    - Only strip MODULE-LEVEL imports (indented imports inside functions/classes
      are kept, since they are runtime imports).
    - Handle multi-line imports: if we decide to strip 'from x import (',
      also skip the continuation lines until the matching ')'.
    - Handle backslash-continuation imports similarly.
    """
    out = []
    skip_continuation = False  # True when we've stripped a multi-line import opener
    paren_depth = 0

    for line in module_code.splitlines(keepends=True):
        raw = line.rstrip("\n")
        s = raw.strip()

        # If we're consuming continuation lines of a stripped import
        if skip_continuation:
            paren_depth += s.count("(") - s.count(")")
            if paren_depth <= 0:
                skip_continuation = False
                paren_depth = 0
            # Skip this continuation line
            continue

        # Only strip TOP-LEVEL imports (no leading whitespace before 'import'/'from')
        if not raw.startswith(" ") and not raw.startswith("\t"):
            if s.startswith("import ") or s.startswith("from "):
                if s in existing_imports:
                    # Check if it opens a multi-line import
                    if s.endswith("(") or s.count("(") > s.count(")"):
                        skip_continuation = True
                        paren_depth = s.count("(") - s.count(")")
                    elif s.endswith("\\"):
                        skip_continuation = True
                        paren_depth = 0
                    continue  # skip this line

        out.append(line)

    return "".join(out)


def strip_shebang(code: str) -> str:
    """Remove a leading #!/usr/bin/env python3 line."""
    lines = code.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    return "".join(lines)


def strip_hakuza_interfaces_import(code: str) -> str:
    """Remove any 'from hakuza_interfaces import *' lines."""
    out = []
    for line in code.splitlines(keepends=True):
        if re.match(r"^\s*from\s+hakuza_interfaces\s+import\s+", line):
            continue
        out.append(line)
    return "".join(out)


def strip_module_docstring(module_code: str, base_header_lines: set) -> str:
    """
    Remove a top-level module docstring whose first content line appears
    in the base file's header block (first 20 lines).  Conservative: only
    strips triple-quoted docstrings that start at line 0/1 (after optional
    shebang removal).
    """
    lines = module_code.splitlines(keepends=True)
    # Find the first non-blank, non-shebang line
    start = 0
    while start < len(lines) and lines[start].strip() in ("", ):
        start += 1

    if start >= len(lines):
        return module_code

    first = lines[start].strip()
    if not (first.startswith('"""') or first.startswith("'''")):
        return module_code

    quote = first[:3]
    # Check if it's a single-line docstring
    rest = first[3:]
    if rest.endswith(quote) and len(rest) > len(quote):
        # It's """...""" on one line — check if content overlaps with base
        content = rest[:-3].strip()
        if any(content in bline for bline in base_header_lines):
            # Strip it
            return "".join(lines[:start] + lines[start + 1:])
        return module_code

    # Multi-line docstring — find closing quotes
    end = start + 1
    while end < len(lines):
        if quote in lines[end]:
            end += 1
            break
        end += 1

    doc_content = "".join(lines[start:end])
    # Check if first meaningful word of the docstring matches known hakuza header keywords
    hakuza_keywords = {"HAKUZA", "hakuza", "Unified Penetration", "penetration testing platform"}
    if any(kw in doc_content for kw in hakuza_keywords):
        # Only strip if it really looks like a duplicate header
        module_name_line = doc_content.split("\n")[0].lower()
        if "hakuza" in module_name_line and "mod_" not in module_name_line:
            return "".join(lines[:start] + lines[end:])

    return module_code


def get_existing_function_names(code: str) -> set:
    """Return the set of top-level function/class names already defined in *code*."""
    names = set()
    for m in re.finditer(r"^(?:def|class)\s+(\w+)", code, re.MULTILINE):
        names.add(m.group(1))
    return names


def extract_argparse_block(module_code: str) -> list:
    """
    Find the # ARGPARSE ADDITIONS comment block and return the un-commented
    add_parser / add_argument lines that should be injected.

    Two formats are supported:
      1. Code embedded in comment lines:  #   p_foo = sub.add_parser(...)
      2. Raw Python code after the marker (not inside comments)

    Only lines whose un-commented content look like Python code are kept
    (i.e. they start with p_, sub., or contain add_parser/add_argument, or
    look like a continuation of an open parenthesis).  Pure prose lines
    (e.g. "In build_parser(), inside the sub-commands block, add:") are
    dropped.
    """
    lines = module_code.splitlines()
    in_block = False
    seen_first_sep = False   # first ─── separator after marker
    raw_lines = []           # comment-stripped candidate lines

    for line in lines:
        stripped = line.strip()

        # ── Detect block start ──────────────────────────────────────────
        if re.search(r"#\s*ARGPARSE ADDITIONS", stripped, re.IGNORECASE):
            in_block = True
            seen_first_sep = False
            raw_lines = []
            continue

        if not in_block:
            continue

        # ── Inside block ────────────────────────────────────────────────

        # A horizontal separator line
        if re.search(r"#\s*-{10,}", stripped):
            if seen_first_sep:
                # Second separator = end of block
                break
            seen_first_sep = True
            continue

        # End of block: hit a DISPATCH section
        if re.search(r"#\s*DISPATCH\s*(ADDITIONS?|ADDITION)", stripped, re.IGNORECASE):
            break

        # Blank lines — skip
        if stripped == "":
            raw_lines.append("")
            continue

        # Comment line — strip the leading "#" and optional spaces/indent
        if stripped.startswith("#"):
            # Remove the leading comment marker plus up to 3 spaces of indent
            content = re.sub(r"^#[ \t]{0,3}", "", line.rstrip())
            raw_lines.append(content)
        else:
            # Raw (non-comment) Python line already — take as-is
            raw_lines.append(line.rstrip())

    # ── Filter: keep only lines that look like Python code ──────────────
    # We do a lightweight parse: track open parentheses so we can keep
    # multi-line argument lists even if they don't start with a keyword.
    result = []
    paren_depth = 0

    # Patterns that identify the START of a valid code line
    CODE_START = re.compile(
        r"^\s*(p_\w+|sub\.|#\s*---|\)|parser\.)"  # variable, sub., comment sep, closing paren
        r"|add_parser\(|add_argument\("
    )

    for raw in raw_lines:
        stripped_r = raw.strip()

        if paren_depth > 0:
            # We're inside an open paren — keep the line regardless
            result.append(raw)
            paren_depth += raw.count("(") - raw.count(")")
            paren_depth = max(0, paren_depth)
            continue

        if not stripped_r:
            continue

        # Check if line looks like valid Python code
        if CODE_START.search(stripped_r) or "add_parser(" in stripped_r or "add_argument(" in stripped_r:
            result.append(raw)
            paren_depth += stripped_r.count("(") - stripped_r.count(")")
            paren_depth = max(0, paren_depth)
        # else: it's prose — skip it

    return result


def extract_dispatch_block(module_code: str) -> list:
    """
    Find the # DISPATCH ADDITIONS comment block and return the un-commented
    "cmd": func, lines.
    """
    lines = module_code.splitlines()
    in_block = False
    result = []

    for line in lines:
        stripped = line.strip()

        if re.search(r"#\s*DISPATCH\s*(ADDITIONS?|ADDITION)", stripped, re.IGNORECASE):
            in_block = True
            continue

        if in_block:
            # Stop at next section separator
            if re.search(r"#\s*-{10,}", stripped) and result:
                break
            if stripped == "" or stripped.startswith("#"):
                content = re.sub(r"^#\s?", "", stripped)
                content_s = content.strip()
                # Accept lines that look like "key": value,
                if re.match(r'^"[^"]+"\s*:\s*\w', content_s) or re.match(r"^'[^']+'\s*:\s*\w", content_s):
                    result.append("        " + content_s)
            elif stripped and not stripped.startswith("#"):
                if re.match(r'^"[^"]+"\s*:\s*\w', stripped) or re.match(r"^'[^']+'\s*:\s*\w", stripped):
                    result.append("        " + stripped)

    return result


def inject_argparse(base_code: str, new_lines: list) -> str:
    """Insert *new_lines* before the 'return parser' line in build_parser()."""
    if not new_lines:
        return base_code

    # Find the indented 'return parser' line
    pattern = re.compile(r"^( {4})return parser\s*$", re.MULTILINE)
    m = pattern.search(base_code)
    if not m:
        print(yellow("  [warn] Could not find 'return parser' — skipping argparse injection"))
        return base_code

    insert_pos = m.start()
    base_indent = "    "   # 4-space indent inside build_parser()

    normalised = []
    for ln in new_lines:
        # If the line has no indentation at all (starts at col 0), add base_indent
        if ln and not ln[0].isspace():
            normalised.append(base_indent + ln)
        else:
            # Keep existing indentation (already has spaces from the comment)
            normalised.append(ln)

    block = "\n".join(normalised) + "\n\n"
    return base_code[:insert_pos] + block + base_code[insert_pos:]


def inject_dispatch(base_code: str, new_lines: list) -> str:
    """Insert *new_lines* before the closing '}' of the dispatch dict in main()."""
    if not new_lines:
        return base_code

    # Find the dispatch dict closing brace — it's on its own line with 4-space indent
    # Pattern: the line is exactly "    }" preceded by lines that contain cmd_ references
    # We search for the pattern more carefully using the known context
    pattern = re.compile(
        r'(    dispatch\s*=\s*\{.*?)(    \})',
        re.DOTALL
    )
    m = pattern.search(base_code)
    if not m:
        print(yellow("  [warn] Could not find dispatch dict closing brace — skipping dispatch injection"))
        return base_code

    # Insert before the closing brace
    closing_pos = m.start(2)
    block = "\n".join(new_lines) + "\n"
    return base_code[:closing_pos] + block + base_code[closing_pos:]


def count_new_commands(argparse_lines: list) -> int:
    """Count how many add_parser() calls are in the injected argparse lines."""
    return sum(1 for ln in argparse_lines if "add_parser(" in ln)


def already_has_definition(base_code: str, func_name: str) -> bool:
    pattern = re.compile(r"^(?:def|class)\s+" + re.escape(func_name) + r"\s*[\(:]", re.MULTILINE)
    return bool(pattern.search(base_code))


# ---------------------------------------------------------------------------
# MAIN ASSEMBLER
# ---------------------------------------------------------------------------

def assemble():
    print()
    print(cyan(bold("  HAKUZA Assembler")))
    print(dim("  ─────────────────────────────────"))
    print()

    # ------------------------------------------------------------------
    # 1. Read base file
    # ------------------------------------------------------------------
    if not BASE.exists():
        print(red(f"  ERROR: Base file '{BASE}' not found."))
        sys.exit(1)

    base_code = BASE.read_text(encoding="utf-8")
    base_lines = base_code.count("\n")
    print(f"  {blue('Base:')}  {BASE}  ({base_lines} lines)")

    # Collect imports already in base
    base_imports = extract_imports(base_code)

    # Collect first-20-line header for docstring dedup
    base_header_lines = set(base_code.splitlines()[:20])

    # ------------------------------------------------------------------
    # 2. Process each module
    # ------------------------------------------------------------------
    module_stats = []   # list of (filename, orig_lines, argparse_lines, dispatch_lines, skipped)
    accumulated_code_sections = []

    for mod_filename in MODULES:
        mod_path = Path(mod_filename)

        if not mod_path.exists():
            print(yellow(f"  [skip] {mod_filename} — file not found"))
            module_stats.append((mod_filename, 0, [], [], True))
            continue

        print(f"  {cyan('+')} Processing {bold(mod_filename)} …", end="", flush=True)
        mod_raw = mod_path.read_text(encoding="utf-8")
        orig_lines = mod_raw.count("\n")

        # Extract injection metadata BEFORE stripping
        argparse_lines = extract_argparse_block(mod_raw)
        dispatch_lines = extract_dispatch_block(mod_raw)

        # --- Clean the module code ---
        mod_code = strip_shebang(mod_raw)
        mod_code = strip_hakuza_interfaces_import(mod_code)
        mod_code = strip_duplicate_imports(mod_code, base_imports)
        mod_code = strip_module_docstring(mod_code, base_header_lines)

        # Update base_imports so subsequent modules also skip these
        base_imports.update(extract_imports(mod_raw))

        n_ap  = count_new_commands(argparse_lines)
        n_dis = len(dispatch_lines)
        print(f" {orig_lines} lines, {n_ap} argparse cmd(s), {n_dis} dispatch entry(s)")

        # Inject argparse additions into base_code
        if argparse_lines:
            base_code = inject_argparse(base_code, argparse_lines)

        # Inject dispatch additions into base_code
        if dispatch_lines:
            base_code = inject_dispatch(base_code, dispatch_lines)

        module_stats.append((mod_filename, orig_lines, argparse_lines, dispatch_lines, False))
        accumulated_code_sections.append((mod_filename, mod_code))

    # ------------------------------------------------------------------
    # 3. Append module bodies before the 'if __name__' guard
    # ------------------------------------------------------------------
    main_guard_pattern = re.compile(
        r'^if\s+__name__\s*==\s*["\']__main__["\']\s*:\s*\n',
        re.MULTILINE
    )
    m_guard = main_guard_pattern.search(base_code)
    if m_guard:
        insert_at = m_guard.start()
    else:
        # Fallback: append at end
        insert_at = len(base_code)

    module_bodies = ""
    for mod_filename, mod_code in accumulated_code_sections:
        sep = (
            f"\n\n"
            f"# {'─' * 74}\n"
            f"# MODULE: {mod_filename}\n"
            f"# {'─' * 74}\n\n"
        )
        module_bodies += sep + mod_code.strip() + "\n"

    base_code = base_code[:insert_at] + module_bodies + "\n\n" + base_code[insert_at:]

    # ------------------------------------------------------------------
    # 4. Write output
    # ------------------------------------------------------------------
    OUTPUT.write_text(base_code, encoding="utf-8")
    final_lines = base_code.count("\n")
    print()
    print(f"  {green('Written:')} {OUTPUT}  ({final_lines} lines)")

    # ------------------------------------------------------------------
    # 5. Syntax check
    # ------------------------------------------------------------------
    print(f"  {blue('Checking syntax …')}", end=" ", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(OUTPUT)],
        capture_output=True,
        text=True,
    )
    syntax_ok = result.returncode == 0
    if syntax_ok:
        print(green("OK ✓"))
    else:
        print(red("FAILED ✗"))
        print(red("  py_compile output:"))
        print(red(result.stderr.strip()))

    # ------------------------------------------------------------------
    # 6. Print summary report
    # ------------------------------------------------------------------
    print()
    print(bold(cyan("  HAKUZA Assembly Complete")))
    print(cyan("  " + "═" * 45))

    base_orig_lines = BASE.stat().st_size  # already written; use stored count
    print(f"  {'Base:':<22} {base_lines} lines")

    total_new_commands = 0
    for (mod_filename, orig_lines, ap_lines, dis_lines, skipped) in module_stats:
        n_cmd = count_new_commands(ap_lines)
        total_new_commands += n_cmd
        meta_hint = MODULE_META.get(mod_filename, ("", []))
        hint_str  = meta_hint[0]

        if skipped:
            status = yellow("(not found — skipped)")
            print(f"  {mod_filename:<28} {status}")
        else:
            cmd_part = f"  (+{n_cmd} cmd{'s' if n_cmd != 1 else ''})" if n_cmd else ""
            print(f"  {mod_filename:<28} {orig_lines:>5} lines{cmd_part}")

    print(f"  {'─' * 47}")
    print(f"  {'Final hakuza.py:':<22} {final_lines} lines")
    print(f"  {'New commands:':<22} {total_new_commands} total")
    print(f"  {'Syntax check:':<22} " + (green("OK ✓") if syntax_ok else red("FAILED ✗")))
    print()

    if not syntax_ok:
        sys.exit(1)


if __name__ == "__main__":
    assemble()
