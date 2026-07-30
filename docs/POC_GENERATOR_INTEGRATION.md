# PoC Generator Integration Guide

This document explains how to integrate `mod_poc_generator.py` into `hakuza.py` and `mod_active.py`.

## Quick Start

### 1. Add argparse commands to hakuza.py

In `hakuza.py`, locate the `build_parser()` function where other subcommand parsers are added (look for `p_active =`, `p_recon =`, etc.).

Add these parsers before the final return statement:

```python
# PoC Generator commands
p_pocgen = sub.add_parser("poc-generate",
    help="Generate a PoC for a specific finding",
    description="Use Claude to generate a standalone, reproducible Proof-of-Concept"
)
p_pocgen.add_argument("--finding-id", "-f", required=True,
    help="Finding ID (UUID or short ID)")
p_pocgen.add_argument("--engagement", "-e",
    help="Engagement ID (default: current engagement)")
p_pocgen.add_argument("--no-ai", action="store_true",
    help="Skip AI generation (GitHub links only)")
p_pocgen.add_argument("--skip-validation", action="store_true",
    help="Skip validation (save PoC even if it fails)")
p_pocgen.set_defaults(func=cmd_poc_generate)

p_pocbatch = sub.add_parser("poc-batch",
    help="Batch-generate PoCs for all findings in an engagement",
    description="Generate PoCs for all open findings (or filter by severity)"
)
p_pocbatch.add_argument("--engagement", "-e",
    help="Engagement ID (default: current engagement)")
p_pocbatch.add_argument("--severity", "-s",
    help="Filter by severity (critical, high, medium, low, informational)")
p_pocbatch.add_argument("--no-ai", action="store_true",
    help="Skip AI generation")
p_pocbatch.add_argument("--skip-validation", action="store_true",
    help="Skip validation")
p_pocbatch.set_defaults(func=cmd_poc_batch)
```

### 2. Add dispatch entries to hakuza.py

In the `main()` function, locate the dispatch dictionary (near the end, after the argparse setup). Add these entries:

```python
dispatch = {
    # ... existing entries ...
    "poc-generate": cmd_poc_generate,
    "poc-batch": cmd_poc_batch,
    # ... rest of dispatch dict ...
}
```

### 3. Import at the top of hakuza.py

Add this import with the other module imports:

```python
# At the top of hakuza.py, with other imports
from mod_poc_generator import cmd_poc_generate, cmd_poc_batch
```

### 4. (Optional) Auto-generate PoCs during active testing

In `mod_active.py`, after a finding is confirmed and added to the database, add automatic PoC generation.

Find the location where `add_finding()` is called (search for `finding = _add_finding(` or `_n("add_finding")`).

After the finding is added, add this code:

```python
# After finding is confirmed and added:
# finding = _add_finding(engagement_id, title=..., severity=..., ...)

# Auto-generate PoC (non-blocking, best-effort)
try:
    from mod_poc_generator import generate_poc_for_finding_complete
    
    poc_result = generate_poc_for_finding_complete(
        finding_id=finding["id"],
        engagement_id=engagement_id,
        finding_dict=finding,
        use_ai=True,
        use_validation=True,
    )
    
    if poc_result["success"]:
        console.print(f"[green]✓ PoC generated[/green]: {poc_result.get('poc_file', 'N/A')}")
    elif poc_result["poc_links"]:
        console.print(f"[dim]PoC: Found {len(poc_result['poc_links'])} GitHub link(s)[/dim]")
    # If neither, silently continue — PoC generation is best-effort
    
except Exception as e:
    # Never let PoC generation failure block finding workflow
    console.print(f"[dim]PoC generation skipped: {e}[/dim]")
```

**Location reference in mod_active.py:**

Search for these patterns to find the right spot:
```python
# You'll find something like:
finding = _add_finding(
    engagement_id,
    title=title_str,
    severity=sev,
    description=desc_text,
    evidence=evidence_text,
    url=target_url,
    category=vuln_class,
    curl_poc=curl_cmd,
)
console.print(f"[green]✓ Finding added:[/green] {finding.get('short_id', 'N/A')}")
```

Add the PoC generation code right after the `console.print()` call.

## Testing the Integration

### 1. Verify imports work
```bash
cd /home/hakuza/projects/hakuza
python3 -c "from mod_poc_generator import generate_poc_for_finding_complete; print('✓ Import OK')"
```

### 2. Test manual PoC generation
```bash
# Start testlab first
python3 testlab/vulnerable_site.py --port 9911 &

# Create a test engagement
hakuza new-engagement poctest --target http://127.0.0.1:9911 --type web

# Run active scanning to create findings
hakuza active http://127.0.0.1:9911/greet?name=guest --engagement poctest

# List findings
hakuza findings poctest

# Generate PoC for first finding
FINDING_ID=$(hakuza findings poctest | grep -oP 'ID: \K[a-f0-9-]+' | head -1)
hakuza poc-generate --finding-id $FINDING_ID --engagement poctest

# Check if PoC was saved
ls engagements/poctest/poc/
```

### 3. Test batch generation
```bash
hakuza poc-batch --engagement poctest --severity high
ls -la engagements/poctest/poc/
```

### 4. Verify database integration
```bash
# Check findings table for poc_file field
python3 << 'EOF'
import sqlite3
from pathlib import Path

db_path = Path.home() / ".hakuza" / "engagements.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

findings = conn.execute("SELECT id, title, poc_file, curl_poc FROM findings LIMIT 3").fetchall()
for f in findings:
    print(f"Finding: {f['title']}")
    print(f"  PoC File: {f['poc_file']}")
    print(f"  Curl: {f['curl_poc'][:50] if f['curl_poc'] else 'None'}...")
    print()
EOF
```

## Troubleshooting Integration

### "ModuleNotFoundError: No module named 'mod_poc_generator'"

**Solution:** Make sure you're running `hakuza` from the project directory:
```bash
cd /home/hakuza/projects/hakuza
python3 hakuza.py poc-generate --finding-id F001 --engagement test
```

Or, if using installed hakuza, copy the module to the installation path:
```bash
cp mod_poc_generator.py ~/.local/lib/python*/site-packages/hakuza/
```

### "Error importing anthropic"

**Solution:** Install the SDK:
```bash
pip install anthropic
```

If you don't have an API key:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

PoCs will still work without AI (fallback to GitHub links only).

### "AttributeError: module has no attribute 'cmd_poc_generate'"

**Solution:** Make sure the import statement is at the top of hakuza.py:
```python
from mod_poc_generator import cmd_poc_generate, cmd_poc_batch
```

Also verify the functions exist in mod_poc_generator.py:
```bash
grep "^def cmd_poc" /home/hakuza/projects/hakuza/mod_poc_generator.py
```

### "Finding not found" when generating PoC

**Solution:** Use the short_id instead of UUID:
```bash
# List findings to see short IDs
hakuza findings myengagement

# Use short ID like "VAPT-WEB-001"
hakuza poc-generate --finding-id VAPT-WEB-001 --engagement myengagement
```

### Testlab validation failing

**Symptom:** PoCs generated but validation says they failed

**Troubleshooting:**
1. Check testlab is running: `curl http://127.0.0.1:9911/`
2. Check port: `netstat -tuln | grep 9911`
3. Run testlab in foreground to see errors:
   ```bash
   python3 testlab/vulnerable_site.py --port 9911
   ```
4. Skip validation for debugging:
   ```bash
   hakuza poc-generate --finding-id F001 --skip-validation
   ```
5. Test PoC manually:
   ```bash
   python3 engagements/myeng/poc/f47ac10b_xss.py
   ```

## Integration Checklist

- [ ] `mod_poc_generator.py` exists in `/home/hakuza/projects/hakuza/`
- [ ] Imports added to hakuza.py
- [ ] `cmd_poc_generate` and `cmd_poc_batch` dispatched in hakuza.py
- [ ] Argparse subcommands added to `build_parser()`
- [ ] (Optional) Auto-generation integrated in mod_active.py
- [ ] Documentation reviewed (docs/POC_GENERATOR.md)
- [ ] Manual test passed: `hakuza poc-generate --finding-id TEST`
- [ ] Batch test passed: `hakuza poc-batch --engagement TEST`
- [ ] Database stores `poc_file` and `curl_poc` fields

## Advanced Configuration

### Change model
Edit `mod_poc_generator.py`, line ~37:
```python
_MODEL = "claude-opus-4-1-20250805"  # Try different models
```

### Change testlab port
Edit `mod_poc_generator.py`, line ~48:
```python
_TESTLAB_PORT = 8888
_TESTLAB_BASE = "http://127.0.0.1:8888"
```

### Disable validation for all PoCs
Edit the call in mod_active.py:
```python
poc_result = generate_poc_for_finding_complete(
    ...,
    use_validation=False,  # Skip validation
)
```

### Add custom testlab endpoints
Edit `_TESTLAB_ENDPOINTS` in mod_poc_generator.py:
```python
_TESTLAB_ENDPOINTS = {
    "custom_vuln": "/my-endpoint?param=value",
    # ... add more
}
```

## Monitoring & Logging

To track PoC generation in production:

```bash
# Monitor for PoC generation errors
tail -f ~/.hakuza/hakuza.log | grep -i "poc"

# Count generated PoCs
sqlite3 ~/.hakuza/engagements.db \
  "SELECT COUNT(*) FROM findings WHERE poc_file IS NOT NULL"

# List findings without PoCs
sqlite3 ~/.hakuza/engagements.db \
  "SELECT short_id, title FROM findings WHERE poc_file IS NULL AND severity IN ('critical', 'high')"
```

## Performance Tuning

For large batches (100+ findings):

1. **Parallel generation:**
   ```python
   # In hakuza.py, modify cmd_poc_batch to use ThreadPoolExecutor
   from concurrent.futures import ThreadPoolExecutor
   
   with ThreadPoolExecutor(max_workers=4) as executor:
       futures = [
           executor.submit(generate_poc_for_finding_complete, f["id"], engagement_id)
           for f in findings
       ]
       results = [f.result() for f in futures]
   ```

2. **Async validation (skip for speed):**
   ```bash
   hakuza poc-batch --engagement myapp --skip-validation
   ```

3. **Reduce model timeout:**
   ```python
   # In mod_poc_generator.py, line ~190
   timeout=15.0,  # Reduced from 30.0
   ```

## Reporting Integration

PoCs are automatically included in reports if using `mod_report.py`. To verify:

```bash
hakuza report myengagement
# Output includes "PoC: curl -X GET ..." sections
```

Manual report inclusion:
```markdown
## Vulnerability XYZ

**PoC:** See `engagements/myengagement/poc/f47ac10b_xss.py`

To reproduce:
\`\`\`bash
python3 poc/f47ac10b_xss.py
\`\`\`
```

## API Usage

For programmatic access (CI/CD, automation):

```python
from mod_poc_generator import generate_poc_for_finding_complete

result = generate_poc_for_finding_complete(
    finding_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
    engagement_id="myengagement",
    use_ai=True,
    use_validation=True,
    fallback_to_links=True,
)

if result["success"]:
    print(f"PoC saved to: {result['poc_file']}")
    if result['curl_poc']:
        print(f"Quick test: {result['curl_poc']}")
else:
    print(f"Failed: {result['message']}")
```

## Support

For issues or enhancements:

1. Check logs: `tail -f ~/.hakuza/hakuza.log`
2. Enable debug: `export DEBUG=1 && hakuza poc-generate ...`
3. Test module standalone: `python3 mod_poc_generator.py generate FINDING_ID`
4. File issue with: output + `python3 -c "import mod_poc_generator; print(dir(mod_poc_generator))"`

## See Also

- `docs/POC_GENERATOR.md` — User guide
- `mod_active.py` — Integration point for auto-generation
- `mod_poc_discovery.py` — GitHub PoC fallback
- `testlab/vulnerable_site.py` — Validation target
