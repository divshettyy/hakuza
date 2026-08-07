# mod_exploit_chains.py — Quick Start Guide

## Installation & Verification

### 1. Verify Module Installation

```bash
cd /home/hakuza/projects/hakuza

# Check syntax
python3 -m py_compile mod_exploit_chains.py
# Output: (no output = success)

# Load module
python3 -c "from mod_exploit_chains import discover_chains; print('✓ Module loads OK')"
```

### 2. Run Tests

```bash
python3 -m pytest test_exploit_chains.py -v
# All 17 tests should pass
```

### 3. Test Direct Execution

```bash
python3 mod_exploit_chains.py
# Should show sample chain discovery output
```

---

## Basic Usage

### Scenario 1: Quick Chain Discovery

```bash
# See all chains for current engagement
hakuza chain

# Output:
# - Shows top 10 chains ranked by impact
# - Indicates if prerequisites are met
# - Estimates exploitation time
```

### Scenario 2: Filter Critical Chains Only

```bash
hakuza chain --findings eng_001 --filter critical

# Shows only chains that would result in critical compromise
```

### Scenario 3: Simulate Exploitation

```bash
hakuza chain --findings eng_001 --simulate

# Shows what WOULD be executed, without running anything
# Safe for demos and proof-of-concept verification
```

### Scenario 4: Execute with Approval

```bash
hakuza chain --findings eng_001 --execute

# For each chain step:
#   [Step 1]: Description
#   [Command]: curl ...
#   Execute this step? [Y/n]:
#
# You approve/reject each step before execution
```

### Scenario 5: Export to JSON

```bash
hakuza chain --findings eng_001 --output chains.json

# Produces structured JSON:
# {
#   "engagement_id": "eng_001",
#   "chains": [...],
#   "summary": {"total_chains": 8, "critical_chains": 5}
# }
```

---

## Understanding the Output

### Table Format

```
Exploitation Chains

ID       Chain Name                             Findings  Impact  Time            Status
────────────────────────────────────────────────────────────────────────────────────
CH_ssrf_ SSRF → Cloud Metadata → IAM...             2    96/100  20-30 minutes   ✓ Ready
```

**Columns:**
- **ID**: Unique chain identifier
- **Chain Name**: Pattern name (what combination of vulns)
- **Findings**: # of findings involved
- **Impact**: 0-100 score (higher = more severe)
- **Time**: Estimated minutes to exploit
- **Status**: ✓ Ready = all prerequisites met, ✗ Missing = needs additional findings

### Detailed Analysis

For each chain, you get:

```
Chain: SSRF → Cloud Metadata → IAM Privilege Escalation
Impact: 96/100

Impact Scoring
  C: 10/10  (can steal any data)
  I: 10/10  (can modify any data)
  A: 10/10  (can disable services)
  CVSS Equivalent: 10.0/10

Business Impact: massive data breach, full data integrity compromise, system unavailability

Real-world CVEs: CVE-2019-9193

Chain Breaker: Firewall IMDS, use IMDSv2 with token binding
```

### Exploitation Flow

```
[01] Identify parameter accepting URLs
    |
    v
[02] Craft SSRF payload to 169.254.169.254/latest/meta-data/...
    |
    v
[03] Extract temporary credentials
    |
    v
[04] AssumeRole to escalate privileges
    |
    v
[05] Access restricted resources (S3, Lambda, EC2)
```

---

## The 32 Chain Patterns (Quick Reference)

### Ultra-Critical (Impact 99-100)
1. **Deserialization RCE → Shell → Persistence** (99)
2. **SSRF → Kubernetes API → Cluster Compromise** (99)
3. **SMB Relay → Active Directory → Domain Compromise** (99)
4. **Privilege Escalation → Network Lateral Movement** (99)
5. **Upload Bypass → Webshell → RCE** (99)
6. **Cloud S3 Misconfiguration → Public Data Breach** (100)
7. **Unpatched RCE → Reverse Shell → Persistence** (98)

### Critical (Impact 90-98)
8. **API → Cloud Credentials → Lateral Movement** (98)
9. **Web → Database → RCE** (95)
10. **HTTP Smuggling → Request Queue Poisoning** (94)
11. **SSRF → Cloud Metadata → IAM Abuse** (96)
12. **JWT Weak Secret → Token Forgery** (93)
13. **SSTI → Code Execution** (97)
14. **LFI → Source Code → Credentials** (92)
15. **Default Credentials → Admin Access** (91)
16. **OAuth Redirect → Token Theft → Escalation** (90)

### High (Impact 80-89)
17-29. (12 more patterns in 80-89 range)

### Medium (Impact <80)
30-32. (3 additional patterns)

---

## Decision Tree: Which Mode to Use

```
Want to understand what chains exist?
├─ YES → hakuza chain
│        (shows all chains discovered)
└─ NO → continue

Want to see without executing?
├─ YES → hakuza chain --simulate
│        (shows what would run, no execution)
└─ NO → continue

Want manual control (approve each step)?
├─ YES → hakuza chain --execute
│        (prompts for approval at each step)
└─ NO → continue

Want automated execution?
├─ YES → hakuza chain --execute --auto-approve
│        ⚠️  WARNING: Only for authorized targets in labs
└─ NO → continue

Want to save results for reporting?
├─ YES → hakuza chain --output chains.json
│        (exports structured data)
└─ NO → Done!
```

---

## Common Tasks

### Task: Find the Most Critical Chain

```bash
hakuza chain

# Look at top row of table (sorted by Impact descending)
# That's your most critical chain
```

### Task: See Exploitation Steps

```bash
hakuza chain | grep -A 10 "Exploitation Flow"

# Shows step-by-step breakdown of how chain is exploited
```

### Task: Check if Chain is Ready

```bash
hakuza chain

# Look at "Status" column
# ✓ Ready = can execute immediately
# ✗ Missing = need more findings first
```

### Task: Estimate Time Budget

```bash
hakuza chain

# Look at "Time" column
# e.g., "20-30 minutes" for SSRF→IAM chain
# Plan accordingly for engagement testing
```

### Task: Validate Before Report

```bash
hakuza chain --simulate

# Dry run all chains
# Once confirmed, export to JSON
hakuza chain --output chains_validated.json

# Include in final security report
```

---

## Troubleshooting

### Problem: "No viable chains found"

**Cause:** Findings don't match chain patterns

**Check:**
1. Do you have findings? `hakuza list`
2. Are categories correct? `hakuza list --format json | grep category`
3. Need more findings? Run more scans:
   ```bash
   hakuza active --url target --profile vuln
   ```

### Problem: "Prerequisites Met: False"

**Cause:** Chain needs additional findings

**Solution:**
1. See which findings are needed (shown in output)
2. Run targeted scan for that vulnerability type
3. Add manually if needed: `hakuza add --finding "title"`

### Problem: Execution fails

**Cause:** PoC command is incorrect

**Solution:**
1. Use `--simulate` first to verify
2. Test PoC manually: copy the curl command, run it
3. If it fails, update finding: `hakuza update F001 --curl-poc "correct command"`
4. Re-run chain

### Problem: Module not loading

**Cause:** Import error

**Fix:**
```bash
cd /home/hakuza/projects/hakuza
python3 -m py_compile mod_exploit_chains.py
python3 -c "from mod_exploit_chains import discover_chains; print('OK')"
```

---

## Integration Examples

### With mod_active.py

```bash
# 1. Run active scans
hakuza active --url https://target

# 2. Discover chains from findings
hakuza chain

# 3. Execute chosen chain
hakuza chain --execute
```

### With mod_poc_generator.py

```bash
# 1. Generate PoCs for findings first
hakuza poc-batch --findings eng_001

# 2. Then discover chains (with PoC data)
hakuza chain --findings eng_001

# 3. Execute chains (now has PoC artifacts)
hakuza chain --findings eng_001 --execute
```

### With mod_report.py

```bash
# 1. Export chains to JSON
hakuza chain --findings eng_001 --output chains.json

# 2. Include in report
hakuza report --engagement eng_001 --include-chains chains.json
```

---

## Key Concepts

### What is a "Chain"?

Combination of 2+ vulnerabilities that together cause complete compromise.

Example: **SSRF → Cloud Metadata → IAM Abuse**
- Vulnerability 1: SSRF (can make internal requests)
- Vulnerability 2: Cloud metadata exposed (can read credentials)
- Chain: Use SSRF to read metadata → steal temp credentials → assume role → full AWS access

### What is "Impact Score"?

0-100 rating of how severe the chain is if exploited.

- 90-100: Critical (full system compromise)
- 70-89: High (major data breach or significant access)
- 50-69: Medium (limited access or data exposure)
- <50: Low (minor impact)

### What is "Prerequisites Met"?

System checked whether all findings needed for the chain are present.

- ✓ Ready: All (or >50%) of chain's prerequisites are in your findings
- ✗ Missing: Need additional findings before chain is exploitable

### What is "Chain Breaker"?

Single finding (if fixed) that breaks the entire chain.

Example: For SSRF→IAM chain, the chain breaker is "Disable IMDS v1, use IMDSv2 with token binding"

If developers implement that fix, the entire SSRF→IAM chain becomes unexploitable.

---

## Next Steps

1. **Try it:** `hakuza chain` on current engagement
2. **Explore:** Review all 32 patterns in `EXPLOIT_CHAINS_GUIDE.md`
3. **Execute:** `hakuza chain --execute` on authorized target (with approval)
4. **Report:** Export `hakuza chain --output report.json` for security reports

---

**Questions?** See `MOD_EXPLOIT_CHAINS_README.md` for complete documentation.
