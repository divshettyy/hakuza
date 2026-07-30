# End-to-End Test Scenario: Full Autonomous Red-Team Engagement

This document describes a complete test scenario to validate HAKUZA's full orchestration pipeline end-to-end.

## Test Target: Local testlab/

**Why testlab**: 
- 23 vulnerable endpoints covering all techniques
- Safe to run at full autonomous power (no real targets harmed)
- Controlled, reproducible environment
- Validates every component in isolation + integration

## Test Scenario: Complete Autonomous Engagement

### Step 0: Setup

```bash
# Terminal 1: Start testlab
cd ~/projects/hakuza/testlab
python3 -m http.server 8000 &

# Terminal 2: Initialize HAKUZA engagement
cd ~/projects/hakuza
python3 hakuza.py init testlab --client "Internal" --target "http://localhost:8000" --type web
python3 hakuza.py switch testlab
python3 hakuza.py scope --add "http://localhost:8000/*"
```

### Step 1: ReAct Orchestrator Test

**Goal**: Verify autonomous planning and execution loop

```bash
python3 hakuza.py orchestrate --max-iterations 5 --depth 3 --dry-run
```

**Expected Output**:
```
Iteration 1/5
  Technique: xss_reflected
  Target: http://localhost:8000/xss_reflected
  Rationale: Common web vuln, untested parameter
  [Executing...]
  ✓ Vulnerability found: Reflected XSS
  
Iteration 2/5
  Technique: sqli_error
  Target: http://localhost:8000/sqli_error
  [Executing...]
  ✓ Vulnerability found: SQL Injection - Error-Based
  
Iteration 3/5
  Technique: ssrf_cloud_metadata
  Target: http://localhost:8000/ssrf
  [Executing...]
  ✓ Test executed - no vulnerability detected

... [findings count] findings after 5 iterations
```

**Validation Checklist**:
- [ ] ReAct loop iterates N times
- [ ] LLM planning shows technique selection logic
- [ ] Executions happen without errors
- [ ] Findings persisted to DB (run `python3 hakuza.py findings testlab`)

---

### Step 2: Fireteam Parallel Investigation

**Goal**: Verify parallel agents, sync gates, approval gates

```bash
python3 hakuza.py fireteam --engagement testlab --waves 2
```

**Expected Output**:
```
Fireteam Wave: wave-1-recon
  Agents: 3
  Angles: subdomain_enum, web_recon, cloud_enum
  Timeout: 120s
  ──────────────────────────────────────────────
  [dim]Spawned agent wave-1-agent-0: subdomain_enum[/dim]
  [dim]Spawned agent wave-1-agent-1: web_recon[/dim]
  [dim]Spawned agent wave-1-agent-2: cloud_enum[/dim]

Wave Results:
  [green]wave-1-agent-0[/green]: subdomain_enum → 1 findings (2.5s)
  [green]wave-1-agent-1[/green]: web_recon → 3 findings (1.8s)
  [green]wave-1-agent-2[/green]: cloud_enum → 0 findings (0.5s)

Approve 4 findings from this wave? [Y/n]: y
```

**Validation Checklist**:
- [ ] Agents spawn in parallel (check timestamps are close)
- [ ] Sync gate waits for all agents
- [ ] Results consolidated and displayed
- [ ] Approval gate works (press 'n' and see findings rejected)
- [ ] Findings saved to DB after approval

---

### Step 3: Technique Execution Handlers

**Goal**: Verify each technique handler works independently

```bash
# Test individual technique handlers
python3 -c "
from mod_technique_executors import execute_technique
from hakuza import get_db, get_engagement

engagement = get_engagement('testlab')
result = execute_technique(
    technique_id='xss_reflected',
    target_url='http://localhost:8000/xss_reflected',
    params_list=['q'],
    engagement_id=engagement['id'],
    db=get_db()
)
print(f'Finding: {result}')
"
```

**Expected Output**:
```
Finding: {
  'title': 'Reflected XSS in parameter q',
  'severity': 'high',
  'evidence': 'Payload reflected in response',
  'curl_poc': 'curl http://localhost:8000/xss_reflected?q=...',
}
```

**Validation Checklist**:
- [ ] XSS handler finds reflection
- [ ] SQLi handler detects syntax errors
- [ ] SSRF handler detects timeouts
- [ ] Each handler returns finding dict or None
- [ ] All handlers have curl_poc populated

---

### Step 4: PoC Generator

**Goal**: Verify LLM-based PoC generation and validation

```bash
# Get a finding ID from previous tests
python3 hakuza.py findings testlab | grep "F001"

# Generate PoC for that finding
python3 -c "
from mod_poc_generator import generate_poc_for_finding, validate_poc
from hakuza import get_db

db = get_db()
finding = db.execute('SELECT * FROM findings LIMIT 1').fetchone()

poc = generate_poc_for_finding(dict(finding), test_enabled=True)
print(f'Generated PoC:\\n{poc}')
"
```

**Expected Output**:
```
Generated PoC:
curl -X GET 'http://localhost:8000/xss_reflected?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
```

**Validation Checklist**:
- [ ] LLM generates working curl command
- [ ] PoC validation passes (exit code 0)
- [ ] PoC saved to file system
- [ ] finding.curl_poc updated in DB

---

### Step 5: Attack-Surface Graph

**Goal**: Verify topology discovery and queryability

```bash
# Populate graph
python3 -c "
from mod_attack_graph import AttackSurfaceGraph
from hakuza import get_db, get_engagement

engagement = get_engagement('testlab')
graph = AttackSurfaceGraph(engagement['id'], get_db())

# Add discovered host
host_id = graph.add_host(
    hostname='localhost',
    ip='127.0.0.1',
    tool_source='manual'
)

# Add service
service_id = graph.add_service(
    host_id=host_id,
    port=8000,
    protocol='HTTP',
    service_name='testlab',
    version='1.0'
)

# Add vulnerability
graph.add_vulnerability(
    host_id=host_id,
    service_id=service_id,
    cve_id='CVE-2024-1234',
    severity='high',
    technique_id='xss_reflected'
)

# Query attack surface
surface = graph.query_attack_surface()
for row in surface:
    print(row)
"
```

**Expected Output**:
```
('localhost', 8000, 'testlab', 'CVE-2024-1234', 'high')
```

**Validation Checklist**:
- [ ] Hosts persisted correctly
- [ ] Services linked to hosts
- [ ] Vulnerabilities linked to services
- [ ] Attack-surface queries return results
- [ ] Graph nodes queryable by severity

---

### Step 6: Master Orchestrator (Full Pipeline)

**Goal**: Verify complete orchestration end-to-end

```bash
python3 hakuza.py master-orchestrate --engagement testlab --max-waves 3 --autonomous
```

**Expected Output**:
```
================================================================================
HAKUZA Master Orchestrator — Full Autonomous Engagement
================================================================================
Target: http://localhost:8000
Type: web
Autonomous Mode: Yes

Phase 1: Strategic Planning
  Strategy: Default Web Pentest
  Planned Waves: 3
  Planned Techniques: 12

Phase 2: Fireteam Parallel Reconnaissance
  Fireteam Wave: wave-1-recon
    Agents: 3
    [Results consolidated...]

Phase 3: Technique-Driven Exploitation
  Testing: xss_reflected
  Testing: sqli_error
  Testing: ssrf_cloud_metadata
  ...

Phase 4: Automated PoC Generation
  Generating PoC for Reflected XSS...
  Generating PoC for SQL Injection...
  ...

Phase 5: Attack-Surface Graph Analysis
  [Graph populated with 15 nodes]

Phase 6: Attack-Path Discovery
  Discovered 2 potential attack chains

Phase 7: Comprehensive Reporting
  Report: 12 findings
  Attack Paths: 2
  Severity: {'critical': 0, 'high': 4, 'medium': 6, 'low': 2, 'info': 0}

================================================================================
Engagement Complete
  Findings: 12
  Fireteam Waves: 3
  Techniques: 12
  PoCs Generated: 10
  Attack-Surface Nodes: 15
================================================================================
```

**Validation Checklist**:
- [ ] All 7 phases execute without errors
- [ ] Findings count matches (should be 12+ for testlab)
- [ ] PoCs generated for all findings
- [ ] Attack-surface graph populated
- [ ] Attack paths discovered
- [ ] Report compiles successfully

---

### Step 7: Report Generation

**Goal**: Verify final deliverable

```bash
python3 hakuza.py report testlab --format html
```

**Expected Output**:
```
✓ Report generated: engagements/testlab/reports/TESTLAB_PENTEST_20250730.html

Open in browser: file:///home/hakuza/.hakuza/engagements/testlab/reports/TESTLAB_PENTEST_20250730.html
```

**Validation Checklist**:
- [ ] HTML report generates without errors
- [ ] All findings included with PoCs
- [ ] ATT&CK techniques mapped (T1190, T1078, etc.)
- [ ] Attack chains included
- [ ] Severity gauge displayed correctly
- [ ] Remediation prioritization present

---

## Regression Testing

After any code changes, run this full scenario to ensure no regressions:

```bash
# Automated test script
cat > test_full_engagement.sh << 'EOF'
#!/bin/bash
set -e

echo "=== Cleaning up previous run ==="
rm -rf ~/.hakuza/engagements/testlab

echo "=== Starting testlab ==="
cd ~/projects/hakuza/testlab
python3 -m http.server 8000 > /dev/null 2>&1 &
TESTLAB_PID=$!
sleep 2

echo "=== Initializing engagement ==="
cd ~/projects/hakuza
python3 hakuza.py init testlab --client "Internal" --target "http://localhost:8000" --type web
python3 hakuza.py switch testlab
python3 hakuza.py scope --add "http://localhost:8000/*"

echo "=== Running orchestrator (5 iterations) ==="
python3 hakuza.py orchestrate --max-iterations 5 --depth 3

echo "=== Running Fireteam (2 waves) ==="
# Would need --force-yes flag for automated approval
# python3 hakuza.py fireteam --engagement testlab --waves 2

echo "=== Running master orchestrator ==="
python3 hakuza.py master-orchestrate --engagement testlab --max-waves 2 --autonomous

echo "=== Generating report ==="
python3 hakuza.py report testlab --format html

echo "=== Test Results ==="
FINDINGS=$(python3 hakuza.py findings testlab | grep -c "VAPT-WEB" || echo 0)
echo "Total findings: $FINDINGS"

if [ "$FINDINGS" -gt 10 ]; then
    echo "✓ PASS: Found $FINDINGS vulnerabilities (expected >10)"
else
    echo "✗ FAIL: Only found $FINDINGS vulnerabilities (expected >10)"
    exit 1
fi

echo "=== Cleanup ==="
kill $TESTLAB_PID 2>/dev/null || true

echo "✓ Full engagement test PASSED"
EOF

chmod +x test_full_engagement.sh
./test_full_engagement.sh
```

---

## Success Criteria

After running this test scenario, you should have:

✅ **Orchestration Loop**: 5+ iterations with technique decisions  
✅ **Fireteam Waves**: 3+ parallel agents per wave, sync gates working  
✅ **Technique Executors**: 10+ vulnerabilities discovered  
✅ **PoC Generation**: 90%+ of findings have working curl PoCs  
✅ **Attack-Surface Graph**: 15+ nodes (hosts, services, vulns) queryable  
✅ **Master Orchestrator**: Complete lifecycle (plan→execute→report) <5 min  
✅ **Report**: HTML deliverable with findings, PoCs, attack chains, ATT&CK mapping  

---

## Troubleshooting

| Issue | Debug |
|-------|-------|
| "No techniques loaded" | Check techniques.yaml exists and YAML is valid |
| "Executor not found" | Check mod_technique_executors.py is imported in mod_orchestrate.py |
| "No findings after orchestrate" | Check testlab endpoints are accessible on localhost:8000 |
| "PoC generation fails" | Check ANTHROPIC_API_KEY is set; verify LLM returns valid JSON |
| "Graph queries return nothing" | Check DB migrations ran in init_db(); verify hosts/services were added |

---

**Test Status**: Ready to run once all modules assembled  
**Estimated Runtime**: 5-10 minutes for full scenario  
**Expected Coverage**: All 23 testlab endpoints should be tested  
