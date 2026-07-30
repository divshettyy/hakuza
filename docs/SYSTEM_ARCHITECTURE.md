# HAKUZA System Architecture (v3.0)

## The Best Red-Team Tool: Autonomous, Parallel, ATT&CK-Mapped, PoC-Verified

This document describes the complete architecture of HAKUZA's autonomous orchestration system—synthesizing the best patterns from Shannon, RedAmon, and 40+ red-team projects into a unified, production-grade platform.

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     HAKUZA Master Orchestrator                              │
│                    (mod_master_orchestrator.py)                             │
│                                                                              │
│  Coordinates: Planning → Fireteam Waves → Execution → PoC Gen →            │
│               Graph Enrichment → Attack-Path Analysis → Report              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │ ReAct        │      │ Fireteam     │      │ Technique    │
        │ Orchestrator │      │ Coordinator  │      │ Executors    │
        │              │      │              │      │              │
        │ LLM plans    │      │ Fan out N    │      │ Run attack   │
        │ next step    │      │ agents       │      │ handlers     │
        └──────────────┘      └──────────────┘      └──────────────┘
                │                   │                    │
                └─────────────────────┼────────────────────┘
                                      ▼
                        ┌──────────────────────────┐
                        │ Technique Library        │
                        │ (techniques.yaml)        │
                        │ 25+ ATT&CK-tagged       │
                        │ vulnerability classes    │
                        └──────────────────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │ PoC          │      │ Attack-      │      │ Findings DB  │
        │ Generator    │      │ Surface      │      │              │
        │              │      │ Graph        │      │ SQLite       │
        │ Auto-gen     │      │              │      │ enriched     │
        │ exploits     │      │ Neo4j/SQLite │      │ with         │
        │              │      │ queryable    │      │ technique_id,│
        │              │      │ topology     │      │ cve_id, PoC  │
        └──────────────┘      └──────────────┘      └──────────────┘
```

---

## Component Details

### 1. Master Orchestrator (`mod_master_orchestrator.py`)

**Role**: Central coordinator that orchestrates full autonomous engagement.

**Phases**:
1. **Planning**: LLM reads engagement state, formulates attack strategy
2. **Fireteam Waves**: Fan out parallel reconnaissance agents
3. **Technique Execution**: Execute planned techniques via handlers
4. **PoC Generation**: Auto-generate reproducible exploits
5. **Graph Enrichment**: Populate attack-surface topology
6. **Attack-Path Analysis**: Discover multi-step exploitation chains
7. **Reporting**: Compile comprehensive pentest report

**Key Methods**:
- `execute_full_engagement(max_waves, autonomous)` — Run full lifecycle
- `_generate_strategy(engagement, max_waves)` — LLM-driven attack planning
- `_discover_attack_paths()` — Find exploitation chains from graph
- `_generate_report(findings, attack_paths)` — Produce pentest deliverable

**CLI**: `hakuza master-orchestrate [--autonomous] [--max-waves 5]`

---

### 2. ReAct Orchestrator (`mod_orchestrate.py`)

**Role**: ReAct-style loop: Thought → Action → Observation → Repeat.

**Pattern**:
```
1. Read engagement state (current findings, recon status, gaps)
2. LLM thinks: "What should I test next?"
3. LLM actions: "Technique: xss_reflected, Target: /search?q=test, Params: [q]"
4. Execute action via handler
5. Observe: "Finding: Reflected XSS, Severity: High, PoC: curl ..."
6. Loop until complete or depth limit reached
```

**Key Methods**:
- `run_orchestration_loop(engagement_name, depth, max_iterations)`
- `build_orchestration_prompt(engagement, findings, techniques)` — Craft prompt
- Integrated into Master Orchestrator Phase 3

**CLI**: `hakuza orchestrate [--depth 5] [--max-iterations 10] [--dry-run]`

---

### 3. Fireteam Coordinator (`mod_fireteam.py`)

**Role**: Fan out parallel investigation agents, sync, consolidate results.

**Pattern** (from RedAmon):
```
Wave 1: Fan out 3 agents
├─ Agent A: Subdomain enumeration (crt.sh, subfinder, hackertarget)
├─ Agent B: Web reconnaissance (tech fingerprint, headers, paths)
└─ Agent C: Cloud enumeration (S3, GCP, Azure asset discovery)
    │
    └─ Sync gate: Wait for all agents to complete (timeout: 120s)
       │
       └─ Approval gate: "Approve 47 findings from this wave?" (if autonomous=False)
          │
          └─ Persist to DB (enriches attack-surface graph)
```

**Key Concepts**:
- **Waves**: Sequential batches of parallel agents
- **Sync Gate**: Wait for all agents in wave to complete before proceeding
- **Approval Gate**: Human review of findings (optional, disabled in autonomous mode)
- **Investigation Angles**: "subdomain_enum", "web_recon", "api_scan", "cloud_enum", etc.

**Key Methods**:
- `run_wave(wave_spec)` — Execute one wave of parallel agents
- `_run_agent(agent_id, angle, timeout)` — Execute one angle in dedicated thread
- `_execute_angle(angle, timeout)` — Dispatch to angle-specific handler

**Supported Angles**:
- `subdomain_enum` — Discover subdomains via CT logs, DNS, reverse lookup
- `web_recon` — Tech fingerprint, security headers, hidden paths
- `api_scan` — GraphQL introspection, REST enumeration, versioning
- `cloud_enum` — S3 bucket discovery, GCP/Azure storage, serverless APIs
- `network_scan` — Nmap, service fingerprint, OS detection
- `vulnerability_scan` — Nuclei templates, CVE enrichment
- `secret_hunting` — Exposed creds in JS files, git repos, env files
- `supply_chain` — Dependency analysis, 3rd-party service exposure

**CLI**: `hakuza fireteam [--engagement NAME] [--waves 3]`

---

### 4. Technique Library (`techniques.yaml`)

**Role**: Centralized, ATT&CK-tagged vulnerability technique specifications.

**Structure** (each technique):
```yaml
- id: xss_reflected
  name: "Reflected Cross-Site Scripting (XSS)"
  mitre: ["T1190", "T1204.001"]
  description: "Inject malicious JavaScript into URL parameters..."
  applicability_tags: [web, webapp, api]
  prerequisites: [target_url, parameter_list]
  procedure: "Test URL parameters for unsanitized HTML/JS reflection..."
  expected_artifacts: [curl_command, poc_url, source_snippet]
  severity: high
```

**Benefits**:
- **ATT&CK Mapping**: Every finding auto-maps to MITRE techniques
- **Coverage Reporting**: "You tested 15/25 techniques (60% coverage)"
- **Autonomous Planning**: LLM picks techniques based on target type + gaps
- **Extensibility**: Add 100+ techniques without code changes

**Current**: 25 core web/API techniques. Extensible to network, cloud, mobile, AD.

---

### 5. Technique Executors (`mod_technique_executors.py`)

**Role**: Actual handlers that run each technique. Hook to mod_active engine.

**Pattern**:
```python
def execute_xss_reflected(target_url, params, engagement_id, db):
    """Execute XSS reflected technique against URL."""
    for param in params:
        payload = "<script>alert(1)</script>"
        response = requests.get(target_url, params={param: payload})
        if payload in response.text:
            # Found XSS
            finding = {
                "title": "Reflected XSS",
                "severity": "high",
                "evidence": f"Parameter '{param}' reflects unsanitized input",
                "curl_poc": f"curl '{target_url}?{param}={payload}'",
            }
            add_finding(engagement_id, **finding)
            return finding
    return None
```

**Key Methods**:
- `execute_technique(technique_id, target_url, params, engagement_id, db)`
- Individual handlers for each technique (xss_reflected, sqli_error, ssrf_cloud_metadata, etc.)
- Falls back to curl command generation if mod_active unavailable
- Validates finding before persisting (parse response, confirm vulnerability present)

**Execution Flow**:
1. Orchestrator decides: "Test XSS on /search?q"
2. Calls `execute_xss_reflected("/search", params=["q"])`
3. Injects payloads, checks for reflection
4. If vulnerable: `add_finding(...)` + returns finding dict
5. If not: Returns None

---

### 6. PoC Generator (`mod_poc_generator.py`)

**Role**: Auto-generate standalone, reproducible exploits for each finding.

**Pattern** (from Covenant):
```
Finding discovered: "Reflected XSS in /search?q"
↓
LLM generates: "curl 'http://target/search?q=<script>alert(1)</script>'"
↓
Validate: Test PoC against testlab/ endpoint
↓
If valid: Save to engagements/<name>/poc/<finding_id>.sh
↓
Update finding.curl_poc = "curl ..."
↓
Include in report: "Exploit: [copy-paste ready curl command]"
```

**Key Methods**:
- `generate_poc_for_finding(finding_dict, test_enabled=True)`
- `validate_poc(poc_code, target_url, expected_result)` — Verify PoC works
- `save_poc(poc_code, finding_id, engagement_id)`

**Validation**:
- Execute PoC against testlab/ corresponding endpoint
- Exit code 0 = vuln confirmed, exit 1 = false positive
- Only save PoC if validation passes
- Fallback: use auto-discovered GitHub link if PoC generation fails

---

### 7. Attack-Surface Graph (`mod_attack_graph.py`)

**Role**: Queryable topology persistence and attack-path discovery.

**Data Model**:
```
hosts
├─ id, engagement_id, hostname, ip, discovered_via, discovered_at
services
├─ id, host_id, port, protocol, service_name, version, discovered_via
vulnerabilities
├─ id, host_id, service_id, cve_id, severity, technique_id, finding_id
credentials
├─ id, host_id, username, password_hash, source_tool
shares
├─ id, host_id, share_name, access_level, discovered_via
attack_paths
├─ id, start_host_id, start_service_id, end_host_id, technique_chain, likelihood
```

**Queries**:
```sql
-- What's my attack surface?
SELECT h.hostname, s.port, s.service_name, v.cve_id, v.severity 
FROM hosts h 
JOIN services s ON h.id = s.host_id 
LEFT JOIN vulnerabilities v ON s.id = v.service_id 
WHERE h.engagement_id = ? 
ORDER BY v.severity DESC

-- What attack paths exist?
SELECT * FROM attack_paths 
WHERE start_host_id = ? 
ORDER BY likelihood DESC
```

**Integration**:
- When mod_active finds XSS on `http://api.example.com:443/search`, auto-populate:
  - `hosts(hostname='api.example.com', ip='203.0.113.45')`
  - `services(port=443, service_name='HTTPS', ...)`
  - `vulnerabilities(cve_id=None, severity='high', technique_id='xss_reflected')`

**Future**: Migrate to Neo4j for advanced graph queries and visualization.

---

### 8. Findings Database Schema (Enhanced)

**New Columns** (added in Phase 1):
- `technique_id` — Links finding to MITRE ATT&CK technique
- `cve_id` — CVE identifier (enables PoC auto-discovery)
- `curl_poc` — Reproducible curl command
- `poc_file` — Path to standalone PoC script
- `poc_links` — JSON array of GitHub/ExploitDB PoC links

**Benefits**:
- Every finding is **technique-tagged** → automatic ATT&CK coverage reporting
- Every CVE → **auto-discovered exploits** via GitHub API
- Every finding → **standalone, reproducible PoC**
- Enables **deduplication**: same technique on different param = linked findings

---

## Execution Flow: End-to-End Example

```
User runs: hakuza master-orchestrate --max-waves 5 --autonomous

1. PLANNING PHASE
   ├─ Read engagement: "web pentest on example.com"
   ├─ LLM strategy: "Use 3 waves: recon (subdomain+web+cloud), scan (api+vuln+secrets), depth (supply_chain+network)"
   ├─ Load techniques.yaml: 25 techniques available
   └─ Populate initial strategy

2. WAVE 1: RECONNAISSANCE (Parallel Fireteam)
   ├─ Agent A: Subdomain enum → discover api.example.com, cdn.example.com
   ├─ Agent B: Web recon → fingerprint: Express.js, AWS, CloudFlare
   └─ Agent C: Cloud enum → discover S3 bucket "example-assets-2024"
       │
       └─ Sync: Wait for all → 3 findings persisted to DB

3. WAVE 2: SCANNING (Parallel Fireteam)
   ├─ Agent A: API scan → discover /api/v1/users, /api/v1/products
   ├─ Agent B: Vulnerability scan → Nuclei templates → 2 findings
   └─ Agent C: Secret hunting → exposed AWS key in JS file
       │
       └─ Sync: 5 findings persisted

4. TECHNIQUE EXECUTION (ReAct Loop)
   ├─ Iteration 1:
   │  ├─ LLM: "Found web app, should test XSS and SQLi"
   │  ├─ Execute: xss_reflected on /search?q
   │  ├─ Result: "XSS found in q parameter"
   │  └─ Add finding: technique_id='xss_reflected', severity='high'
   ├─ Iteration 2:
   │  ├─ LLM: "Found API, should test mass assignment and IDOR"
   │  ├─ Execute: idor_horizontal on /api/v1/users/{id}
   │  └─ Result: "Can access other users' profiles"
   └─ Continue until depth or max_iterations reached

5. POC GENERATION (Automated)
   ├─ For XSS finding:
   │  ├─ LLM generates: "curl 'http://api.example.com/search?q=<script>...'"
   │  ├─ Validate: Execute against testlab/xss endpoint
   │  ├─ Result: "PoC works, exit code 0"
   │  └─ Save: poc_file = "engagements/example/poc/F001_xss.sh"
   ├─ For IDOR finding:
   │  ├─ Auto-discover: GitHub search "IDOR example.com" → 3 public exploits
   │  └─ Add: poc_links = [{"url": "github.com/...", "stars": 45, ...}]
   └─ For CVE-2024-50379 (if discovered):
      ├─ Auto-discover: GitHub + ExploitDB
      └─ Attach links + working PoC

6. GRAPH ENRICHMENT
   ├─ XSS on api.example.com → add_vulnerability(host_id, service_id, ...)
   ├─ API enumeration → add_service(host_id, port=443, service='HTTPS')
   ├─ S3 bucket discovery → add_host(hostname='example-assets-2024.s3.amazonaws.com')
   └─ Build attack_paths: api.example.com(XSS) → SSRF to S3 bucket

7. ATTACK-PATH ANALYSIS
   ├─ Query: "Find multi-step chains"
   ├─ Result: "api.example.com (XSS) → SSRF to internal IP → RCE via exposed socket"
   └─ Estimate likelihood: 85%

8. REPORTING
   ├─ Compile findings: 12 total (3 critical, 4 high, 5 medium)
   ├─ Include PoCs: "All 12 findings have reproducible curl/script exploits"
   ├─ ATT&CK mapping: "T1190 (9 findings), T1078 (2), T1567 (1)"
   ├─ Attack chains: 3 multi-step exploitation paths
   └─ Remediation: Prioritized by CVSS + business impact

9. SUMMARY
   └─ Output:
      "✓ 12 findings discovered
       ✓ 5 Fireteam waves completed (8 parallel agents per wave)
       ✓ 15 techniques tested (60% coverage)
       ✓ 12 PoCs generated and validated
       ✓ 18 attack-surface nodes populated
       ✓ 3 multi-step exploitation chains discovered
       ✓ Report: engagements/example/reports/EXAMPLE_PENTEST_20250730.html"
```

---

## Why This Is Best-in-Class

| Feature | Shannon | RedAmon | HAKUZA v3 |
|---------|---------|---------|-----------|
| **Autonomous Loop** | ✓ ReAct | ✓ LangGraph | ✓ ReAct + Fireteam |
| **White-Box Analysis** | ✓ Source code | ✗ | 🔄 Planned |
| **Parallel Agents** | ✗ | ✓ Fireteam | ✓ Fireteam 3.0 |
| **Attack-Surface Graph** | ✗ | ✓ Neo4j | ✓ SQLite + Neo4j-ready |
| **PoC Validation** | ✗ | ✗ | ✓ LLM-gen + tested |
| **ATT&CK-Mapped** | ✗ | ✗ | ✓ Full technique library |
| **Technique Library** | ✗ | ✗ | ✓ 25+, extensible |
| **One Unified Platform** | ✗ | ✓ | ✓ CLI + dashboard |

---

## Deployment Options

### Local Development (Current)
```bash
cd ~/projects/hakuza
python3 hakuza.py master-orchestrate --max-waves 5 --autonomous
```

### Docker Container (Production)
```bash
docker build -t hakuza:latest .
docker run -it -e ANTHROPIC_API_KEY=... hakuza:latest \
  master-orchestrate --engagement example.com --autonomous
```

### Red-Team Infrastructure
```bash
# Standalone autonomous scanner + reporting
hakuza master-orchestrate --engagement target --autonomous --max-waves 10 \
  --output report.html --slack-notify https://...
```

---

## Next Phases (Roadmap)

### Immediate (This Week)
- ✅ Technique library + executors
- ✅ Fireteam parallel agents
- ✅ Master orchestrator
- ✅ PoC generator
- 🔄 Assembly integration (in-flight)

### Next (Next Week)
- [ ] White-box source code analysis (Shannon-style)
- [ ] Neo4j attack-surface persistence
- [ ] Advanced attack-path algorithms (Dijkstra for least-effort chains)
- [ ] Multi-target orchestration (fan out to 100+ hosts)

### Later (Weeks 3-4)
- [ ] Red-team infrastructure provisioning (C2, phishing, MITM)
- [ ] Supply-chain attack simulation
- [ ] Collaborative red team (approval workflows, shared graph)
- [ ] Continuous red team (recurring scans, trend analysis)

---

## Architecture Principles

1. **Modularity**: Each component (Fireteam, ReAct, PoC Gen, Graph) independently testable
2. **Parallelism**: Use threading for I/O-bound tasks (network recon)
3. **Composability**: Orchestrator chains modules, not vice versa
4. **Validation**: Every finding requires PoC proof; every PoC must be tested
5. **Automation**: LLM plans attack strategy; humans approve dangerous operations
6. **Traceability**: All findings link to techniques → ATT&CK mapping automatic
7. **Extensibility**: Technique library grows without code changes

---

**Document Generated**: 2025-07-30  
**Architecture Version**: 3.0 (Master Orchestrator)  
**Status**: In Development (4 parallel agents)  

See `ORCHESTRATION_ROADMAP.md` for detailed implementation plan.
