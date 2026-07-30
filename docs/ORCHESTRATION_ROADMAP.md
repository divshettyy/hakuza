# HAKUZA Orchestration Roadmap (2025)

## Overview
This document outlines the enhancement roadmap to transform HAKUZA from a command-driven penetration testing tool into an autonomous, AI-orchestrated red-team platform comparable to Shannon and RedAmon.

## Current Status (v2.0)
✅ Engagement DB (SQLite) with full lifecycle tracking  
✅ 23+ active vulnerability classes (live differential testing, not template matching)  
✅ Web dashboard + Playwright E2E tests  
✅ Tool orchestration (subfinder, httpx, katana, nuclei, ffuf)  
✅ Multiple testing modes (recon, takeover, wayback, secrets, scan, active)  
✅ AI analysis via Claude (triage, chaining, reporting)  
✅ Scope enforcement + modular architecture  

## Phase 1: Foundation (CURRENT — DB Schema + Technique Library)

### ✅ COMPLETED
1. **DB Schema Migration**
   - Added columns to `findings` table:
     - `technique_id` — maps findings to MITRE ATT&CK-tagged techniques
     - `cve_id` — stores CVE identifier for PoC discovery
     - `curl_poc` — reproducible curl command for exploitation
     - `poc_file` — path to PoC artifact (script, payload)
     - `poc_links` — JSON array of auto-discovered GitHub/ExploitDB links
   - Migration code in `init_db()` handles backwards compatibility

2. **ATT&CK Technique Library** (`techniques.yaml`)
   - 25 core web/API vulnerability techniques
   - Each technique includes:
     - MITRE ATT&CK T-IDs (mapped to tactics)
     - Applicability tags (web, api, database, auth, etc.)
     - Prerequisites + procedure steps
     - Expected artifacts (curl command, PoC file, source snippet)
     - Severity level (critical/high/medium/low/info)
   - Extensible YAML schema for future domains (network, cloud, mobile, AD)

3. **PyYAML Dependency** (`requirements.txt`)
   - Added `pyyaml>=6.0` for technique library loading

### 🔄 IN PROGRESS — Module Integration
Three new modules created but **assemble.py has a known duplication bug**:

**`mod_techniques.py`** — 173 lines
- `load_techniques()` — load & cache techniques from YAML
- `find_techniques_by_tags(tags)` — filter by applicability
- `find_techniques_by_severity(sev)` — filter by severity
- `cmd_list_techniques()` / `cmd_show_technique()` — CLI commands
- Provides: `list-techniques`, `show-technique` subcommands

**`mod_poc_discovery.py`** — 161 lines
- `search_github_poc(cve_id)` — GitHub API search for working exploits
- `extract_poc_links(cve_id)` — aggregate PoC sources
- `enrich_finding_with_poc()` — auto-enrich findings with PoC URLs
- Provides: `poc-discover` subcommand
- Pattern: CVE-XXXX → GitHub search → return top 3 repos with stars/language

**`mod_orchestrate.py`** — 198 lines
- `build_orchestration_prompt()` — craft ReAct prompt for LLM
- `run_orchestration_loop()` — autonomous agent loop (iteration counter, depth control)
- `cmd_orchestrate()` — entry point for `hakuza orchestrate` command
- Provides: `orchestrate` subcommand with `--depth`, `--max-iterations`, `--dry-run` flags
- Pattern: read engagement state → ask Claude what to test next → execute → loop

**KNOWN ISSUE**: `assemble.py` has a bug that injects ARGPARSE/DISPATCH blocks twice, causing argparse conflicts (e.g., duplicate "ad" parser). This needs fixing before modules can be assembled.

---

## Phase 2: Autonomous Orchestration (Next)

### Objective
Transform HAKUZA from command-driven to autonomous agent-driven via a ReAct-style planner.

### Implementation
1. **Fix assemble.py duplication bug**
   - The `inject_argparse()` and `inject_dispatch()` functions are matching too many insertion points
   - Test case: ensure single injection of each ARGPARSE/DISPATCH block per module

2. **Integrate mod_techniques.py**
   - Add `/technique` commands to CLI
   - Load techniques.yaml at startup
   - Expose via `_techniques_cache` global for orchestrator access

3. **Integrate mod_poc_discovery.py**
   - Add `/poc-discover CVE-XXXX` command
   - Auto-enrich findings when CVE is detected
   - Calls `enrich_finding_with_poc()` with DB connection

4. **Integrate mod_orchestrate.py**
   - Add `orchestrate` command to main dispatch
   - Hook into existing Claude client + SYSTEM_PROMPT
   - Orchestrator reads findings via `list_findings()`, plans via LLM, executes via technique handlers

5. **Execution Handlers** (Stub → Real)
   - Each technique needs an executor function that:
     - Takes target URL + parameters
     - Runs test via existing tool (active engine, subprocess, or API)
     - Parses results → calls `add_finding()`
   - Example: `xss_reflected` → calls `mod_active.test_xss_reflected(url, param)`

### Key Architecture Decisions
- **ReAct Loop**: LLM → Thought/Action/Observation → Execution → Loop
- **Technique-Centric**: Every finding tagged with `technique_id` enables ATT&CK coverage reporting
- **PoC-First**: Every finding includes reproducible exploit (curl, script, or GitHub link)
- **Autonomous**: Default mode (with approval gates for dangerous ops)
- **Fallback**: Degrades to manual command-driven mode if orchestrator disabled

---

## Phase 3: Attack Surface Persistence (Later)

### Objective
Build a queryable topology graph (like RedAmon's Neo4j) for complex multi-target engagements.

### Options
1. **Neo4j Backend** (RedAmon pattern)
   - Pros: Excellent query/traversal, attack-path analysis
   - Cons: Heavy dependency, requires service
   - Use when: VAPT firm with many targets, complex networks

2. **Enhanced SQLite** (Lighter)
   - Pros: No external service, already using SQLite
   - Cons: No native graph queries
   - Tables: `hosts`, `services`, `ports`, `apps`, `users`, `credentials`, `shares`
   - Pattern: Build queryable schema, write analytical queries

**Recommendation**: Start with SQLite schema, migrate to Neo4j as optional backend later.

---

## Phase 4: Advanced Features (Beyond Scope Today)

### White-Box Source Analysis (Shannon Pattern)
- Analyze source code for data flows
- Map attack paths: entry points → sinks
- Requires: Language-specific parsers (Python AST, JS/TS TypeScript compiler, Java BCEL, etc.)
- Complexity: Very High
- Value: High (finds complex bugs early)

### Fireteam Parallel Agents (RedAmon Pattern)
- Fan out N independent sub-agents per angle
- Sync gates before execution
- Consolidate results
- Requires: Better agent orchestration infrastructure
- Complexity: Medium
- Value: Medium (faster recon, but more API costs)

### Code Remediation + GitHub PR Generation (CypherFix Pattern)
- Identify exploitable finding
- Analyze source code for root cause
- Generate fix via LLM
- Create GitHub PR automatically
- Requires: Deep code analysis + git API integration
- Complexity: High
- Value: Medium-High (automates post-exploit workflow)

### Dynamic Payload Mutation (Bashfuscator/Covenant Pattern)
- Convert static payloads to chainable mutation pipeline
- Severity dial: light → medium → aggressive obfuscation
- Applies to: WAF/IDS bypass, XSS encodings, SQL injection obfuscation
- Requires: Mutation framework + encoding chains
- Complexity: Medium
- Value: Medium (better WAF evasion)

### Traffic Capture Integration (TrafficMind Pattern)
- Optional mitmproxy/tcpdump during active tests
- Replay suspicious requests via Burp-style UI
- Requires: Proxy integration + binaries
- Complexity: Low-Medium
- Value: Low-Medium (nice-to-have, mainly for manual triage)

---

## Implementation Priority

### Must-Have (Tier 1 — This Month)
1. ✅ DB schema + add_finding updates → **DONE**
2. ✅ techniques.yaml + mod_techniques.py → **DONE**
3. ✅ mod_poc_discovery.py → **DONE**
4. ✅ mod_orchestrate.py → **DONE**
5. 🔄 Fix assemble.py duplication bug → **IN PROGRESS**
6. 🔄 Integrate all modules into hakuza.py → **BLOCKED on #5**
7. ⏳ Test orchestrator loop against testlab/ → **NEXT**

### Nice-To-Have (Tier 2 — Next Month)
- Attack-surface SQLite schema (hosts, services, ports, apps)
- Execution handlers for each technique (hook up to mod_active engine)
- Approval gates for dangerous operations
- Parallel multi-target fuzzing (async threads)

### Later (Tier 3)
- Neo4j optional backend
- White-box source code analysis
- Fireteam parallel agents
- Code remediation + GitHub PR generation
- Dynamic payload mutations
- Traffic capture integration

---

## Testing Strategy

### Regression Tests
- Existing commands must not break: recon, scan, active, report, etc.
- Run against testlab/ for 23 existing vuln classes

### New Feature Tests
- `hakuza list-techniques` — verify YAML loads, 25 techniques visible
- `hakuza show-technique sqli_union` — verify full details including MITRE mappings
- `hakuza poc-discover CVE-2021-44228` — verify GitHub search, top 3 results returned
- `hakuza orchestrate --dry-run --max-iterations 3` — verify LLM planning, no actual execution

### Integration Tests
- End-to-end: `hakuza orchestrate` runs for N iterations, discovers findings, enrich with PoC
- DB validation: findings table has all 5 new columns populated
- Backwards compatibility: existing findings (from before 2025 update) still queryable

---

## Risk Mitigation

### Assembly Bug (Current Blocker)
- **Risk**: assemble.py injects duplicate ARGPARSE/DISPATCH blocks
- **Impact**: CLI argparse conflicts, tool unusable
- **Mitigation**: Debug injection logic, add test harness, verify single injection per module

### LLM Cost (Orchestration)
- **Risk**: Continuous ReAct loop calls Claude $$ on every iteration
- **Impact**: Engagement costs can spiral
- **Mitigation**: Depth limit, iteration cap, dry-run mode, cost tracking in logs

### Authorization Bypass (PoC Discovery)
- **Risk**: Auto-discovered PoC might trigger IDS/WAF during execution
- **Impact**: Engagement discovered, client notified
- **Mitigation**: Approval gates for PoC execution, require explicit opt-in

### Schema Incompatibility
- **Risk**: Old DB versions don't have new columns
- **Impact**: add_finding() queries fail
- **Mitigation**: Migration code in init_db() handles backwards compatibility

---

## Success Criteria

✅ New findings have technique_id + cve_id populated  
✅ Techniques.yaml loads and techniques accessible via CLI  
✅ PoC discovery returns GitHub links for known CVEs  
✅ Orchestrator loop runs autonomously, makes 3+ sequential decisions  
✅ All tests pass including regressions on testlab/  
✅ Zero breakage to existing commands  
✅ Documentation updated (README + docs/)  

---

## Next Steps (After This PR)

1. Debug and fix assemble.py duplication issue
2. Re-assemble hakuza.py with all three new modules
3. Implement execution handlers for each technique (hook to mod_active)
4. Build comprehensive end-to-end test scenario
5. Test against testlab/ for regressions
6. Document in README + update version to v2.1.0

---

**Document Generated**: 2025-07-30  
**Status**: Foundation phase complete, assembly phase in progress  
**Next Review**: After assemble.py fix (target: 2025-08-01)
