# HAKUZA Phase 4+: Expansion to 100+ Techniques

## Current Status (v3.0 Release)
- **34 techniques** implemented
- **14 handlers** built
- **7 orchestration phases** complete
- **25,000+ lines of code**
- **Production ready**

## Vision: Market-Leading Platform
Transform from "good autonomous red-team tool" to **"undisputed market leader"** by:
1. 3x technique coverage (100+ vs. 34)
2. Advanced orchestration (white-box analysis, ML prioritization)
3. Enterprise hardening (scale, performance, reliability)
4. Integrated exploitation (auto-chains, impact scoring)

---

## Phase 4: Technique Expansion (100+ Techniques)

### NEW HANDLER GROUPS (30+ handlers needed)

#### Web/HTTP (15+ new handlers)
- [x] XSS Reflected (exist)
- [x] XSS Stored (exist)
- [ ] **XSS DOM-based** — eval() in JS
- [ ] **XSS WAF Bypass** — encoding tricks
- [x] SQLi Error-based (exist)
- [x] SQLi Blind (exist)
- [ ] **SQLi UNION** — column enumeration
- [ ] **SQLi Time-based** — conditional delays
- [ ] **SQLi Stacked** — multi-query injection
- [ ] **NoSQL Injection** — MongoDB operators
- [ ] **CSV Injection** — formula injection
- [ ] **LDAP Injection** — directory traversal
- [ ] **XXE Advanced** — parameter entity expansion
- [x] LFI Traversal (exist)
- [ ] **LFI Wrapper** — PHP wrappers, log poisoning
- [ ] **Path Traversal** — Windows paths

#### API/Authentication (12+ new handlers)
- [x] JWT None Algorithm (exist)
- [ ] **JWT Weak Secret** — brute-force keys
- [ ] **JWT Algorithm Confusion** — RS256→HS256
- [ ] **JWT KID Injection** — path traversal
- [ ] **OAuth Implicit Flow** — token leakage
- [ ] **OAuth Authorization Code** — CSRF, redirect_uri bypass
- [ ] **OIDC Misconfiguration** — scope escalation
- [ ] **API Key Exposure** — hardcoded keys
- [ ] **API Rate Limit Bypass** — IP header spoofing
- [ ] **API Versioning Bypass** — v1→v2 escalation
- [ ] **API Mass Assignment** — extra fields
- [ ] **GraphQL Injection** — query depth, aliases

#### Infrastructure (15+ new handlers)
- [x] SSRF Cloud Metadata (exist)
- [ ] **SSRF Advanced** — gopher://, dict://, tftp://
- [ ] **SSRF→RCE** — internal service exploitation
- [ ] **Open Redirect** — filter bypass
- [ ] **CORS Misconfiguration** (exist foundation)
- [ ] **CORS Null Origin** — wildcard + null
- [ ] **Subdomain Takeover** — dangling DNS
- [ ] **Cache Poisoning** — unkeyed headers
- [ ] **HTTP Smuggling** — CL.TE, TE.TE
- [ ] **Host Header Injection** — password reset links
- [ ] **Prototype Pollution** — JavaScript gadgets
- [ ] **Deserialization** — Java gadgets (ysoserial)
- [ ] **Race Condition** — concurrent requests
- [ ] **Timing Attack** — brute-force via latency
- [ ] **DNS Rebinding** — local network bypass

#### Advanced (10+ new handlers)
- [x] SSTI Injection (exist)
- [ ] **SSTI Template Engine Detection** — Jinja2, Twig, FreeMarker, Mako, Velocity
- [ ] **SSTI→RCE Chains** — per-engine payloads
- [ ] **Server-Side Template Injection Variants** — multiple engines
- [x] Default Credentials (exist)
- [ ] **Weak Credentials** — common password lists
- [ ] **Credential Reuse** — across services
- [ ] **Insecure Randomness** — predictable tokens
- [ ] **Hardcoded Secrets** — in JS, config files
- [x] IDOR Horizontal (exist)
- [ ] **IDOR Vertical** — role escalation
- [ ] **IDOR UUID Prediction** — sequential IDs
- [ ] **Mass Assignment** — beyond basic (exist)

#### Cloud/Advanced (12+ new handlers)
- [ ] **AWS S3 Misconfiguration** — bucket list, object read/write
- [ ] **AWS IAM Enumeration** — role/policy discovery
- [ ] **AWS Credential Exposure** — metadata service
- [ ] **GCP Storage Misconfiguration** — Firebase, Cloud Storage
- [ ] **Azure Blob Exposure** — SAS token reuse
- [ ] **Kubernetes API Exposure** — pod escape, RBAC
- [ ] **Docker Daemon Exposure** — container creation
- [ ] **Database Connection String Exposure** — connection pooling
- [ ] **Cloud Metadata Service** — GCP, Azure, AWS variants
- [ ] **Serverless Function Exposure** — cold-start exploitation
- [ ] **Container Registry Escape** — image layer extraction
- [ ] **Cloud IAM Bypass** — service account abuse

#### Social/Reporting (8+ new handlers)
- [ ] **Information Disclosure** — version detection
- [ ] **Sensitive Data Exposure** — in error pages, comments
- [ ] **Insecure Direct Object References** — file access
- [ ] **Insufficient Logging** — audit trail gaps
- [ ] **Security Misconfiguration** — default settings
- [ ] **Dependency Vulnerability** — vulnerable libraries
- [ ] **Known Vulnerable Component** — version detection
- [ ] **Missing Security Headers** — CSP, HSTS, X-Frame

---

## Phase 5: Advanced Orchestration

### White-Box Analysis (New Module: `mod_whitebox.py`)
- Parse source code for:
  - Data flow analysis (sources → sinks)
  - Dangerous APIs (eval, exec, unserialize)
  - Authentication/authorization logic gaps
  - Cryptographic implementation flaws
  - SQL query construction patterns
- Generate technique recommendations based on findings
- Score code patterns by exploitability

### ML-Based Prioritization (New Module: `mod_ml_prioritizer.py`)
- Learn from:
  - Technique success rates
  - Target patterns
  - Historical findings
  - CVSS/EPSS scores
- Predict best exploitation sequence
- Adapt strategy per target type

### Integrated Exploitation Chains (Expand `mod_master_orchestrator.py`)
- Auto-discover multi-step paths:
  - Unauthenticated XSS → Session Hijacking → Admin
  - SQLi → File Read → Source Code Disclosure → RCE
  - SSRF → Cloud Metadata → AWS Credentials → Lateral Movement
- Validate each step before proceeding
- Calculate cumulative impact scores

### Enterprise Features (New Module: `mod_enterprise.py`)
- Multi-engagement orchestration
- Team collaboration (findings comments, status tracking)
- Custom technique library import
- Result aggregation + trending
- Compliance mapping (PCI-DSS, HIPAA, ISO27001)
- Audit logging (all actions, changes, approvals)

---

## Implementation Schedule (Phase 4)

### Week 1: Core Handlers (15 handlers)
- XSS DOM-based, NoSQL, LFI variants
- SQLi UNION, Time-based
- OAuth/OIDC handlers
- Basic cloud checks

### Week 2: Advanced Handlers (15 handlers)
- Deserialization, Race conditions
- Cache poisoning, HTTP smuggling
- DNS rebinding, Subdomain takeover
- Timing attacks, Prototype pollution

### Week 3: Integration & Testing (10 handlers + refinement)
- Complete remaining handlers
- E2E testing of all 100+ techniques
- Performance optimization
- Integration with orchestrator

### Week 4: Advanced Modules
- White-box analyzer module
- ML prioritizer (MVP)
- Exploitation chain builder
- Enterprise features (MVP)

---

## Success Criteria: Market Leadership

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Techniques | 34 | 100+ | In Progress |
| Handlers | 14 | 40+ | In Progress |
| Orchestration Phases | 7 | 10+ | Planned |
| White-box Analysis | ✗ | ✓ | Planned |
| ML Prioritization | ✗ | ✓ | Planned |
| Auto-Chaining | ✗ | ✓ | Planned |
| Performance (<5min/engagement) | ✓ | ✓ | Verified |
| Database Scaling (1000+ findings) | ✓ | ✓ | Tested |
| Multi-target orchestration | ✗ | ✓ | Planned |
| Compliance Mapping | ✗ | ✓ | Planned |

---

## Competitive Advantage

### vs. Shannon (AI White-Box Hacker)
- ✓ Parallel agents (vs. sequential)
- ✓ PoC validation (vs. unvalidated)
- ✓ Attack-surface graph (vs. none)
- ✓ 100+ techniques (vs. limited)

### vs. RedAmon (LangGraph Red-Team)
- ✓ Extensible technique library (YAML)
- ✓ LLM-generated + validated PoCs
- ✓ Advanced white-box analysis (planned)
- ✓ Enterprise features (planned)

### vs. Nuclei/Scanner Tools
- ✓ Autonomous decision-making (vs. template-based)
- ✓ PoC generation (vs. static patterns)
- ✓ Exploitation chains (vs. isolated checks)
- ✓ Attack-surface prioritization (vs. all findings equal)

---

## Known Limitations Being Addressed

| Limitation | Solution | Timeline |
|-----------|----------|----------|
| 34→100+ techniques | Handler expansion (Week 1-3) | Phase 4 |
| No white-box analysis | mod_whitebox.py module | Phase 5 |
| No AI prioritization | ML model + training data | Phase 5 |
| No exploitation chains | mod_chains.py module | Phase 5 |
| No enterprise features | SaaS-ready module | Phase 6 |

---

## Next: Start Phase 4 Week 1

**Immediate priorities:**
1. ✅ Complete E2E testing (done)
2. ✅ Fix critical bugs (done)
3. 📋 Build 15 new handlers (DOM-XSS, NoSQL, UNION-SQLi, OAuth)
4. 📋 Add 40 new techniques to YAML
5. 📋 Integrate with orchestrator
6. 📋 Comprehensive testing

**Target: 50+ techniques by end of Week 1**

---

**Philosophy**: HAKUZA becomes the best by:
- **Breadth**: 100+ techniques (vs. 34)
- **Depth**: Multi-step chains (vs. isolated checks)
- **Intelligence**: ML prioritization (vs. sequential)
- **Validation**: Generated + tested PoCs (vs. templates)
- **Enterprise**: Scale + compliance (vs. single-user)

**ETA**: Full market-leader status by end of Phase 5 (2-3 weeks)
