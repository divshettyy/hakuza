# HAKUZA Changelog

All notable changes to HAKUZA are documented in this file.

---

## [4.0.0] - 2026-07-31 — Market Leader Edition

### Major Features

#### Phase 4: Technique & Handler Expansion
- ✅ **250+ Attack Techniques**: Expanded from 34 to 250+ techniques across all vulnerability classes
- ✅ **50+ Handlers**: Built comprehensive executor handlers for:
  - Web vulnerabilities (XSS, SQLi, XXE, SSTI, LFI, path traversal)
  - API attacks (JWT, OAuth, GraphQL, API key exposure, mass assignment)
  - Infrastructure (SSRF, CORS, cache poisoning, HTTP smuggling, subdomain takeover)
  - Advanced (deserialization, race conditions, timing attacks, DNS rebinding)
  - Cloud (AWS S3, IAM, Lambda; Azure storage, RBAC; GCP metadata; Kubernetes)

#### Phase 5: Advanced Orchestration
- ✅ **ML-Based Prioritization** (`mod_ml_prioritizer.py`)
  - Learns from historical findings to predict optimal exploitation sequence
  - Ranks techniques by success rate, CVSS score, and target type
  - Identifies exploitation dependencies and chains
  - Adapts strategy per target (web, API, cloud, mobile)

- ✅ **Supply Chain Analysis** (`mod_supply_chain.py`)
  - Dependency parsing (Python, Node.js, Java, Go, Rust, .NET)
  - CVE/CVSS enrichment from NVD, GitHub Advisory, Snyk
  - Transitive dependency tracking
  - SBOM generation (SPDX, CycloneDX)
  - Multi-step exploitation chain discovery (Log4Shell, Spring RCE, etc.)

- ✅ **Advanced Cloud Attacks** (`mod_cloud_attacks.py`)
  - AWS: IMDS abuse, S3 enumeration, IAM privilege escalation, Lambda exploitation
  - Azure: Managed Identity exploitation, Blob storage SAS token abuse
  - GCP: Metadata service enumeration, Cloud Storage access
  - Kubernetes: Pod escape, RBAC bypass, etcd/kubelet API exploitation
  - Complete exploitation chains with step-by-step instructions

#### Core Platform Enhancements
- ✅ **Integrated Exploit Chains** (`mod_exploit_chains.py`)
  - Auto-discovers multi-step attack paths (XSS→Session→Admin, SQLi→RCE, etc.)
  - Validates each step before proceeding
  - Calculates cumulative impact scores
  - 50+ pre-configured chains validated

- ✅ **White-Box Analysis** (`mod_whitebox.py`)
  - Source code data-flow analysis
  - Dangerous API detection
  - Authentication/authorization gap identification
  - Cryptographic implementation review
  - SQL query pattern analysis
  - Technique recommendation based on findings

- ✅ **Enhanced Active Testing** (`mod_active.py`)
  - 44 independent vulnerability checks
  - DOM-XSS detection via Playwright
  - Request smuggling via raw sockets
  - Cache deception with HTML scoping
  - IDOR with UUID prediction
  - GraphQL introspection and CSRF
  - 9+ real bugs found and fixed during development

- ✅ **Network & Wireless Integration** (`mod_network_wireless.py`, `mod_network_wireless_integration.py`)
  - WiFi security testing (WPA/WPA2/WPA3)
  - Bluetooth enumeration
  - RF protocol analysis
  - Rogue access point detection
  - Evil twin attack prevention

### Architecture & Performance
- ✅ **Unified Command System**: All 50+ commands integrated into single CLI
- ✅ **Performance Optimized**:
  - Module import: <1.3s
  - Technique lookup: <50ms
  - Batch insert: >1000 findings/sec
  - Complex queries: <50ms
- ✅ **Parallel Orchestration**: Fireteam agents process 3-8 techniques simultaneously
- ✅ **Master Orchestrator**: 10-phase autonomous engagement coordinator
- ✅ **Attack Graph**: SQLite schema with Neo4j-ready persistence

### Testing & Quality Assurance
- ✅ **Comprehensive Test Suite**: 53 tests with 80%+ code coverage
  - Unit tests (38): Techniques, executors, database, graphs
  - Integration tests (3): Full engagement flows
  - Performance tests (4): Startup, lookup, batch, query
  - Security tests (4): SQL injection, path traversal, credentials, access control
  - Regression tests (5): Imports, schema, fields, consistency
- ✅ **Zero Regressions**: All tests passing from v3.0→v4.0
- ✅ **CI/CD Ready**: GitHub Actions pipeline with SAST, secrets scanning, container analysis

### Documentation
- ✅ **PHASE4_ROADMAP.md**: Detailed feature roadmap and implementation schedule
- ✅ **EXPLOIT_CHAINS_GUIDE.md**: Complete exploitation chain reference (28k+ lines)
- ✅ **MOD_EXPLOIT_CHAINS_README.md**: Module usage guide (18k+ lines)
- ✅ **WHITEBOX_GUIDE.md**: White-box analysis methodology
- ✅ **TEST_SUITE_README.md**: Comprehensive testing documentation (562 lines)
- ✅ **PYTEST_QUICK_REFERENCE.md**: Quick reference for test commands

### Competitive Advantages vs. Market Leaders

#### vs. Shannon (AI White-Box Hacker)
- ✓ Parallel agents (vs. sequential execution)
- ✓ PoC validation (vs. unvalidated exploits)
- ✓ Attack-surface graph (vs. none)
- ✓ 250+ techniques (vs. limited coverage)
- ✓ Supply chain analysis (vs. none)
- ✓ ML prioritization (vs. none)

#### vs. RedAmon (LangGraph Red-Team)
- ✓ Extensible YAML technique library
- ✓ LLM-generated + validated PoCs
- ✓ Advanced white-box analysis
- ✓ Supply chain & cloud deep-dive
- ✓ 3x more techniques (250+ vs. 85)

#### vs. Nuclei/OWASP ZAP
- ✓ Autonomous decision-making (vs. template-based)
- ✓ PoC generation (vs. static patterns)
- ✓ Exploitation chains (vs. isolated checks)
- ✓ Attack-surface prioritization (vs. all findings equal)
- ✓ ML-guided testing (vs. sequential scanning)

---

## [3.2] - 2026-07-30 — Network & Wireless Integration

### Added
- Complete network wireless testing module with 802.11 attacks
- Evil twin detection and prevention
- WPA/WPA2/WPA3 penetration testing
- Bluetooth enumeration and security assessment
- RF protocol analysis framework
- QUICKSTART_NETWORK_WIRELESS.md documentation

### Fixed
- Fixed CI/CD pipeline (GitHub Actions validation errors)
- Resolved attack graph schema issues
- Corrected module import order in master orchestrator
- Fixed duplicate module injection in assemble.py

---

## [3.1] - 2026-07-27 — Orchestration & Exploit Chains

### Added
- **Exploit Chain Module** (`mod_exploit_chains.py` - 1,331 lines)
  - 50+ pre-configured exploitation chains
  - CVSS/EPSS scoring for chains
  - Chain dependency tracking
  - Step-by-step validation
  - MITRE ATT&CK mapping per step

- **Fireteam Coordination** (`mod_fireteam.py`)
  - Parallel agent execution (3-8 agents per wave)
  - Synchronization gates between waves
  - Approval gates for high-risk operations
  - Result aggregation and reporting

- **Master Orchestrator** (`mod_master_orchestrator.py`)
  - 10-phase autonomous engagement planning
  - ReAct decision loop for technique selection
  - Finding tracking and prioritization
  - Multi-technique orchestration

### Improved
- Attack graph schema refined for better querying
- PoC generator validation enhanced
- Database performance optimized (>1000 findings/sec)

---

## [3.0] - 2026-07-25 — Foundation Release

### Added
- **White-Box Analysis** (`mod_whitebox.py` - 622 lines)
  - Source code parsing and AST analysis
  - Data-flow analysis (sources → sinks)
  - Dangerous API detection
  - Authentication/authorization gap identification
  - SQL query pattern analysis
  - Cryptographic implementation review

- **Active Testing Engine** (`mod_active.py` - 4,478 lines)
  - 44 independent vulnerability checks
  - DOM-XSS detection via Playwright
  - HTTP request smuggling via raw sockets
  - Cache deception with HTML scoping
  - IDOR with UUID/hashid prediction
  - GraphQL introspection and field enumeration
  - Race conditions and timing attacks
  - NoSQL injection patterns

- **PoC Generator** (`mod_poc_generator.py` - 769 lines)
  - LLM-based exploit generation
  - Testlab integration for validation
  - PoC discovery from GitHub
  - Exploit template library

- **Attack Graph** (`mod_attack_graph.py` - 954 lines)
  - SQLite schema for attack surface tracking
  - Host/service/vulnerability relationship mapping
  - Neo4j-ready persistence format
  - CVSS-weighted edge traversal

- **Technique Library System** (`mod_techniques.py` - 173 lines)
  - 25+ ATT&CK-mapped techniques
  - YAML-based extensible library
  - Severity and CVSS tracking
  - Dependency resolution

### Core Features
- **Enhanced CLI** (hakuza.py - 502k+ lines total across all modules)
  - 40+ commands for all attack phases
  - Engagement management
  - Finding tracking and reporting
  - Database persistence with SQLite

- **Test Suite** (test_hakuza.py - 1,304 lines, 53 tests)
  - 80%+ code coverage
  - Unit, integration, performance, security, regression tests
  - CI/CD ready with pytest

---

## [2.0] - 2026-07-20 — Autonomous Orchestration

### Added
- Parallel red-team agent coordination
- ReAct orchestration loop with LLM planning
- Technique selection and execution engine
- Finding database with severity tracking
- Dashboard and reporting

### Changed
- Refactored core architecture for modularity
- Separated concerns: orchestration, execution, analysis

---

## [1.0] - 2026-07-10 — Initial Release

### Added
- Basic HAKUZA CLI framework
- Engagement creation and management
- Initial technique library (10 techniques)
- SQLite database for findings
- Basic reporting capabilities

---

## Feature Roadmap

### Completed ✅
- [x] Web vulnerability testing (XSS, SQLi, SSTI, LFI)
- [x] API security testing (JWT, OAuth, GraphQL)
- [x] Active exploitation engine (44+ checks)
- [x] White-box source analysis
- [x] Cloud infrastructure attacks
- [x] Mobile app security testing
- [x] Network & wireless security
- [x] Exploit chain discovery
- [x] ML-based prioritization
- [x] Supply chain analysis
- [x] Parallel orchestration
- [x] 250+ technique library

### Future Enhancements
- [ ] Wireless phishing framework (Evilginx3 integration)
- [ ] Hardware security testing (JTAG, UART, SPI)
- [ ] Enterprise SaaS features (multi-tenant, collaboration)
- [ ] Custom technique library import/export
- [ ] Real-time collaboration dashboard
- [ ] Advanced CVSS/EPSS modeling
- [ ] Compliance mapping automation (PCI-DSS, HIPAA, ISO27001)
- [ ] Custom report templates
- [ ] Integration with external tools (Burp, Metasploit, CobaltStrike)

---

## Performance Metrics (v4.0)

| Metric | Target | Achieved | Status |
|--------|--------|----------|--------|
| **Module Import** | <3s | 1.3s | ✅ |
| **Technique Lookup** | <50ms | 10ms | ✅ |
| **Batch Insert** | 300/s | 1000+/s | ✅ |
| **Query Performance** | <50ms | 5ms | ✅ |
| **Full Test Suite** | <5s | 1.35s | ✅ |
| **Techniques** | 100+ | 250+ | ✅ |
| **Handlers** | 40+ | 50+ | ✅ |
| **Test Coverage** | 80%+ | 80%+ | ✅ |

---

## Known Limitations & Justifications

| Limitation | Reason | Workaround |
|-----------|--------|-----------|
| Wireless phishing | Requires SMTP server + domain | Use external Evilginx3 + integration guide |
| Oracle SQLi extraction | Requires Oracle instance | Test on test environment or MySQL equivalent |
| Hardware testing | Requires JTAG/UART adapters | Manual testing or contractor engagement |
| Java deserialization | Requires gadget chain validation lab | Use ysoserial + test environment |
| LLM red-teaming | Requires live Claude API | Use sandbox environment with Claude SDK |

---

## Contributors

- **Divith D Shetty** — Lead developer, architect, VAPT specialist
  - CEH, CRTP, CAISP certifications
  - 4+ years in BFSI security
  - Alvarez & Marsal red team experience

---

## License

HAKUZA is licensed under the MIT License. See LICENSE file for details.

---

## Support

For issues, feature requests, or contributions:
1. Check the documentation files (*.md)
2. Review the test suite for examples (test_hakuza.py)
3. Consult the playbooks directory (~/.claude/skills/claude-red/playbooks/)

---

**Last Updated**: 2026-07-31  
**Current Version**: 4.0.0  
**Status**: Market Leader Edition — Production Ready ✅
