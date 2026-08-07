# HAKUZA Advanced API Fuzzing Engine — Complete Guide

## Overview

The API Fuzzer module (`mod_api_fuzzer.py`) is an advanced, context-aware API fuzzing engine that provides:

- **1000+ payload variants** from curated payload libraries (XSS, SQLi, SSTI, RCE, XXE, SSRF, IDOR, etc.)
- **Context-aware payload generation** based on parameter type detection
- **Differential response analysis** using baseline comparison (status, length, hash, timing)
- **Automated vulnerability classification** with CWE/CVSS scoring
- **Parallel fuzzing** across multiple endpoints and parameters
- **Swagger/OpenAPI support** for automated endpoint discovery
- **PoC generation** in curl and Python formats
- **Nuclei template integration** for confirmed vulnerabilities

## Key Features

### 1. APIEndpointDiscovery
- Parse Swagger/OpenAPI JSON/YAML specifications
- Manual endpoint definition support
- GraphQL introspection discovery (future)
- Extracts methods, paths, parameters, security requirements

### 2. ParameterFuzzer
- Parallel fuzzing with configurable thread count
- Support for GET, POST, PUT, PATCH, DELETE methods
- Parameter location fuzzing: query, header, body, cookie
- Timeout and retry configuration
- Session-based connection pooling

### 3. PayloadLibraryLoader
- Loads 1000+ pre-curated payloads from `~/tools/payloads/`
- Supports: XSS, SQLi, SSTI, RCE, XXE, SSRF, IDOR, LFI, CORS, JWT, etc.
- Dynamic payload filtering based on vulnerability type
- Comment-aware parsing (ignores `#` lines)

### 4. ContextAwarePayloadGenerator
- Automatic parameter type detection (numeric, email, URL, file, command, template, query)
- Intelligent payload selection based on parameter semantics
- Type-specific payloads (e.g., SQLi for numeric IDs, SSRF for URL params)
- Fallback to generic payloads for unknown types

### 5. ResponseBaseline & ResultDifferencer
- Establishes baseline response characteristics (status, length, hash, timing)
- Statistical analysis (mean, stdev) of response metrics
- Detects anomalies using z-score analysis (2-2.5 sigma thresholds)
- Content similarity scoring using difflib
- Confidence scoring based on anomaly patterns

### 6. VulnerabilityClassifier
- Maps findings to CWE (Common Weakness Enumeration)
- CVSS 3.1 scoring with severity levels
- Confidence-based score adjustment
- Automatic PoC generation (curl + Python)
- Remediation guidance mapping

## Installation

```bash
# Module is already integrated into hakuza.py
cd /home/hakuza/projects/hakuza

# Verify installation
python3 -m pytest test_mod_api_fuzzer.py -v
# Expected: 65 passed
```

## Usage Examples

### Basic API Fuzzing

```bash
# Quick fuzz with Swagger/OpenAPI spec
hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints swagger.json \
  --depth quick \
  --output findings.json

# Medium depth with 20 threads
hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints swagger.json \
  --depth medium \
  --threads 20 \
  --timeout 30

# Full comprehensive fuzz (all payload variants)
hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints swagger.json \
  --depth full \
  --threads 50 \
  --timeout 60 \
  --output findings_report.md
```

### Manual Endpoint Definition

Create `endpoints.json`:

```json
[
  {
    "method": "GET",
    "path": "/api/users",
    "description": "Get users list",
    "parameters": [
      {"name": "id", "in": "query"},
      {"name": "filter", "in": "query"}
    ]
  },
  {
    "method": "POST",
    "path": "/api/users",
    "description": "Create user",
    "parameters": [
      {"name": "Authorization", "in": "header"}
    ]
  }
]
```

Then fuzz:

```bash
hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints endpoints.json \
  --depth full
```

### Output Formats

#### JSON Output

```bash
hakuza api-fuzz \
  --target http://target.com \
  --endpoints api.json \
  --output results.json
```

Sample output:
```json
[
  {
    "finding_id": "F_SQLI_1722477600",
    "vulnerability_type": "sqli",
    "severity": "Critical",
    "cvss_score": 9.8,
    "confidence": 0.95,
    "title": "SQL Injection in GET /api/users",
    "cwe": "CWE-89",
    "endpoint": {
      "method": "GET",
      "path": "/api/users"
    },
    "proof_of_concept_curl": "curl -X GET 'http://target/api/users?id=%27%20OR%20%271%27%3D%271'",
    "proof_of_concept_python": "...",
    "references": [...]
  }
]
```

#### Markdown Report

```bash
hakuza api-fuzz \
  --target http://target.com \
  --endpoints api.json \
  --output report.md
```

## Parameter Type Detection

The fuzzer automatically detects parameter types and applies context-aware payloads:

| Parameter Type | Pattern | Payload Types Applied |
|---|---|---|
| **numeric** | `id`, `uid`, `pid`, `page`, `limit` | SQLi, IDOR |
| **email** | `email`, `from`, `to`, `recipient` | Custom email payloads |
| **url** | `url`, `redirect`, `callback`, `link` | SSRF, Open Redirect |
| **file** | `file`, `path`, `filename`, `upload` | LFI, XXE, Path Traversal |
| **command** | `cmd`, `command`, `exec`, `run` | RCE, Command Injection |
| **template** | `template`, `tpl`, `view`, `format` | SSTI |
| **query** | `q`, `search`, `filter`, `keyword` | All common vulns (limited set) |
| **generic** | Unknown parameter names | Limited payload set |

## Vulnerability Types Supported

| Vulnerability | CWE | CVSS | Detection Method |
|---|---|---|---|
| SQL Injection | CWE-89 | 9.8 | Error messages, time-based, response diff |
| XSS | CWE-79 | 7.1 | Reflection detection, DOM patterns |
| SSTI | CWE-1336 | 8.6 | Template injection patterns |
| RCE | CWE-78 | 9.8 | Command execution indicators |
| XXE | CWE-611 | 8.6 | XML parsing errors |
| SSRF | CWE-918 | 8.6 | Cloud metadata responses |
| IDOR | CWE-639 | 7.5 | Numeric ID traversal |
| LFI | CWE-22 | 7.5 | Path traversal patterns |
| CORS | CWE-862 | 5.7 | Header misconfigurations |
| JWT | CWE-347 | 8.1 | Weak algorithms, signing issues |
| NoSQL Injection | CWE-943 | 8.6 | MongoDB operators |
| Race Condition | CWE-362 | 7.5 | Timing-based detection |
| Mass Assignment | CWE-915 | 6.5 | Hidden parameter detection |

## Advanced Configuration

### Custom Payload Library

To use custom payloads, place files in `~/tools/payloads/`:

```bash
# Create custom payload file
cat > ~/tools/payloads/custom-api.txt << 'EOF'
# Custom API Injection Payloads
api_key=test123&bypass=true
{"admin":true}
{"role":["admin"]}
EOF

# Fuzzer automatically loads on next run
```

### Depth Levels Explained

#### Quick (Default)
- Payloads: 20-30 per parameter
- Vuln types: SQLi, XSS
- Time: ~2-5 minutes for 10 endpoints
- Use case: Initial reconnaissance

#### Medium
- Payloads: 50-100 per parameter
- Vuln types: SQLi, XSS, SSTI, RCE, SSRF, IDOR
- Time: ~10-20 minutes for 10 endpoints
- Use case: Standard penetration test

#### Full
- Payloads: 200-1000 per parameter
- Vuln types: All 18 types
- Time: ~60-180 minutes for 10 endpoints
- Use case: Comprehensive audit, high-value targets

## Response Analysis Algorithm

The fuzzer uses statistical differential analysis:

1. **Baseline Capture**: 3 clean requests to establish baseline
   - Mean response length
   - Standard deviation (response length, timing)
   - Response hash for content identity

2. **Anomaly Detection**: Each fuzzed request analyzed via:
   - **Status Code Check**: Diff from baseline status
   - **Length Check**: Z-score > 2 sigma (5% threshold)
   - **Timing Check**: Z-score > 2.5 sigma (1.2% threshold)
   - **Content Diff**: Similarity < 0.7 (30% difference)

3. **Confidence Scoring**:
   - Multiple anomalies increase confidence
   - Weight: status=20%, length=30%, timing=20%, content=30%
   - Final score: 0.0-1.0 (>0.3 considered potential finding)

## Proof of Concept Generation

### Curl PoC Example

```bash
curl -X GET 'http://target/api/users?id=%27%20OR%20%271%27%3D%271'
# Tests: id parameter for SQL injection
# Status: 200, Length: 5024, Time: 0.45s
```

### Python PoC Example

```python
#!/usr/bin/env python3
import requests

target = "http://target"
endpoint = "/api/users"
param_name = "id"
payload = "' OR '1'='1"

resp = requests.get(
    f"{target}{endpoint}",
    params={param_name: payload}
)

print(f"Status: {resp.status_code}")
print(f"Response: {resp.text[:200]}")
```

## Integration with Other HAKUZA Modules

### Active Module (`hakuza active`)
- Sequential differential testing of single endpoints
- AI confirmation of ambiguous findings
- Custom script execution support

### API Fuzzer (`hakuza api-fuzz`)
- Parallel fuzzing of entire API surface
- Context-aware payload generation
- Batch endpoint processing

### PoC Generator (`hakuza poc-generate`)
- Converts fuzzer findings into standalone PoCs
- Validates against testlab
- Generates reproducible test scripts

### Report Generator (`hakuza report`)
- Aggregates fuzzer findings
- CVSS scoring and prioritization
- Executive summary generation

## Performance Tuning

### For Large APIs

```bash
# Use more threads for faster scanning
hakuza api-fuzz \
  --target http://large-api.com \
  --endpoints swagger.json \
  --depth medium \
  --threads 50 \
  --timeout 30
```

### For Slow Networks

```bash
# Increase timeout, reduce threads
hakuza api-fuzz \
  --target http://slow-api.com \
  --endpoints swagger.json \
  --depth quick \
  --threads 5 \
  --timeout 60
```

### Memory-Efficient Mode

```bash
# Reduce payload variants (loaded in memory)
# Edit PayloadLibraryLoader in mod_api_fuzzer.py:
# Change payloads[:50] to payloads[:20] per type
```

## Common Scenarios

### Scenario 1: Public API with No Docs

```bash
# Manual endpoint list
cat > endpoints.txt << 'EOF'
GET /api/v1/users
GET /api/v1/users/search
POST /api/v1/users
GET /api/v1/products
GET /api/v1/products/{id}
POST /api/v1/orders
EOF

# Convert to JSON and fuzz
# (User script: endpoints.txt to endpoints.json conversion)
hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints endpoints.json \
  --depth full
```

### Scenario 2: GraphQL API

```bash
# Fuzz GraphQL parameters
cat > graphql_endpoints.json << 'EOF'
[
  {
    "method": "POST",
    "path": "/graphql",
    "parameters": [
      {"name": "query", "in": "body"},
      {"name": "variables", "in": "body"}
    ]
  }
]
EOF

hakuza api-fuzz \
  --target http://api.example.com \
  --endpoints graphql_endpoints.json \
  --depth full
```

### Scenario 3: Authentication Required

```bash
# Add Authorization header to all requests
# Currently manual: modify endpoint definitions to include:
# {"name": "Authorization", "in": "header"}
# Then inject via custom script wrapper

# Alternative: Use hakuza active with auth cookie
hakuza active \
  --url http://api.example.com/api/users \
  --method GET \
  --cookie "session_id=authenticated_value"
```

## Troubleshooting

### "No endpoints discovered"
```bash
# Verify Swagger file exists and is valid JSON/YAML
python3 -c "import json; json.load(open('swagger.json'))"
# If error, fix the file first

# Verify endpoints have 'paths' key
python3 -c "import yaml; spec = yaml.safe_load(open('swagger.json')); print(spec.get('paths', {}))"
```

### "All requests timing out"
```bash
# Increase timeout and reduce threads
hakuza api-fuzz \
  --target http://target.com \
  --endpoints api.json \
  --threads 5 \
  --timeout 60
```

### "No findings detected"
```bash
# Try deeper scan to increase payload coverage
hakuza api-fuzz \
  --target http://target.com \
  --endpoints api.json \
  --depth full

# Manually verify one endpoint is vulnerable first:
curl 'http://target.com/api/users?id=1 OR 1=1'
# If vulnerable, the issue might be baseline establishment
```

## Test Coverage

The module includes **65+ unit tests** covering:

- ✓ Payload library loading (7 tests)
- ✓ Endpoint discovery (5 tests)
- ✓ Parameter type detection (8 tests)
- ✓ Context-aware payload generation (3 tests)
- ✓ Response analysis and differencing (5 tests)
- ✓ Vulnerability classification (7 tests)
- ✓ PoC generation (curl/Python) (4 tests)
- ✓ CWE/CVSS mapping (4 tests)
- ✓ Fuzzing results data model (2 tests)
- ✓ API fuzzer orchestration (5 tests)
- ✓ Parameter fuzzer (4 tests)
- ✓ Vulnerability types (2 tests)
- ✓ Data classes (5 tests)
- ✓ End-to-end integration (2 tests)

Run tests:
```bash
cd /home/hakuza/projects/hakuza
python3 -m pytest test_mod_api_fuzzer.py -v
# Expected: 65 passed
```

## Code Statistics

- **Total Lines of Code**: ~1800 LOC
- **Payload Variants**: 1000+
- **Supported Vulnerability Types**: 18
- **Test Cases**: 65+
- **Documentation**: Comprehensive guide + inline comments

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│         APIFuzzerOrchestrator                      │
│  (Master coordinator, finding aggregation)          │
└────────────────┬────────────────────────────────────┘
                 │
    ┌────────────┼────────────┬──────────┐
    ▼            ▼            ▼          ▼
┌────────────┐ ┌────────────┐ ┌───────────────────┐
│APIEndpoint │ │Payload     │ │ResponseBaseline   │
│Discovery   │ │LibraryLoader│ │& Differencer      │
│(Swagger)   │ │(1000+ items)│ │(Statistical)      │
└────────────┘ └────────────┘ └───────────────────┘
    ▲                             ▲
    │                             │
    └─────────┬──────────┬────────┘
              │          │
         ┌────▼──────┐   │
         │Parameter  │   │
         │Fuzzer     ◄───┘
         │(Parallel) │
         └────┬──────┘
              │
         ┌────▼──────────────────┐
         │FuzzingResult[]         │
         │(Anomalies detected)    │
         └────┬──────────────────┘
              │
         ┌────▼──────────────────────┐
         │VulnerabilityClassifier    │
         │(CWE/CVSS mapping)         │
         └────┬──────────────────────┘
              │
         ┌────▼──────────────────────┐
         │VulnerabilityFinding[]      │
         │(With curl + Python PoCs)   │
         └────────────────────────────┘
```

## Future Enhancements

1. **GraphQL Introspection**: Automatic GraphQL query discovery
2. **WSDL Support**: SOAP API endpoint parsing
3. **Machine Learning**: Anomaly detection using trained model
4. **Nuclei Export**: Auto-generate Nuclei templates from findings
5. **Rate Limiting Detection**: Smart request throttling
6. **Cookie Jar Management**: Session maintenance across fuzzing
7. **Proxy Support**: Burp/OWASP ZAP integration
8. **OAuth 2.0**: Automatic token refresh during fuzzing

## References

- OWASP API Top 10 2023: https://owasp.org/www-project-api-security/
- HackerOne API Security Reports: https://hackerone.com
- Swagger/OpenAPI Spec: https://spec.openapis.org/
- CWE Categories: https://cwe.mitre.org/
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1

## Support

For issues or questions:
```bash
# Enable debug mode
hakuza api-fuzz --target ... --endpoints ... 2>&1 | tee debug.log

# Run test suite to verify installation
python3 -m pytest test_mod_api_fuzzer.py -v

# Check logs
grep -i "error\|exception" debug.log
```

---

**Author**: Divith D Shetty | CEH · CRTP · CAISP  
**Module Version**: 1.0.0  
**Last Updated**: 2026-07-31
