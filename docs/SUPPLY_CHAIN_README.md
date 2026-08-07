# HAKUZA Supply Chain Vulnerability Module

## Overview

The supply chain vulnerability module (`mod_supply_chain.py`) detects and analyzes supply chain vulnerabilities in application dependencies across multiple package managers. It identifies known exploits, typosquatting attacks, maintenance risks, and build/install-time attack vectors.

**Impact**: A single compromised dependency can compromise millions of downstream users. This module helps detect and prevent supply chain attacks.

---

## Features

### 1. Multi-Ecosystem Support
- **npm** (Node.js) - package.json parsing
- **pip** (Python) - requirements.txt parsing
- **Maven** (Java) - pom.xml parsing
- **Bundler** (Ruby) - Gemfile parsing
- Auto-detection of package managers in target directory

### 2. Vulnerability Detection

#### Known Exploits Database
Detects vulnerabilities in the supplied exploit database:
- **SolarWinds Orion** (CVE-2020-14687) - Supply chain backdoor
- **event-stream** (CVE-2018-16341) - CoinMiner injection
- **ua-parser-js** (CVE-2021-27514) - Account takeover
- **colors.js** (CVE-2021-23567) - Maintenance rage-quit
- **lodash** (CVE-2021-23337) - ReDoS vulnerability
- **log4j** (CVE-2021-44228) - JNDI injection RCE
- **django**, **urllib3**, **codecov** and more

#### Typosquatting Detection
Identifies packages with names similar to popular libraries:
```
lodash → load-ash, lo-dash, lodahs
express → expresss, expreess
react → reavt, reacct
```

#### Maintenance Risk Assessment
Flags abandoned or slowly-maintained packages:
- No updates for 2+ years
- Low community engagement
- Unmaintained dependencies

#### Dependency Confusion Detection
Identifies packages that appear to be internal but may be confused:
- Packages with "internal", "private", "corp" in name
- Risk of public registry taking priority over private

#### Version Constraint Analysis
Detects risky version specifications:
- Loose constraints (`*`, `latest`, `any`)
- Pre-release versions in production (`-alpha`, `-beta`, `-rc`)

### 3. Supply Chain Attack Chains

The module builds and documents attack chains:

#### Install-Time RCE
```
Attacker registers/hijacks package → adds postinstall script →
Developer runs npm install → Script executes with full privileges →
Backdoor/malware installed on developer machine
```

#### Build-Time Injection
```
Compromise build tool (webpack, babel) → Tool modifies compiled output →
Developers ship backdoored binaries → All users affected
```

#### Runtime Exploitation
```
Application imports vulnerable dependency → User input triggers vuln →
RCE/data disclosure/privilege escalation on production system
```

### 4. Output Formats

#### Markdown Report
Human-readable report with severity breakdown, detailed findings, and remediation steps.

#### JSON Report
Machine-readable JSON with all findings, dependencies, and metadata.

#### SARIF (Static Analysis Results Format)
Integration with security tools (GitHub Code Scanning, Azure DevOps, etc.)

---

## Installation

The module is included in HAKUZA v2.0+. No additional installation required.

```bash
cd /home/hakuza/projects/hakuza
python3 mod_supply_chain.py --help
```

---

## Usage

### Via hakuza CLI

```bash
# Scan current directory, output markdown
hakuza supply-chain --scan .

# Scan specific directory, save as JSON
hakuza supply-chain --scan ~/my-project --format json --output findings.json

# Generate SARIF for CI/CD integration
hakuza supply-chain --scan . --format sarif --output findings.sarif
```

### Standalone

```bash
cd /home/hakuza/projects/hakuza

# Scan and print to console
python3 mod_supply_chain.py --scan .

# Save markdown report
python3 mod_supply_chain.py --scan . --format markdown --output report.md

# Save JSON for programmatic access
python3 mod_supply_chain.py --scan . --format json --output findings.json

# SARIF for tool integration
python3 mod_supply_chain.py --scan . --format sarif --output findings.sarif
```

---

## Output Example

### Console Output
```
[*] HAKUZA Supply Chain Vulnerability Scanner
======================================================================
[*] Scanning: /home/user/project

[+] Found 42 dependencies
[+] Found 5 supply chain vulnerabilities

[CRITICAL] SCN_0001: lodash
    Type: known_supply_chain_exploit
    Description: template() function vulnerable to ReDoS
    CVEs: CVE-2021-23337
    Impact: Denial of service on application
    Remediation: Update to version 4.17.21+

[HIGH] SCN_0002: event-stream
    Type: known_supply_chain_exploit
    Description: Package hijacked via account takeover
    Impact: RCE on 2M+ developer machines
    ...
```

### Markdown Report

See `report.md` for complete example with:
- Summary statistics
- Severity breakdown (critical, high, medium, low)
- Detailed findings with indicators
- Dependency inventory with risk counts

### JSON Report

```json
{
  "scan_time": "2026-07-31T00:41:38.932601",
  "path": "/home/user/project",
  "dependencies_count": 42,
  "findings_count": 5,
  "dependencies": [
    {
      "name": "lodash",
      "requested_version": "4.17.10",
      "resolved_version": "4.17.10",
      "package_manager": "npm",
      "is_dev_dependency": false,
      "typosquatting_risk": 0.0,
      "maintenance_risk": 0.0
    }
  ],
  "findings": [
    {
      "id": "SCN_0001",
      "severity": "critical",
      "vuln_type": "known_supply_chain_exploit",
      "package": "lodash",
      "affected_versions": "4.17.10",
      "description": "template() function vulnerable to ReDoS",
      "impact": "Denial of service on application",
      "cves": ["CVE-2021-23337"],
      "exploit_available": false,
      "indicators": [
        "High CPU usage when processing untrusted templates",
        "Hanging/timeout on template rendering"
      ]
    }
  ]
}
```

---

## Real-World Test

### Setup Test Project
```bash
mkdir test_project && cd test_project
cat > package.json << 'EOF'
{
  "dependencies": {
    "lodash": "4.17.10",        # Vulnerable to ReDoS
    "event-stream": "3.3.6",    # Supply chain hijacking
    "ua-parser-js": "0.7.28"    # Account takeover
  }
}
EOF
```

### Run Scan
```bash
hakuza supply-chain --scan . --format markdown --output report.md
```

### View Results
```bash
cat report.md
```

Expected findings:
- 3 CRITICAL: Known supply chain exploits
- 2 HIGH: Typosquatting risks
- 1 MEDIUM: Maintenance risks

---

## Integration with CI/CD

### GitHub Actions
```yaml
name: Supply Chain Check
on: [push, pull_request]

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: python-actions/python@v2
      
      - name: Run Supply Chain Scan
        run: |
          python3 mod_supply_chain.py --scan . \
            --format sarif \
            --output findings.sarif
      
      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: findings.sarif
```

### GitLab CI
```yaml
supply-chain:
  stage: test
  script:
    - python3 mod_supply_chain.py --scan . --format json --output findings.json
  artifacts:
    reports:
      sast: findings.json
```

### Jenkins
```groovy
stage('Supply Chain Analysis') {
    steps {
        sh '''
            python3 mod_supply_chain.py --scan . \\
                --format sarif \\
                --output findings.sarif
        '''
        publishHTML([
            reportDir: '.',
            reportFiles: 'findings.sarif',
            reportName: 'Supply Chain Report'
        ])
    }
}
```

---

## Attack Patterns & Indicators

### Pattern: Install-Time RCE

**Detection**:
```bash
# Check for postinstall scripts
cat package.json | grep -i postinstall

# Monitor during install
npm install --loglevel verbose 2>&1 | tee install.log
grep -E "spawn|child_process|exec" install.log
```

**Indicators**:
- Unexpected network activity during install
- High CPU/disk activity
- Scripts downloading external files
- Modified system files after install

### Pattern: Build-Time Injection

**Detection**:
```bash
# Verify build artifact hashes
shasum -a 256 dist/app.js > dist.sha256
# Compare against source build

# Inspect bundled code
objdump -s app.whl | grep -i payload
```

**Indicators**:
- Build artifacts differ from expected
- Hash mismatches
- Unexpected strings in compiled output
- Larger file sizes than expected

### Pattern: Typosquatting

**Detection**:
```bash
# Check for misspellings in package.json
npm ls

# Search npm registry for similar names
npm search loadash   # Returns "lodash" (correct)
npm search expres    # Returns "express" (correct)
```

**Indicators**:
- Package name differs from intended (typo)
- Recent package creation
- Few downloads/stars
- Unexpected dependencies in malicious package

---

## Database Extensibility

### Adding New Known Exploits

Edit `mod_supply_chain.py` and add to `KNOWN_EXPLOITS`:

```python
KNOWN_EXPLOITS = {
    # ... existing entries ...
    
    "my-vulnerable-package": {
        "vuln_type": "Supply Chain Hijacking",
        "affected_versions": ["1.0.0", "1.0.1"],
        "cve": ["CVE-2024-XXXXX"],
        "description": "Describes the vulnerability",
        "impact": "What happens when exploited",
        "indicators": [
            "Indicator 1",
            "Indicator 2",
        ],
        "payload_type": "Type of malicious code",
        "detection_method": "How to detect it",
        "real_world": True,
    },
}
```

### Adding Typosquatting Patterns

Edit `TYPOSQUATTING_WATCH_LIST`:

```python
TYPOSQUATTING_WATCH_LIST = {
    # ... existing entries ...
    "my-package": [
        "my-pakage",     # Missing 'c'
        "my-packge",     # Missing 'a'
        "mypackage",     # No hyphen
    ],
}
```

---

## Limitations & Future Work

### Current Limitations
1. **Version matching**: Simplified version comparison (doesn't handle all semver patterns)
2. **API lookups**: Maintenance risk assessment requires real API calls (currently mocked)
3. **Transitive dependencies**: Doesn't yet traverse full dependency tree
4. **License compliance**: No license checking integrated yet

### Future Enhancements
1. **SBOM generation**: CycloneDX and SPDX format output
2. **Continuous monitoring**: Watch for new vulnerabilities in pinned dependencies
3. **Remediation automation**: Auto-generate patch PRs for vulnerable deps
4. **Supply chain attestation**: Verify package signatures and provenance
5. **Private registry integration**: Support Artifactory, Nexus, etc.
6. **Machine learning**: Anomaly detection for suspicious packages

---

## Troubleshooting

### Issue: "Error parsing package.json"
**Solution**: Ensure file is valid JSON
```bash
python3 -m json.tool package.json
```

### Issue: No findings detected
**Solution**: Module only detects known exploits in database. Check:
```bash
python3 -c "from mod_supply_chain import KNOWN_EXPLOITS; print(list(KNOWN_EXPLOITS.keys()))"
```

### Issue: "Unexpected network activity" warning during scan
**Solution**: Maintenance risk assessment may query npm registry. Disable with:
```python
# Edit mod_supply_chain.py, comment out requests calls in assess_maintenance_risk()
```

---

## References

### Case Studies (See `/docs/SUPPLY_CHAIN_CASE_STUDIES.md`)
- SolarWinds Orion - Supply chain backdoor
- event-stream - CoinMiner injection
- lodash - ReDoS vulnerability
- ua-parser-js - Account takeover

### External Resources
- [OWASP: Dependency Checking](https://owasp.org/www-community/attacks/dependency_confusion)
- [NIST: Software Supply Chain](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5)
- [Snyk: Supply Chain Report](https://snyk.io/blog/supply-chain-report-2021/)
- [GitHub: Advisory Database](https://github.com/advisories)

---

## License

Part of HAKUZA v2.0+ - See main LICENSE file

## Author

Divith D Shetty | CEH · CRTP · CAISP

---

## Support

For issues or feature requests:
1. Check `/docs/SUPPLY_CHAIN_CASE_STUDIES.md` for detailed examples
2. Run test suite: `python3 -m pytest test_supply_chain.py -v`
3. Enable debug logging: `python3 -u mod_supply_chain.py --scan . 2>&1 | tee debug.log`
