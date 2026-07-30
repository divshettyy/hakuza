# Attack-Surface Graph Integration Guide

## Overview

The attack-surface graph (`mod_attack_graph.py`) builds a queryable topology of discovered hosts, services, vulnerabilities, and potential attack paths. It is **SQLite-first** with Neo4j as an optional future migration target.

## Current Status

### Implemented
- ✅ SQLite schema (6 core tables + indices)
- ✅ CRUD functions for all entities (hosts, services, vulnerabilities, credentials, shares, attack paths)
- ✅ Query patterns: `get_attack_surface()`, `find_rce_paths()`, `find_lateral_movement_paths()`
- ✅ ASCII visualization: `render_attack_surface_ascii()`
- ✅ CLI command: `hakuza attack-surface [--format ascii|json] [--rce-paths] [--lateral] [--max-targets N] [--save FILE]`
- ✅ Schema initialization in `hakuza.py:init_db()`

### To-Do: Integration Hooks

The graph is **ready to use**, but needs to be populated by existing modules. Hook points are marked below with implementation details.

---

## Integration Points

### 1. **mod_recon_plus.py** — Service Discovery

When recon discovers a new service (via nmap, HTTP probing, etc.), populate the graph.

**Current Hook Location:** `mod_recon_plus.cmd_recon()` or `mod_recon_plus.cmd_wayback()`

**Integration Code:**
```python
# After discovering a service, call:
import mod_attack_graph

mod_attack_graph.on_service_discovered(
    engagement_id=eng['id'],
    ip=discovered_ip,
    hostname=discovered_hostname,
    port=discovered_port,
    protocol='tcp',  # or 'udp'
    service_name=service_name,  # e.g. 'Apache', 'OpenSSH'
    version=version,  # e.g. '2.4.41'
    discovered_via='nmap'  # or 'recon', 'banner_grab', etc.
)
```

**Example Locations to Add This:**
- `mod_recon_plus.py:cmd_recon()` — after running nmap/masscan
- `mod_recon_plus.py` — in any service-discovery helper function
- `mod_active.py` — after banner grabbing a service

---

### 2. **mod_active.py** — Vulnerability Discovery

When `mod_active` finds a vulnerability, enrich the graph with the finding link.

**Current Hook Location:** `mod_active._persist()` (where findings are created)

**Integration Code:**
```python
# After add_finding() creates a new finding, call:
import mod_attack_graph

finding = add_finding(eng_id, title=..., severity=..., url=..., ...)

# Extract host/port from the finding's URL
from urllib.parse import urlparse
parsed = urlparse(finding.get('url', ''))
hostname = parsed.netloc.split(':')[0]

# Ensure host is in graph
host = mod_attack_graph.add_host(
    engagement_id=eng_id,
    hostname=hostname,
    discovered_via_tool='active'
)

# Add vulnerability to graph
mod_attack_graph.add_vulnerability(
    host_id=host['id'],
    finding_id=finding['id'],
    cve_id=finding.get('cve_id'),
    severity=finding.get('severity'),
    technique_id=finding.get('technique_id'),  # 'sqli', 'xss', 'rce', etc.
    cvss_score=finding.get('cvss_score'),
    exploitability='attempted'
)
```

**Why This Matters:**
- Links findings to their topology context (which host, which service)
- Enables risk prioritization: "critical SQLi on a confirmed service" vs "low-severity info on uncertain host"
- Powers the orchestrator to decide: attack this host next, or defer to higher-confidence targets

---

### 3. **hakuza.py** — Manual Finding Entry

When a user adds findings manually via `hakuza add`, also update the graph.

**Current Hook Location:** `hakuza.py:add_finding()`

**Integration Code:**
```python
def add_finding(engagement_id: str, title: str, ...) -> dict:
    """[existing code]"""
    ...
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    finding = _row_to_dict(row)
    
    # NEW: Enrich attack graph
    try:
        import mod_attack_graph
        if finding.get('url'):
            from urllib.parse import urlparse
            parsed = urlparse(finding['url'])
            hostname = parsed.netloc.split(':')[0] if parsed.netloc else None
            if hostname:
                host = mod_attack_graph.add_host(
                    engagement_id, hostname=hostname, discovered_via_tool='manual'
                )
                mod_attack_graph.add_vulnerability(
                    host['id'],
                    finding_id=finding_id,
                    severity=finding.get('severity'),
                    technique_id=finding.get('technique_id'),
                    cvss_score=finding.get('cvss_score'),
                    exploitability='confirmed' if finding.get('status') == 'confirmed' else 'attempted'
                )
    except (ImportError, Exception):
        pass  # Graph enrichment is optional
    
    return finding
```

---

### 4. **Orchestrator (mod_orchestrate.py)** — Attack Prioritization

The orchestrator can query the graph to decide which technique to run next.

**Current Hook Location:** `mod_orchestrate.py` (or future AI-driven orchestrator)

**Example: Query for High-Value Targets**
```python
import mod_attack_graph

# Get ranked targets
surface = mod_attack_graph.get_attack_surface(engagement_id)
for target in surface['prioritized_targets']:
    print(f"Attack {target['host']['ip']}: risk_score={target['risk_score']}")
    # Orchestrator could spawn RCE tests on high-risk hosts first

# Find RCE-enabling vulnerabilities
rce_paths = mod_attack_graph.find_rce_paths(engagement_id, severity_floor='high')
for path in rce_paths:
    print(f"Potential RCE on {path['host']['ip']}:{path['service']['port']}")
    # Prioritize SQLi/SSTI/XXE/RCE techniques on these hosts first
```

**Decision Flow:**
```
Graph shows:
  Host A: 1 critical SQLi (confirmed)
  Host B: 2 high vulns (attempted)
  Host C: 1 medium CORS (not_attempted)

Orchestrator decision:
  1. Run privesc/shell-spawn on Host A (RCE path available)
  2. Re-test Host B's high-severity findings with AI escalation
  3. Test Host C only if time permits
```

---

### 5. **mod_recon_plus.py** — Credential Discovery

When credentials are discovered, link them to the graph.

**Current Hook Location:** `mod_recon_plus.cmd_secrets()` or similar

**Integration Code:**
```python
import mod_attack_graph
import hashlib

# After finding a credential (username/password), hash it
password_hash = hashlib.sha256(password.encode()).hexdigest()

mod_attack_graph.add_credential(
    engagement_id=eng['id'],
    username=username,
    password_hash=password_hash,
    source_tool='secrets',  # where we found it
    host_id=host_id,  # optional: which host this applies to
    service_type='ssh',  # optional: SSH, FTP, SMB, etc.
    confirmed=False
)
```

---

### 6. **Lateral Movement Analysis**

After a foothold is gained, find lateral-movement opportunities.

**Integration Code:**
```python
import mod_attack_graph

# After compromising a host, check for lateral paths
lateral = mod_attack_graph.find_lateral_movement_paths(engagement_id)
for opportunity in lateral:
    if opportunity['type'] == 'share_with_creds':
        print(f"SMB share {opportunity['share']} on {opportunity['host']['ip']}")
        print("  → Credentials available in graph")
        # Next: try to access this share
```

---

## Database Schema Reference

### graph_hosts
- **id**: Integer PK
- **engagement_id**: FK to engagements
- **hostname**: Resolved DNS name
- **ip**: IP address
- **os**: Operating system (if detected)
- **discovered_via_tool**: "nmap", "recon", "banner_grab", "manual", etc.
- **confidence**: 0-100, how sure we are this host exists
- **discovered_at**: ISO timestamp
- **created_at, updated_at**: Audit trail

### graph_services
- **id**: Integer PK
- **host_id**: FK to graph_hosts
- **port**: TCP/UDP port number
- **protocol**: "tcp" or "udp"
- **service_name**: e.g., "OpenSSH 7.4"
- **version**: Version string
- **discovered_via**: "nmap", "banner_grab", "nuclei", etc.
- **fingerprint_confidence**: 0-100

### graph_vulnerabilities
- **id**: Integer PK
- **host_id**: FK to graph_hosts
- **service_id**: FK to graph_services (optional; vuln may span host)
- **finding_id**: FK to findings.id (cross-reference)
- **cve_id**: e.g., "CVE-2021-12345"
- **cwe_id**: e.g., "CWE-89" (SQLi)
- **severity**: "critical", "high", "medium", "low", "info"
- **technique_id**: "sqli", "xss", "rce", "ssti", "xxe", "idor", "cors", etc.
- **cvss_score**: Float 0-10
- **exploitability**: "not_attempted", "attempted", "confirmed", "exploited"

### graph_attack_paths
- **id**: Integer PK
- **engagement_id**: FK to engagements
- **start_host_id**: Host we're attacking from
- **start_service_id**: Service we're exploiting (optional)
- **end_host_id**: Host we're trying to compromise
- **technique_chain**: JSON array of technique IDs, e.g., `["sqli_union_1", "privesc_sudo_2"]`
- **likelihood**: "high", "medium", "low"
- **required_creds**: Boolean
- **assumed_creds**: Comma-separated cred IDs from graph_credentials table

### graph_credentials
- **id**: Integer PK
- **engagement_id**: FK to engagements
- **host_id**: FK to graph_hosts (optional)
- **username**: Username
- **password_hash**: SHA256(password) — never plaintext
- **source_tool**: "secrets", "finding", "capture", "default", etc.
- **service_type**: "ssh", "ftp", "smb", "mysql", etc.
- **confirmed**: Boolean (have we tested these?)

### graph_shares
- **id**: Integer PK
- **host_id**: FK to graph_hosts
- **share_name**: e.g., "C$", "IPC$", "admin"
- **access_level**: "rw", "ro", "unknown"
- **discovered_via**: "nmap", "enum4linux", "smbclient", etc.

---

## Risk Scoring Formula

The orchestrator uses this to prioritize targets:

```
risk_score = Σ(severity_weight + exploitability_weight) × host_confidence × urgency_factor

severity_weight = {critical: 4, high: 3, medium: 2, low: 1, info: 0}
exploitability_weight = {exploited: 3, confirmed: 2, attempted: 1, not_attempted: 0}
host_confidence = 0-1 (how sure we are this host exists)
urgency_factor = (time_since_first_vuln_discovered / 7 days) — up to 2x multiplier
```

Example:
- Host A (IP confirmed): 1 critical SQLi (confirmed) = 4 + 2 = 6 × 1.0 = **6.0**
- Host B (IP uncertain): 1 high RCE (attempted) = 3 + 1 = 4 × 0.7 = **2.8**
- Host C (DNS-only): 2 medium vulns (not_attempted) = 2 × 0.5 = **1.0**

→ Attack Host A first.

---

## Future: Neo4j Migration

When SQLite becomes a bottleneck (large engagements, many queries), migrate to Neo4j:

```cypher
CREATE (h:Host {id, ip, hostname, confidence})
CREATE (s:Service {id, port, protocol})
CREATE (v:Vulnerability {id, cve_id, severity})
CREATE (h)-[:RUNS]->(s)
CREATE (h)-[:HAS_VULN]->(v)
CREATE (s)-[:HAS_VULN]->(v)
```

Neo4j benefits:
- Graph queries: "all hosts 2 hops from this RCE" (lateral movement paths)
- Pattern matching: "find chains where any host has both SQLi and SSTI" (multi-stage attacks)
- Relationship reasoning: "which services access which databases" (lateral impact)

---

## Testing the Graph (Manual)

```bash
# Start an engagement
hakuza init test-graph --client Test --target https://example.com --type web

# Manually add some data (for testing)
python3 << 'EOF'
import mod_attack_graph

# Ensure graph schema is initialized
import hakuza
hakuza.init_db()

# Add a host
host = mod_attack_graph.add_host(
    engagement_id='test-graph',
    ip='192.168.1.100',
    hostname='target.local',
    os='Ubuntu 20.04',
    discovered_via_tool='manual'
)
print(f"Added host: {host}")

# Add a service
service = mod_attack_graph.add_service(
    host_id=host['id'],
    port=3306,
    protocol='tcp',
    service_name='MySQL',
    version='5.7.30',
    discovered_via='nmap'
)
print(f"Added service: {service}")

# Add a vulnerability
vuln = mod_attack_graph.add_vulnerability(
    host_id=host['id'],
    service_id=service['id'],
    cve_id='CVE-2021-22234',
    severity='critical',
    technique_id='sqli',
    cvss_score=9.8,
    exploitability='attempted'
)
print(f"Added vulnerability: {vuln}")

# Query the attack surface
surface = mod_attack_graph.get_attack_surface('test-graph')
print(f"Attack surface: {len(surface['prioritized_targets'])} targets")
for target in surface['prioritized_targets']:
    print(f"  {target['host']['ip']}: risk={target['risk_score']}")
EOF

# View the surface via CLI
hakuza attack-surface --format ascii
hakuza attack-surface --format json --save /tmp/surface.json
```

---

## Summary

The attack-surface graph is **production-ready** but requires integration hooks in:

1. ✅ `mod_attack_graph.py` — complete
2. ✅ `hakuza.py:init_db()` — schema init added
3. ✅ `hakuza.py:cmd_attack_surface()` — CLI added
4. ⏳ `mod_recon_plus.py` — hook calls to `on_service_discovered()` (ready, awaiting integration)
5. ⏳ `mod_active.py` — hook calls to `on_finding_created()` (ready, awaiting integration)
6. ⏳ `mod_orchestrate.py` — use `get_attack_surface()` for prioritization (ready, awaiting integration)

Each integration point is straightforward (~5–10 lines per hook). The graph will automatically enable intelligent attack prioritization once these hooks are wired.
