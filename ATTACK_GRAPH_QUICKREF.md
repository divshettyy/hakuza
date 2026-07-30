# Attack-Surface Graph — Quick Reference

## Files

| File | Purpose |
|------|---------|
| `mod_attack_graph.py` | Main module (31 KB) — schema, queries, visualization |
| `docs/ATTACK_GRAPH_DESIGN.md` | Design rationale, use cases, schema reference |
| `docs/ATTACK_GRAPH_INTEGRATION.md` | Integration guide with code snippets |
| `ATTACK_GRAPH_QUICKREF.md` | This file |

## CLI Usage

```bash
# Show ASCII table of prioritized targets
hakuza attack-surface

# Show top 20 targets
hakuza attack-surface --max-targets 20

# Export as JSON for programmatic access
hakuza attack-surface --format json --save /tmp/surface.json

# Show RCE-enabling paths (SQLi, SSTI, XXE, RCE, CmdInj)
hakuza attack-surface --rce-paths

# Show lateral-movement opportunities (shares, creds, SSH)
hakuza attack-surface --lateral

# Complete analysis with all data types
hakuza attack-surface --rce-paths --lateral --format json --save /tmp/full_surface.json
```

## Programmatic Usage

```python
import mod_attack_graph
import hakuza

# Initialize schema (called automatically by hakuza.init_db())
hakuza.init_db()

# Add a host
host = mod_attack_graph.add_host(
    engagement_id='my-engagement',
    hostname='target.local',
    ip='192.168.1.100',
    os='Ubuntu 20.04',
    discovered_via_tool='nmap'
)

# Add a service
service = mod_attack_graph.add_service(
    host_id=host['id'],
    port=3306,
    protocol='tcp',
    service_name='MySQL',
    version='5.7.30',
    discovered_via='nmap'
)

# Add a vulnerability
vuln = mod_attack_graph.add_vulnerability(
    host_id=host['id'],
    service_id=service['id'],
    cve_id='CVE-2021-22234',
    severity='critical',
    technique_id='sqli',
    cvss_score=9.8,
    exploitability='attempted'  # not_attempted → attempted → confirmed → exploited
)

# Get attack surface (prioritized by risk)
surface = mod_attack_graph.get_attack_surface('my-engagement')
for target in surface['prioritized_targets'][:5]:
    print(f"{target['host']['ip']}: risk={target['risk_score']}")

# Find RCE paths
rce_paths = mod_attack_graph.find_rce_paths('my-engagement', severity_floor='high')
for path in rce_paths:
    print(f"RCE opportunity: {path['host']['ip']}:{path['service']['port']}")

# Find lateral-movement opportunities
lateral = mod_attack_graph.find_lateral_movement_paths('my-engagement')
for opp in lateral:
    print(f"Pivot: {opp['host']['ip']} - {opp['type']}")

# Render ASCII table
ascii_table = mod_attack_graph.render_attack_surface_ascii('my-engagement', max_targets=10)
print(ascii_table)
```

## Database Schema (Quick Reference)

### graph_hosts
- Discovered hosts/IPs
- Confidence: 0-100 (how certain the host exists)
- Linked to: services, vulnerabilities, credentials, shares

### graph_services
- Discovered ports/services
- Linked to: hosts, vulnerabilities
- Fingerprint confidence: 0-100

### graph_vulnerabilities
- Linked to findings via finding_id
- Technique: sqli, xss, rce, ssti, xxe, idor, cors, jwt, csrf, etc.
- Exploitability: not_attempted → attempted → confirmed → exploited

### graph_attack_paths
- Multi-step exploitation chains
- technique_chain: JSON array ["sqli_1", "privesc_2", ...]
- Likelihood: high/medium/low

### graph_credentials
- Discovered credentials (password_hash, never plaintext)
- Confirmed: boolean (have we tested these?)

### graph_shares
- SMB/NFS shares
- Access level: rw/ro/unknown

## Risk Scoring

```
risk_score = Σ(severity + exploitability) × host_confidence

severity: critical=4, high=3, medium=2, low=1, info=0
exploitability: exploited=3, confirmed=2, attempted=1, not_attempted=0
host_confidence: 0-100 (e.g., 100=verified IP, 70=DNS-only, 50=hypothesis)
```

**Example**:
- Host A (IP verified, 1 critical SQLi confirmed): (4+2) × 1.0 = **6.0** ← highest priority
- Host B (DNS-only, 2 high attempts): (3+1) × 0.7 = **2.8** ← defer
- Host C (DNS-only, 1 low attempt): (1+1) × 0.5 = **1.0** ← skip for now

## Integration Hooks (Ready to Wire)

### When Recon Discovers a Service
```python
mod_attack_graph.on_service_discovered(
    engagement_id, ip, hostname, port, protocol, service_name, version, discovered_via='nmap'
)
```

### When Active Testing Finds a Vulnerability
```python
mod_attack_graph.on_finding_created(
    engagement_id, finding_id, url, title, severity, technique_id, cvss_score
)
```

## Orchestrator Integration

```python
# Get highest-risk targets for exploitation
surface = get_attack_surface(engagement_id)
for target in surface['prioritized_targets'][:3]:
    spawn_rce_tests(target)  # Focus RCE tests on top 3 hosts

# Find which technique to test next
rce_paths = find_rce_paths(engagement_id, severity_floor='critical')
if rce_paths:
    exploit_rce_first()  # RCE on critical found
else:
    try_other_techniques()  # Fall back to other vulns
```

## Future: Neo4j Migration

When graph queries become slow (large engagements):

```cypher
MATCH (h:Host)-[:RUNS_SERVICE]->(s:Service)-[:HAS_VULN]->(v:Vulnerability)
WHERE v.severity = 'critical'
RETURN h.ip, s.port, v.cve_id, v.technique_id
```

Migration path documented in `docs/ATTACK_GRAPH_INTEGRATION.md`.

## Testing Manually

```bash
# 1. Create engagement
hakuza init test-graph --client Test --target https://example.com --type web

# 2. Add test data
python3 << 'EOF'
import mod_attack_graph
import hakuza
hakuza.init_db()

host = mod_attack_graph.add_host('test-graph', ip='10.0.0.1', hostname='target.local')
service = mod_attack_graph.add_service(host['id'], 3306, service_name='MySQL')
vuln = mod_attack_graph.add_vulnerability(host['id'], service_id=service['id'],
                                          severity='critical', technique_id='sqli')
EOF

# 3. View the surface
hakuza attack-surface
hakuza attack-surface --rce-paths
hakuza attack-surface --format json --save /tmp/test.json
```

## Status

✅ **Production-Ready**
- SQLite schema: ✅ Implemented
- CRUD functions: ✅ Implemented
- Query patterns: ✅ Implemented
- CLI command: ✅ Implemented
- Hakuza integration: ✅ Implemented
- Integration hooks: ✅ Ready (awaiting wiring in mod_recon_plus, mod_active)
- Documentation: ✅ Complete
- Testing: ✅ Verified

## Documentation

- **For Designers**: `docs/ATTACK_GRAPH_DESIGN.md` — Schema rationale, use cases, future migrations
- **For Integrators**: `docs/ATTACK_GRAPH_INTEGRATION.md` — Exact code snippets for hooking into mod_recon_plus, mod_active, orchestrator
- **For Users**: This file — CLI usage, programmatic examples, risk scoring
