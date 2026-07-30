"""
mod_attack_graph.py — HAKUZA Attack Surface Graph (SQLite-first, Neo4j-optional)

Purpose
-------
Build a queryable topology graph that enables:
  1. "What hosts have I discovered?"
  2. "What services run on host X?"
  3. "Which ports are vulnerable?" → prioritize by risk
  4. Find attack paths: discovered_port → vulnerable_service → CVE → compromise_host
  5. Track lateral-movement paths after foothold

Design Philosophy
-----------------
- Start simple (SQLite), migrate to Neo4j later when needed
- Every finding enriches the graph automatically
- Graph enables intelligent prioritization, not just sequential testing
- All queries are read-only; graph is populated by findings/recon, not directly

Schema (SQLite tables)
----------------------
hosts(
  id INTEGER PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  hostname TEXT,
  ip TEXT,
  os TEXT,
  discovered_via_tool TEXT,  -- "nmap", "recon", "manual", etc.
  confidence INTEGER DEFAULT 100,  -- 0-100: how sure we are this host exists
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

services(
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL FOREIGN KEY,
  port INTEGER,
  protocol TEXT,  -- tcp, udp
  service_name TEXT,
  version TEXT,
  discovered_via TEXT,  -- "nmap", "banner grab", "nuclei", etc.
  fingerprint_confidence INTEGER DEFAULT 100,  -- certainty of service ID
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

vulnerabilities(
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL FOREIGN KEY,
  service_id INTEGER FOREIGN KEY,
  finding_id TEXT,  -- cross-reference to hakuza.findings.id
  cve_id TEXT,
  cwe_id TEXT,
  severity TEXT,  -- critical, high, medium, low, info
  technique_id TEXT,  -- mod_active technique: sqli, xss, rce, etc.
  cvss_score REAL,
  exploitability TEXT,  -- "not_attempted", "attempted", "confirmed", "exploited"
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

attack_paths(
  id INTEGER PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  start_host_id INTEGER NOT NULL FOREIGN KEY,
  start_service_id INTEGER FOREIGN KEY,
  end_host_id INTEGER NOT NULL FOREIGN KEY,
  technique_chain TEXT,  -- JSON array of technique IDs: ["rce_1", "privesc_2", ...]
  likelihood TEXT,  -- high, medium, low
  required_creds BOOLEAN DEFAULT 0,  -- whether this path needs credentials
  assumed_creds TEXT,  -- if creds required, which ones (from credentials table)
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

credentials(
  id INTEGER PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  host_id INTEGER FOREIGN KEY,
  username TEXT,
  password_hash TEXT,  -- never store plaintext
  source_tool TEXT,  -- where we got these: "finding", "capture", "default", etc.
  service_type TEXT,  -- ssh, ftp, smb, mysql, etc.
  confirmed BOOLEAN DEFAULT 0,  -- have we successfully used these?
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

shares(
  id INTEGER PRIMARY KEY,
  host_id INTEGER NOT NULL FOREIGN KEY,
  share_name TEXT,
  access_level TEXT,  -- rw, ro, unknown
  discovered_via TEXT,
  discovered_at TEXT,
  created_at TEXT,
  updated_at TEXT
)

Risk scoring: used by orchestrator to prioritize which host/service to attack next
  - (severity + exploitability_signal) * confidence * urgency
  - e.g., "critical CVE on a confirmed service" = attack NOW
  - e.g., "low-severity info on uncertain host" = defer until higher-confidence
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from pathlib import Path


# ---------------------------------------------------------------------------
# Lazy imports — same pattern as mod_active.py and mod_recon_plus.py
# ---------------------------------------------------------------------------

def _hakuza():
    """Lazy import of the hakuza module so this file is importable standalone."""
    import importlib
    return importlib.import_module("hakuza")


def _n(attr):
    """Fetch an attribute from the hakuza module at call-time."""
    return getattr(_hakuza(), attr)


def _get_db():
    """Get the HAKUZA main database connection."""
    return _n("get_db")()


# ---------------------------------------------------------------------------
# Schema initialization (idempotent)
# ---------------------------------------------------------------------------

def init_attack_graph_schema():
    """Create all attack-graph tables if they don't exist. Called by hakuza.py's init_db()."""
    conn = _get_db()
    conn.executescript("""
    -- Main topology tables
    CREATE TABLE IF NOT EXISTS graph_hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id TEXT NOT NULL,
        hostname TEXT,
        ip TEXT,
        os TEXT,
        discovered_via_tool TEXT,
        confidence INTEGER DEFAULT 100,
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(engagement_id, ip, hostname),
        FOREIGN KEY(engagement_id) REFERENCES engagements(id)
    );

    CREATE TABLE IF NOT EXISTS graph_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT DEFAULT 'tcp',
        service_name TEXT,
        version TEXT,
        discovered_via TEXT,
        fingerprint_confidence INTEGER DEFAULT 100,
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(host_id, port, protocol),
        FOREIGN KEY(host_id) REFERENCES graph_hosts(id)
    );

    CREATE TABLE IF NOT EXISTS graph_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        service_id INTEGER,
        finding_id TEXT,
        cve_id TEXT,
        cwe_id TEXT,
        severity TEXT DEFAULT 'low',
        technique_id TEXT,
        cvss_score REAL,
        exploitability TEXT DEFAULT 'not_attempted',
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(host_id) REFERENCES graph_hosts(id),
        FOREIGN KEY(service_id) REFERENCES graph_services(id),
        FOREIGN KEY(finding_id) REFERENCES findings(id)
    );

    CREATE TABLE IF NOT EXISTS graph_attack_paths (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id TEXT NOT NULL,
        start_host_id INTEGER NOT NULL,
        start_service_id INTEGER,
        end_host_id INTEGER NOT NULL,
        technique_chain TEXT,
        likelihood TEXT DEFAULT 'medium',
        required_creds BOOLEAN DEFAULT 0,
        assumed_creds TEXT,
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(engagement_id) REFERENCES engagements(id),
        FOREIGN KEY(start_host_id) REFERENCES graph_hosts(id),
        FOREIGN KEY(start_service_id) REFERENCES graph_services(id),
        FOREIGN KEY(end_host_id) REFERENCES graph_hosts(id)
    );

    CREATE TABLE IF NOT EXISTS graph_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id TEXT NOT NULL,
        host_id INTEGER,
        username TEXT,
        password_hash TEXT,
        source_tool TEXT,
        service_type TEXT,
        confirmed BOOLEAN DEFAULT 0,
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(engagement_id) REFERENCES engagements(id),
        FOREIGN KEY(host_id) REFERENCES graph_hosts(id)
    );

    CREATE TABLE IF NOT EXISTS graph_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        share_name TEXT,
        access_level TEXT DEFAULT 'unknown',
        discovered_via TEXT,
        discovered_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(host_id, share_name),
        FOREIGN KEY(host_id) REFERENCES graph_hosts(id)
    );

    -- Indices for common queries
    CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON graph_hosts(engagement_id);
    CREATE INDEX IF NOT EXISTS idx_hosts_ip ON graph_hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_services_host ON graph_services(host_id);
    CREATE INDEX IF NOT EXISTS idx_services_port ON graph_services(port);
    CREATE INDEX IF NOT EXISTS idx_vulns_host ON graph_vulnerabilities(host_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_service ON graph_vulnerabilities(service_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_severity ON graph_vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vulns_cve ON graph_vulnerabilities(cve_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_exploitability ON graph_vulnerabilities(exploitability);
    CREATE INDEX IF NOT EXISTS idx_paths_engagement ON graph_attack_paths(engagement_id);
    CREATE INDEX IF NOT EXISTS idx_creds_engagement ON graph_credentials(engagement_id);
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Host management
# ---------------------------------------------------------------------------

def add_host(
    engagement_id: str,
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    os: Optional[str] = None,
    discovered_via_tool: str = "manual",
) -> Dict:
    """Add or update a host. Returns the host dict."""
    if not hostname and not ip:
        raise ValueError("At least hostname or ip must be provided")

    conn = _get_db()
    now = datetime.now().isoformat()

    # Check if exists
    existing = conn.execute(
        "SELECT id FROM graph_hosts WHERE engagement_id = ? AND (ip = ? OR hostname = ?)",
        (engagement_id, ip, hostname),
    ).fetchone()

    if existing:
        conn.execute(
            """UPDATE graph_hosts SET os = COALESCE(?, os),
               discovered_via_tool = ?, updated_at = ?
               WHERE id = ?""",
            (os, discovered_via_tool, now, existing['id']),
        )
        conn.commit()
        return get_host_by_id(existing['id'])

    cursor = conn.execute(
        """INSERT INTO graph_hosts
           (engagement_id, hostname, ip, os, discovered_via_tool, discovered_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (engagement_id, hostname, ip, os, discovered_via_tool, now, now, now),
    )
    conn.commit()
    host_id = cursor.lastrowid
    return get_host_by_id(host_id)


def get_host_by_id(host_id: int) -> Dict:
    """Fetch a host by ID."""
    conn = _get_db()
    row = conn.execute("SELECT * FROM graph_hosts WHERE id = ?", (host_id,)).fetchone()
    return dict(row) if row else None


def get_hosts_for_engagement(engagement_id: str) -> List[Dict]:
    """List all hosts for an engagement."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM graph_hosts WHERE engagement_id = ? ORDER BY ip, hostname",
        (engagement_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Service management
# ---------------------------------------------------------------------------

def add_service(
    host_id: int,
    port: int,
    protocol: str = "tcp",
    service_name: Optional[str] = None,
    version: Optional[str] = None,
    discovered_via: str = "manual",
) -> Dict:
    """Add or update a service on a host. Returns the service dict."""
    conn = _get_db()
    now = datetime.now().isoformat()

    # Check if exists
    existing = conn.execute(
        "SELECT id FROM graph_services WHERE host_id = ? AND port = ? AND protocol = ?",
        (host_id, port, protocol),
    ).fetchone()

    if existing:
        conn.execute(
            """UPDATE graph_services SET service_name = COALESCE(?, service_name),
               version = COALESCE(?, version), discovered_via = ?, updated_at = ?
               WHERE id = ?""",
            (service_name, version, discovered_via, now, existing['id']),
        )
        conn.commit()
        return get_service_by_id(existing['id'])

    cursor = conn.execute(
        """INSERT INTO graph_services
           (host_id, port, protocol, service_name, version, discovered_via, discovered_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (host_id, port, protocol, service_name, version, discovered_via, now, now, now),
    )
    conn.commit()
    service_id = cursor.lastrowid
    return get_service_by_id(service_id)


def get_service_by_id(service_id: int) -> Dict:
    """Fetch a service by ID."""
    conn = _get_db()
    row = conn.execute("SELECT * FROM graph_services WHERE id = ?", (service_id,)).fetchone()
    return dict(row) if row else None


def get_services_for_host(host_id: int) -> List[Dict]:
    """List all services for a host."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM graph_services WHERE host_id = ? ORDER BY port",
        (host_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Vulnerability management
# ---------------------------------------------------------------------------

def add_vulnerability(
    host_id: int,
    service_id: Optional[int] = None,
    finding_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    severity: str = "medium",
    technique_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    exploitability: str = "not_attempted",
) -> Dict:
    """Add or link a vulnerability to host/service. Returns the vuln dict."""
    conn = _get_db()
    now = datetime.now().isoformat()

    cursor = conn.execute(
        """INSERT INTO graph_vulnerabilities
           (host_id, service_id, finding_id, cve_id, cwe_id, severity, technique_id,
            cvss_score, exploitability, discovered_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (host_id, service_id, finding_id, cve_id, cwe_id, severity, technique_id,
         cvss_score, exploitability, now, now, now),
    )
    conn.commit()
    vuln_id = cursor.lastrowid
    return get_vulnerability_by_id(vuln_id)


def get_vulnerability_by_id(vuln_id: int) -> Dict:
    """Fetch a vulnerability by ID."""
    conn = _get_db()
    row = conn.execute("SELECT * FROM graph_vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
    return dict(row) if row else None


def get_vulnerabilities_for_host(host_id: int, severity_filter: Optional[str] = None) -> List[Dict]:
    """List vulnerabilities for a host, optionally filtered by severity."""
    conn = _get_db()
    if severity_filter:
        rows = conn.execute(
            """SELECT * FROM graph_vulnerabilities WHERE host_id = ? AND severity = ?
               ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 cvss_score DESC""",
            (host_id, severity_filter.lower()),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM graph_vulnerabilities WHERE host_id = ?
               ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 cvss_score DESC""",
            (host_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def update_vulnerability_exploitability(vuln_id: int, exploitability: str) -> Dict:
    """Update the exploitability status (e.g., 'not_attempted' → 'confirmed')."""
    conn = _get_db()
    now = datetime.now().isoformat()
    conn.execute(
        "UPDATE graph_vulnerabilities SET exploitability = ?, updated_at = ? WHERE id = ?",
        (exploitability, now, vuln_id),
    )
    conn.commit()
    return get_vulnerability_by_id(vuln_id)


# ---------------------------------------------------------------------------
# Credential management
# ---------------------------------------------------------------------------

def add_credential(
    engagement_id: str,
    username: str,
    password_hash: str,
    source_tool: str = "manual",
    host_id: Optional[int] = None,
    service_type: Optional[str] = None,
    confirmed: bool = False,
) -> Dict:
    """Store discovered credentials (hashed). Returns the cred dict."""
    if not password_hash:
        raise ValueError("password_hash must be provided (never store plaintext)")

    conn = _get_db()
    now = datetime.now().isoformat()

    conn.execute(
        """INSERT INTO graph_credentials
           (engagement_id, host_id, username, password_hash, source_tool, service_type,
            confirmed, discovered_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (engagement_id, host_id, username, password_hash, source_tool, service_type,
         confirmed, now, now, now),
    )
    conn.commit()
    cred_id = cursor.lastrowid

    row = conn.execute("SELECT * FROM graph_credentials WHERE id = ?", (cred_id,)).fetchone()
    return dict(row) if row else None


def get_credentials_for_engagement(engagement_id: str) -> List[Dict]:
    """List all discovered credentials for an engagement."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM graph_credentials WHERE engagement_id = ? ORDER BY created_at DESC",
        (engagement_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Share management (SMB, NFS, etc.)
# ---------------------------------------------------------------------------

def add_share(
    host_id: int,
    share_name: str,
    access_level: str = "unknown",
    discovered_via: str = "manual",
) -> Dict:
    """Add a file share on a host. Returns the share dict."""
    conn = _get_db()
    now = datetime.now().isoformat()

    # Check if exists
    existing = conn.execute(
        "SELECT id FROM graph_shares WHERE host_id = ? AND share_name = ?",
        (host_id, share_name),
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE graph_shares SET access_level = ?, discovered_via = ?, updated_at = ? WHERE id = ?",
            (access_level, discovered_via, now, existing['id']),
        )
        conn.commit()
        share_id = existing['id']
    else:
        conn.execute(
            """INSERT INTO graph_shares
               (host_id, share_name, access_level, discovered_via, discovered_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (host_id, share_name, access_level, discovered_via, now, now, now),
        )
        conn.commit()
        share_id = conn.lastrowid

    row = conn.execute("SELECT * FROM graph_shares WHERE id = ?", (share_id,)).fetchone()
    return dict(row) if row else None


def get_shares_for_host(host_id: int) -> List[Dict]:
    """List all shares on a host."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT * FROM graph_shares WHERE host_id = ? ORDER BY share_name",
        (host_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Attack path planning
# ---------------------------------------------------------------------------

def add_attack_path(
    engagement_id: str,
    start_host_id: int,
    end_host_id: int,
    technique_chain: List[str],
    start_service_id: Optional[int] = None,
    likelihood: str = "medium",
    required_creds: bool = False,
    assumed_creds: Optional[str] = None,
) -> Dict:
    """Record a discovered attack path (exploit chain). technique_chain is a list like
    ['rce_sqli_1', 'privesc_sudo_2', 'lateral_ssh_3']. Returns the path dict."""
    conn = _get_db()
    now = datetime.now().isoformat()

    chain_json = json.dumps(technique_chain)

    conn.execute(
        """INSERT INTO graph_attack_paths
           (engagement_id, start_host_id, start_service_id, end_host_id, technique_chain,
            likelihood, required_creds, assumed_creds, discovered_at, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (engagement_id, start_host_id, start_service_id, end_host_id, chain_json,
         likelihood, required_creds, assumed_creds, now, now, now),
    )
    conn.commit()
    path_id = cursor.lastrowid

    row = conn.execute("SELECT * FROM graph_attack_paths WHERE id = ?", (path_id,)).fetchone()
    return dict(row) if row else None


def get_attack_paths_for_engagement(engagement_id: str) -> List[Dict]:
    """List all attack paths for an engagement."""
    conn = _get_db()
    rows = conn.execute(
        """SELECT * FROM graph_attack_paths WHERE engagement_id = ?
           ORDER BY
             CASE likelihood WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
             created_at DESC""",
        (engagement_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Core query patterns: attack surface analysis
# ---------------------------------------------------------------------------

def get_attack_surface(engagement_id: str) -> Dict:
    """Return a complete attack surface view: hosts, services, vulns, prioritized.

    Returns a dict with:
      {
        "hosts": [host dicts],
        "services_by_host": {host_id: [service dicts]},
        "vulnerabilities_by_host": {host_id: [vuln dicts]},
        "prioritized_targets": [
          {
            "host": host dict,
            "service": service dict or None,
            "vulnerabilities": [vuln dicts],
            "risk_score": float,
            "recommendation": string
          },
          ...
        ]
      }
    """
    conn = _get_db()

    # Fetch all hosts
    hosts = get_hosts_for_engagement(engagement_id)

    services_by_host = {}
    vulns_by_host = {}

    for host in hosts:
        host_id = host['id']
        services_by_host[host_id] = get_services_for_host(host_id)
        vulns_by_host[host_id] = get_vulnerabilities_for_host(host_id)

    # Build prioritized targets
    prioritized = []
    for host in hosts:
        host_id = host['id']
        vulns = vulns_by_host.get(host_id, [])
        services = services_by_host.get(host_id, [])

        if not vulns:
            continue  # Skip hosts with no known vulns

        # Aggregate risk: severity, exploitability, confidence
        sev_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        exploit_scores = {"exploited": 3, "confirmed": 2, "attempted": 1, "not_attempted": 0}

        total_risk = 0
        for v in vulns:
            sev_score = sev_scores.get(v.get('severity', 'low'), 1)
            exploit_score = exploit_scores.get(v.get('exploitability', 'not_attempted'), 0)
            host_confidence = host.get('confidence', 100) / 100.0
            risk = (sev_score + exploit_score) * host_confidence
            total_risk += risk

        avg_risk = total_risk / len(vulns)

        # Determine recommendation
        crit_count = len([v for v in vulns if v.get('severity') == 'critical'])
        high_count = len([v for v in vulns if v.get('severity') == 'high'])

        if crit_count > 0:
            rec = f"ATTACK IMMEDIATELY: {crit_count} critical vuln(s)"
        elif high_count > 0:
            rec = f"HIGH PRIORITY: {high_count} high-severity vulns"
        else:
            rec = f"Medium priority: {len(vulns)} vulns discovered"

        prioritized.append({
            "host": host,
            "service": services[0] if services else None,
            "service_count": len(services),
            "vulnerabilities": vulns,
            "vulnerability_count": len(vulns),
            "critical_count": crit_count,
            "high_count": high_count,
            "risk_score": avg_risk,
            "recommendation": rec,
        })

    # Sort by risk score descending
    prioritized.sort(key=lambda x: x['risk_score'], reverse=True)

    return {
        "hosts": hosts,
        "services_by_host": services_by_host,
        "vulnerabilities_by_host": vulns_by_host,
        "prioritized_targets": prioritized,
    }


def find_rce_paths(engagement_id: str, severity_floor: str = "high") -> List[Dict]:
    """Find potential RCE attack chains: look for services with RCE/SQLi/SSTI vulns.

    Returns list of dicts: {host, service, vulnerabilities, confidence}
    """
    conn = _get_db()
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_floor_rank = sev_order.get(severity_floor.lower(), 3)

    rows = conn.execute(
        """SELECT DISTINCT h.id, h.ip, h.hostname, s.id as service_id, s.port, s.service_name,
             COUNT(v.id) as vuln_count
           FROM graph_hosts h
           LEFT JOIN graph_services s ON h.id = s.host_id
           LEFT JOIN graph_vulnerabilities v ON (v.host_id = h.id OR v.service_id = s.id)
           WHERE h.engagement_id = ? AND v.technique_id IN ('sqli', 'rce', 'ssti', 'xxe', 'cmd_injection')
           AND CASE v.severity
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 ELSE 4 END <= ?
           GROUP BY h.id, s.id
           ORDER BY vuln_count DESC, CASE v.severity
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 ELSE 4 END""",
        (engagement_id, sev_floor_rank),
    ).fetchall()

    paths = []
    for row in rows:
        host = get_host_by_id(row['id'])
        service = get_service_by_id(row['service_id']) if row['service_id'] else None
        vulns = conn.execute(
            """SELECT * FROM graph_vulnerabilities
               WHERE (host_id = ? OR service_id = ?)
               AND technique_id IN ('sqli', 'rce', 'ssti', 'xxe', 'cmd_injection')""",
            (row['id'], row['service_id']),
        ).fetchall()

        if vulns:
            paths.append({
                "host": host,
                "service": service,
                "vulnerabilities": [dict(v) for v in vulns],
                "confidence": host.get('confidence', 100),
            })

    return paths


def find_lateral_movement_paths(engagement_id: str) -> List[Dict]:
    """Find lateral-movement opportunities: services that expose creds or enable pivoting.

    Looks for: shares, SSH/RDP exposure, service vulns that leak creds.
    """
    conn = _get_db()

    paths = []

    # Pattern 1: hosts with SMB/NFS shares + creds
    shares_rows = conn.execute(
        """SELECT DISTINCT h.id, h.ip, h.hostname, g.share_name, g.access_level
           FROM graph_shares g
           JOIN graph_hosts h ON g.host_id = h.id
           WHERE h.engagement_id = ?
           ORDER BY h.ip""",
        (engagement_id,),
    ).fetchall()

    for row in shares_rows:
        host = get_host_by_id(row['id'])
        creds = conn.execute(
            "SELECT * FROM graph_credentials WHERE host_id = ? OR engagement_id = ?",
            (row['id'], engagement_id),
        ).fetchall()

        if host and creds:
            paths.append({
                "type": "share_with_creds",
                "host": host,
                "share": row['share_name'],
                "access_level": row['access_level'],
                "credentials_available": len(creds) > 0,
                "confidence": host.get('confidence', 100),
            })

    return paths


# ---------------------------------------------------------------------------
# Integration hooks (called by mod_active, mod_recon_plus, orchestrator)
# ---------------------------------------------------------------------------

def on_service_discovered(engagement_id: str, ip: str, hostname: Optional[str],
                          port: int, protocol: str, service_name: Optional[str],
                          version: Optional[str], discovered_via: str = "recon"):
    """Called by recon module when a new service is discovered. Auto-populates graph."""
    # Ensure host exists
    host = add_host(engagement_id, hostname=hostname, ip=ip, discovered_via_tool=discovered_via)

    # Add service
    add_service(
        host['id'],
        port=port,
        protocol=protocol,
        service_name=service_name,
        version=version,
        discovered_via=discovered_via,
    )


def on_finding_created(engagement_id: str, finding_id: str, url: str, title: str,
                       severity: str, technique_id: str, cvss_score: Optional[float] = None):
    """Called by mod_active when a new finding is created. Auto-enriches graph."""
    # Try to extract IP/hostname from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0] if parsed.netloc else None

    # Ensure host exists (as best guess from URL)
    try:
        host = add_host(engagement_id, hostname=hostname, discovered_via_tool="active")
    except:
        return  # If we can't parse the URL, skip graph enrichment

    # Add vulnerability
    add_vulnerability(
        host['id'],
        finding_id=finding_id,
        severity=severity,
        technique_id=technique_id,
        cvss_score=cvss_score,
        exploitability="attempted",
    )


# ---------------------------------------------------------------------------
# CLI visualization (for `hakuza attack-surface`)
# ---------------------------------------------------------------------------

def render_attack_surface_ascii(engagement_id: str, max_targets: int = 10) -> str:
    """Generate an ASCII table of the attack surface for CLI display."""
    surface = get_attack_surface(engagement_id)

    lines = []
    lines.append("=" * 120)
    lines.append("HAKUZA ATTACK SURFACE ANALYSIS")
    lines.append("=" * 120)
    lines.append("")

    prioritized = surface['prioritized_targets'][:max_targets]

    if not prioritized:
        lines.append("No vulnerable hosts discovered yet.")
        lines.append("")
        return "\n".join(lines)

    # Header
    lines.append(
        f"{'Host':<20} {'IP':<18} {'Port':<8} {'Service':<20} {'Vulns':<6} "
        f"{'Risk':<8} {'Recommendation':<50}"
    )
    lines.append("-" * 120)

    for target in prioritized:
        host = target['host']
        service = target['service']
        risk_score = target['risk_score']
        crit = target['critical_count']
        high = target['high_count']

        host_str = (host.get('hostname') or "N/A")[:20]
        ip_str = (host.get('ip') or "N/A")[:18]
        port_str = str(service['port']) if service else "N/A"
        svc_str = (service['service_name'] or "unknown")[:20] if service else "N/A"
        vuln_str = f"{crit}C/{high}H"
        risk_str = f"{risk_score:.1f}"
        rec_str = target['recommendation'][:45]

        lines.append(
            f"{host_str:<20} {ip_str:<18} {port_str:<8} {svc_str:<20} {vuln_str:<6} "
            f"{risk_str:<8} {rec_str:<50}"
        )

    lines.append("-" * 120)
    lines.append("")

    # Summary
    all_hosts = surface['hosts']
    lines.append(f"Summary: {len(prioritized)} of {len(all_hosts)} hosts with vulns")
    lines.append("")

    return "\n".join(lines)


def cmd_attack_surface(args):
    """Display attack-surface topology and prioritized targets."""
    import sys
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    engagement_name = args.engagement if hasattr(args, 'engagement') and args.engagement else None

    # Get engagement
    try:
        import hakuza
        if not engagement_name:
            engagement_name = hakuza.get_config_value("current_engagement")

        if not engagement_name:
            if console:
                console.print("[red]No engagement selected. Use 'hakuza switch' or --engagement[/red]")
            else:
                print("Error: No engagement selected")
            return

        engagement = hakuza.get_engagement(engagement_name)
        if not engagement:
            if console:
                console.print(f"[red]Engagement not found: {engagement_name}[/red]")
            else:
                print(f"Error: Engagement not found: {engagement_name}")
            return

        # Get attack surface
        surface = query_attack_surface(engagement['id'])

        # Display
        if args.rce_paths:
            output = find_rce_paths(engagement['id'])
            title = "RCE Attack Paths"
        elif args.lateral:
            output = find_lateral_movement_paths(engagement['id'])
            title = "Lateral Movement Paths"
        else:
            output = render_attack_surface_ascii(engagement['id'])
            title = "Attack Surface Topology"

        if console:
            console.print(f"\n[bold cyan]{title}[/bold cyan]\n")
            console.print(output)
        else:
            print(f"\n{title}\n")
            print(output)

    except Exception as e:
        if console:
            console.print(f"[red]Error: {e}[/red]")
        else:
            print(f"Error: {e}")


if __name__ == "__main__":
    # For testing/demo only
    print("Attack graph module loaded. Use via hakuza.py or import directly.")
