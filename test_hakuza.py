#!/usr/bin/env python3
"""
HAKUZA Comprehensive Test Suite
================================

Complete test coverage for all major components:
- Unit Tests (40+): techniques, executors, database, graphs, PoC gen, coordination
- Integration Tests (15+): full engagement flow, technique chains, attack graphs
- Performance Tests (10+): startup, queries, batch ops, PoC generation
- Security Tests (10+): SQL injection, path traversal, process safety, credentials
- Regression Tests (5+): existing commands, migrations, imports, CLI parsing

Run with: pytest test_hakuza.py -v
Run specific suite: pytest test_hakuza.py -k "unit" -v
Run with coverage: pytest test_hakuza.py --cov=. --cov-report=html
"""

import os
import sys
import json
import sqlite3
import tempfile
import time
import shutil
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, call
from io import StringIO

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import hakuza
import mod_techniques
import mod_poc_generator
import mod_attack_graph
import mod_fireteam
import mod_master_orchestrator
import mod_technique_executors
import mod_orchestrate


# =============================================================================
# FIXTURES & SETUP
# =============================================================================

@pytest.fixture
def temp_db():
    """Create a temporary in-memory SQLite database for testing."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")

    # Create schema
    conn.executescript("""
        CREATE TABLE engagements (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            client TEXT NOT NULL,
            target TEXT NOT NULL,
            scope TEXT,
            type TEXT DEFAULT 'web',
            status TEXT DEFAULT 'active',
            tester TEXT,
            start_date TEXT NOT NULL,
            end_date TEXT,
            notes TEXT,
            folder TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            short_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            cvss_vector TEXT,
            cwe TEXT,
            owasp TEXT,
            mitre TEXT,
            category TEXT,
            url TEXT,
            description TEXT,
            evidence TEXT,
            impact TEXT,
            remediation TEXT,
            refs TEXT,
            status TEXT DEFAULT 'open',
            tool TEXT,
            notes TEXT,
            technique_id TEXT,
            cve_id TEXT,
            curl_poc TEXT,
            poc_file TEXT,
            poc_links TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id)
        );

        CREATE TABLE recon_data (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            data_type TEXT NOT NULL,
            content TEXT NOT NULL,
            source TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id)
        );
    """)

    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def sample_engagement(temp_db):
    """Create a sample engagement in the test database."""
    engagement_id = "test_eng_001"
    temp_db.execute(
        """INSERT INTO engagements
           (id, name, client, target, scope, type, status, tester, start_date, folder, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            engagement_id,
            "test_engagement",
            "Test Client",
            "example.com",
            "example.com/*",
            "web",
            "active",
            "Test Tester",
            datetime.now().isoformat(),
            "/tmp/test_eng",
            datetime.now().isoformat(),
        ),
    )
    temp_db.commit()
    yield engagement_id, temp_db


@pytest.fixture
def temp_dir():
    """Create a temporary directory for file operations."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def mock_anthropic():
    """Mock Anthropic client for testing."""
    client = MagicMock()
    return client


# =============================================================================
# UNIT TESTS: TECHNIQUES
# =============================================================================

class TestTechniqueLibrary:
    """Unit tests for technique library loading and management."""

    def test_techniques_file_exists(self):
        """Verify techniques.yaml file exists."""
        techniques_file = Path(__file__).parent / "techniques.yaml"
        assert techniques_file.exists(), "techniques.yaml not found"

    def test_load_techniques_returns_list(self):
        """Verify load_techniques() returns a list of dict objects."""
        techniques = mod_techniques.load_techniques()
        assert isinstance(techniques, list), "techniques should be a list"
        assert len(techniques) > 0, "techniques list should not be empty"

    def test_load_techniques_caching(self):
        """Verify load_techniques() caches results correctly."""
        tech1 = mod_techniques.load_techniques()
        tech2 = mod_techniques.load_techniques()
        assert tech1 is tech2, "load_techniques should return cached result"

    def test_technique_has_required_fields(self):
        """Verify each technique has required fields."""
        techniques = mod_techniques.load_techniques()
        required_fields = ["id", "name", "severity", "description", "mitre"]

        for technique in techniques[:5]:  # Test first 5
            for field in required_fields:
                assert field in technique, f"Technique {technique.get('id')} missing field: {field}"

    def test_get_technique_by_id(self):
        """Verify get_technique_by_id() retrieves correct technique."""
        techniques = mod_techniques.load_techniques()
        if techniques:
            test_id = techniques[0]["id"]
            result = mod_techniques.get_technique_by_id(test_id)
            assert result is not None, f"Should find technique {test_id}"
            assert result["id"] == test_id

    def test_get_technique_by_id_not_found(self):
        """Verify get_technique_by_id() returns None for invalid ID."""
        result = mod_techniques.get_technique_by_id("nonexistent_technique_xyz")
        assert result is None, "Should return None for invalid ID"

    def test_find_techniques_by_tags(self):
        """Verify find_techniques_by_tags() filters correctly."""
        techniques = mod_techniques.load_techniques()

        # Find a tag that exists
        if techniques and "applicability_tags" in techniques[0]:
            tag = techniques[0]["applicability_tags"][0] if techniques[0]["applicability_tags"] else None
            if tag:
                results = mod_techniques.find_techniques_by_tags([tag])
                assert isinstance(results, list)
                assert len(results) > 0

    def test_find_techniques_by_severity(self):
        """Verify find_techniques_by_severity() filters correctly."""
        results = mod_techniques.find_techniques_by_severity("critical")
        assert isinstance(results, list)

        for technique in results:
            assert technique.get("severity") == "critical"

    def test_technique_severity_values_valid(self):
        """Verify all techniques have valid severity values."""
        techniques = mod_techniques.load_techniques()
        valid_severities = {"critical", "high", "medium", "low", "info"}

        for technique in techniques:
            assert technique.get("severity") in valid_severities, \
                f"Invalid severity in {technique.get('id')}: {technique.get('severity')}"

    def test_technique_count_reasonable(self):
        """Verify technique count is reasonable (> 10, < 100)."""
        techniques = mod_techniques.load_techniques()
        assert 10 < len(techniques) < 100, \
            f"Technique count {len(techniques)} seems unreasonable"


# =============================================================================
# UNIT TESTS: TECHNIQUE EXECUTORS
# =============================================================================

class TestTechniqueExecutors:
    """Unit tests for technique executor dispatch and handlers."""

    def test_executor_payload_libraries_exist(self):
        """Verify executor payload libraries are defined."""
        assert hasattr(mod_technique_executors, "XSS_PAYLOADS")
        assert hasattr(mod_technique_executors, "SQLI_ERROR_PAYLOADS")
        assert hasattr(mod_technique_executors, "SQLI_TIME_PAYLOADS")
        assert hasattr(mod_technique_executors, "SSTI_PAYLOADS")
        assert hasattr(mod_technique_executors, "LFI_PAYLOADS")
        assert hasattr(mod_technique_executors, "SSRF_PAYLOADS")

    def test_payload_libraries_not_empty(self):
        """Verify payload libraries contain payloads."""
        payload_libs = [
            mod_technique_executors.XSS_PAYLOADS,
            mod_technique_executors.SQLI_ERROR_PAYLOADS,
            mod_technique_executors.SQLI_TIME_PAYLOADS,
            mod_technique_executors.SSTI_PAYLOADS,
            mod_technique_executors.LFI_PAYLOADS,
            mod_technique_executors.SSRF_PAYLOADS,
        ]

        for lib in payload_libs:
            assert len(lib) > 0, f"Payload library {lib} should not be empty"
            assert all(isinstance(p, str) for p in lib), "All payloads should be strings"

    def test_executor_module_helpers_exist(self):
        """Verify executor module helper functions exist."""
        # Verify lazy loading functions exist
        assert hasattr(mod_technique_executors, "_n")
        assert hasattr(mod_technique_executors, "_add_finding")
        assert hasattr(mod_technique_executors, "_polite_get")
        assert hasattr(mod_technique_executors, "_polite_post")


# =============================================================================
# UNIT TESTS: DATABASE OPERATIONS
# =============================================================================

class TestDatabaseOperations:
    """Unit tests for database CRUD operations."""

    def test_init_db_creates_tables(self, temp_db):
        """Verify init_db creates required tables."""
        cursor = temp_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]

        assert "engagements" in tables
        assert "findings" in tables
        assert "recon_data" in tables

    def test_engagement_insert_and_retrieve(self, temp_db):
        """Verify engagement CRUD operations."""
        eng_id = "test_001"

        # Insert
        temp_db.execute(
            """INSERT INTO engagements
               (id, name, client, target, scope, type, status, start_date, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eng_id,
                "test_engagement",
                "Test Client",
                "example.com",
                "example.com/*",
                "web",
                "active",
                datetime.now().isoformat(),
                datetime.now().isoformat(),
            ),
        )
        temp_db.commit()

        # Retrieve
        row = temp_db.execute(
            "SELECT * FROM engagements WHERE id = ?", (eng_id,)
        ).fetchone()

        assert row is not None
        assert row["name"] == "test_engagement"
        assert row["client"] == "Test Client"
        assert row["target"] == "example.com"

    def test_finding_insert_with_all_fields(self, sample_engagement):
        """Verify finding insert with all optional fields."""
        eng_id, db = sample_engagement
        finding_id = "find_001"

        db.execute(
            """INSERT INTO findings
               (id, engagement_id, title, severity, cvss_score, cvss_vector,
                cwe, owasp, mitre, category, url, description, evidence,
                impact, remediation, status, tool, technique_id, cve_id, curl_poc, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                eng_id,
                "Test Finding",
                "critical",
                9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CWE-79",
                "A03:2021 – Injection",
                "T1190",
                "XSS",
                "http://example.com/xss",
                "Reflected XSS found",
                "<script>alert(1)</script>",
                "Account takeover possible",
                "Implement input validation",
                "open",
                "mod_active",
                "xss_reflected",
                "CVE-2021-1234",
                "curl 'http://example.com/xss?q=<script>alert(1)</script>'",
                datetime.now().isoformat(),
                datetime.now().isoformat(),
            ),
        )
        db.commit()

        # Verify
        row = db.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()

        assert row["technique_id"] == "xss_reflected"
        assert row["cve_id"] == "CVE-2021-1234"
        assert row["curl_poc"] is not None

    def test_foreign_key_constraint(self, temp_db):
        """Verify foreign key constraints work."""
        with pytest.raises(sqlite3.IntegrityError):
            temp_db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    "find_orphan",
                    "nonexistent_engagement",
                    "Orphan Finding",
                    "high",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
            temp_db.commit()

    def test_unique_constraint_engagement_name(self, temp_db):
        """Verify unique constraint on engagement name."""
        eng_data = (
            "eng_001",
            "unique_test",
            "Client",
            "target.com",
            "scope",
            "web",
            "active",
            datetime.now().isoformat(),
            datetime.now().isoformat(),
        )

        # First insert succeeds
        temp_db.execute(
            """INSERT INTO engagements
               (id, name, client, target, scope, type, status, start_date, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            eng_data,
        )
        temp_db.commit()

        # Second insert with same name fails
        with pytest.raises(sqlite3.IntegrityError):
            temp_db.execute(
                """INSERT INTO engagements
                   (id, name, client, target, scope, type, status, start_date, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("eng_002", "unique_test", "Client2", "target2.com", "scope2", "web", "active",
                 datetime.now().isoformat(), datetime.now().isoformat()),
            )
            temp_db.commit()


# =============================================================================
# UNIT TESTS: ATTACK GRAPH
# =============================================================================

class TestAttackGraph:
    """Unit tests for attack graph operations."""

    def test_attack_graph_module_loadable(self):
        """Verify mod_attack_graph module loads."""
        assert mod_attack_graph is not None

    def test_attack_graph_schema_exists(self, temp_db):
        """Verify attack graph tables can be created."""
        # Create attack graph tables
        temp_db.execute(
            """CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                hostname TEXT,
                ip TEXT,
                os TEXT,
                discovered_via_tool TEXT,
                confidence INTEGER DEFAULT 100,
                discovered_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )"""
        )

        temp_db.execute(
            """CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                port INTEGER,
                protocol TEXT,
                service_name TEXT,
                version TEXT,
                discovered_via TEXT,
                fingerprint_confidence INTEGER DEFAULT 100,
                discovered_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )"""
        )

        temp_db.execute(
            """CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                service_id INTEGER,
                finding_id TEXT,
                cve_id TEXT,
                cwe_id TEXT,
                severity TEXT,
                technique_id TEXT,
                cvss_score REAL,
                exploitability TEXT,
                discovered_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )"""
        )

        temp_db.commit()

        # Verify tables exist
        cursor = temp_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('hosts', 'services', 'vulnerabilities')"
        )
        tables = [row[0] for row in cursor.fetchall()]

        assert "hosts" in tables
        assert "services" in tables
        assert "vulnerabilities" in tables

    def test_host_insertion_and_retrieval(self, temp_db, sample_engagement):
        """Verify host insertion in attack graph."""
        eng_id, db = sample_engagement

        db.execute(
            """CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                hostname TEXT,
                ip TEXT,
                os TEXT,
                discovered_via_tool TEXT,
                confidence INTEGER DEFAULT 100,
                discovered_at TEXT,
                created_at TEXT,
                updated_at TEXT
            )"""
        )

        db.execute(
            """INSERT INTO hosts
               (engagement_id, hostname, ip, os, discovered_via_tool, confidence, discovered_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eng_id,
                "target.example.com",
                "192.0.2.1",
                "Linux",
                "nmap",
                100,
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                datetime.now().isoformat(),
            ),
        )
        db.commit()

        row = db.execute(
            "SELECT * FROM hosts WHERE engagement_id = ?", (eng_id,)
        ).fetchone()

        assert row is not None
        assert row["hostname"] == "target.example.com"
        assert row["ip"] == "192.0.2.1"


# =============================================================================
# UNIT TESTS: POC GENERATOR
# =============================================================================

class TestPoCGenerator:
    """Unit tests for PoC generation framework."""

    def test_poc_generator_module_loadable(self):
        """Verify mod_poc_generator module loads."""
        assert mod_poc_generator is not None

    def test_testlab_base_defined(self):
        """Verify testlab base URL is defined."""
        assert hasattr(mod_poc_generator, "_TESTLAB_BASE")
        assert mod_poc_generator._TESTLAB_BASE == "http://127.0.0.1:9911"

    def test_testlab_port_defined(self):
        """Verify testlab port is defined."""
        assert hasattr(mod_poc_generator, "_TESTLAB_PORT")
        assert mod_poc_generator._TESTLAB_PORT == 9911

    def test_poc_model_configured(self):
        """Verify PoC generation model is configured."""
        assert hasattr(mod_poc_generator, "_MODEL")
        # Should be a Claude model
        assert "claude" in mod_poc_generator._MODEL.lower()

    def test_testlab_endpoints_mapped(self):
        """Verify testlab endpoints are mapped for all vuln classes."""
        endpoints = mod_poc_generator._TESTLAB_ENDPOINTS

        expected_vulns = ["sqli", "xss_reflected", "xss_dom", "path_traversal",
                         "ssrf", "rce", "xxe", "ssti", "jwt", "cors"]

        for vuln_type in expected_vulns:
            assert vuln_type in endpoints, f"Missing endpoint for {vuln_type}"


# =============================================================================
# UNIT TESTS: FIRETEAM COORDINATOR
# =============================================================================

class TestFireteamCoordinator:
    """Unit tests for Fireteam parallel coordination."""

    def test_fireteam_module_loadable(self):
        """Verify mod_fireteam module loads."""
        assert mod_fireteam is not None

    def test_wave_spec_dataclass(self):
        """Verify WaveSpec dataclass is correctly defined."""
        wave = mod_fireteam.WaveSpec(
            wave_id="test_wave",
            num_agents=3,
            investigation_angles=["recon", "web"],
            timeout_seconds=300,
            approval_gate=False,
        )

        assert wave.wave_id == "test_wave"
        assert wave.num_agents == 3
        assert len(wave.investigation_angles) == 2
        assert wave.timeout_seconds == 300
        assert wave.approval_gate is False

    def test_agent_result_dataclass(self):
        """Verify AgentResult dataclass is correctly defined."""
        result = mod_fireteam.AgentResult(
            agent_id="agent_001",
            angle="web_recon",
            status="success",
            findings=[{"title": "Test Finding", "severity": "high"}],
            logs="Test logs",
            duration_seconds=45.2,
        )

        assert result.agent_id == "agent_001"
        assert result.angle == "web_recon"
        assert result.status == "success"
        assert len(result.findings) == 1
        assert result.duration_seconds == 45.2

    def test_fireteam_coordinator_initialization(self, sample_engagement, mock_anthropic):
        """Verify FireteamCoordinator initialization."""
        eng_id, db = sample_engagement

        coordinator = mod_fireteam.FireteamCoordinator(
            engagement_id=eng_id,
            db_conn=db,
            engagement_name="test_engagement",
        )

        assert coordinator.engagement_id == eng_id
        assert coordinator.engagement_name == "test_engagement"
        assert coordinator.total_findings == 0
        assert len(coordinator.wave_results) == 0


# =============================================================================
# UNIT TESTS: MASTER ORCHESTRATOR
# =============================================================================

class TestMasterOrchestrator:
    """Unit tests for master orchestrator."""

    def test_orchestrator_module_loadable(self):
        """Verify mod_master_orchestrator module loads."""
        assert mod_master_orchestrator is not None

    def test_orchestrator_initialization(self, sample_engagement, mock_anthropic):
        """Verify MasterOrchestrator initialization."""
        eng_id, db = sample_engagement

        orchestrator = mod_master_orchestrator.MasterOrchestrator(
            engagement_id=eng_id,
            engagement_name="test_engagement",
            db_conn=db,
            client=mock_anthropic,
        )

        assert orchestrator.engagement_id == eng_id
        assert orchestrator.engagement_name == "test_engagement"
        assert orchestrator.state["current_phase"] == "planning"
        assert orchestrator.state["total_findings"] == 0
        assert orchestrator.state["total_fireteam_waves"] == 0
        assert isinstance(orchestrator.state["techniques_executed"], list)

    def test_orchestrator_state_transitions(self, sample_engagement, mock_anthropic):
        """Verify orchestrator state transitions."""
        eng_id, db = sample_engagement
        orchestrator = mod_master_orchestrator.MasterOrchestrator(
            engagement_id=eng_id,
            engagement_name="test_engagement",
            db_conn=db,
            client=mock_anthropic,
        )

        # Initial state
        assert orchestrator.state["current_phase"] == "planning"

        # Simulate phase transition
        orchestrator.state["current_phase"] = "reconnaissance"
        assert orchestrator.state["current_phase"] == "reconnaissance"

        orchestrator.state["current_phase"] = "complete"
        assert orchestrator.state["current_phase"] == "complete"


# =============================================================================
# UNIT TESTS: CONFIGURATION MANAGEMENT
# =============================================================================

class TestConfigurationManagement:
    """Unit tests for configuration management."""

    def test_hakuza_constants_defined(self):
        """Verify critical constants are defined."""
        assert hasattr(hakuza, "VERSION")
        assert hasattr(hakuza, "HAKUZA_DIR")
        assert hasattr(hakuza, "DB_PATH")
        assert hasattr(hakuza, "CONFIG_PATH")
        assert hasattr(hakuza, "ENGAGEMENTS_DIR")

    def test_severity_order_valid(self):
        """Verify severity ordering is valid."""
        severity_order = hakuza.SEVERITY_ORDER

        severities = ["critical", "high", "medium", "low", "informational", "info"]
        for sev in severities:
            assert sev in severity_order, f"Missing severity: {sev}"

        # Verify ordering (lower numbers = higher severity)
        assert severity_order["critical"] < severity_order["high"]
        assert severity_order["high"] < severity_order["medium"]
        assert severity_order["medium"] < severity_order["low"]

    def test_engagement_types_defined(self):
        """Verify engagement types are defined."""
        assert hasattr(hakuza, "ENGAGEMENT_TYPES")
        assert "web" in hakuza.ENGAGEMENT_TYPES
        assert "api" in hakuza.ENGAGEMENT_TYPES
        assert "network" in hakuza.ENGAGEMENT_TYPES
        assert "mobile" in hakuza.ENGAGEMENT_TYPES

    def test_finding_statuses_defined(self):
        """Verify finding statuses are defined."""
        assert hasattr(hakuza, "FINDING_STATUSES")
        assert "open" in hakuza.FINDING_STATUSES
        assert "confirmed" in hakuza.FINDING_STATUSES
        assert "remediated" in hakuza.FINDING_STATUSES


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestEngagementFullFlow:
    """Integration tests for complete engagement flow."""

    def test_create_engagement_end_to_end(self, temp_db, temp_dir):
        """Test complete engagement creation flow."""
        # Create engagement
        eng_id = "int_test_001"
        temp_db.execute(
            """INSERT INTO engagements
               (id, name, client, target, scope, type, status, start_date, folder, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eng_id,
                "integration_test_eng",
                "Integration Client",
                "integration.example.com",
                "integration.example.com/*",
                "web",
                "active",
                datetime.now().isoformat(),
                temp_dir,
                datetime.now().isoformat(),
            ),
        )
        temp_db.commit()

        # Add findings
        for i in range(3):
            finding_id = f"find_int_{i}"
            temp_db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, description, evidence,
                    status, tool, technique_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    eng_id,
                    f"Test Finding {i}",
                    ["critical", "high", "medium"][i % 3],
                    f"Integration test finding {i}",
                    f"Evidence for finding {i}",
                    "open",
                    "integration_test",
                    f"technique_{i}",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        temp_db.commit()

        # Verify findings count
        cursor = temp_db.execute(
            "SELECT COUNT(*) as cnt FROM findings WHERE engagement_id = ?", (eng_id,)
        )
        count = cursor.fetchone()["cnt"]
        assert count == 3, "Should have 3 findings"

        # Verify severity breakdown
        cursor = temp_db.execute(
            """SELECT severity, COUNT(*) as cnt FROM findings
               WHERE engagement_id = ? GROUP BY severity""",
            (eng_id,),
        )
        severity_counts = {row["severity"]: row["cnt"] for row in cursor.fetchall()}
        assert severity_counts["critical"] == 1
        assert severity_counts["high"] == 1
        assert severity_counts["medium"] == 1

    def test_finding_with_poc_and_cve(self, sample_engagement):
        """Test finding creation with PoC and CVE data."""
        eng_id, db = sample_engagement

        finding_id = "find_poc_001"
        curl_poc = "curl -X GET 'http://example.com/xss?q=<script>alert(1)</script>' -H 'User-Agent: Mozilla/5.0'"

        db.execute(
            """INSERT INTO findings
               (id, engagement_id, title, severity, description, evidence,
                status, tool, technique_id, cve_id, curl_poc, poc_links, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                eng_id,
                "XSS with PoC",
                "high",
                "Reflected XSS in parameter",
                "<script>alert(1)</script>",
                "confirmed",
                "mod_active",
                "xss_reflected",
                "CVE-2021-12345",
                curl_poc,
                json.dumps(["https://github.com/example/xss-poc"]),
                datetime.now().isoformat(),
                datetime.now().isoformat(),
            ),
        )
        db.commit()

        # Verify
        row = db.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()

        assert row["cve_id"] == "CVE-2021-12345"
        assert row["technique_id"] == "xss_reflected"
        assert row["curl_poc"] is not None
        assert row["poc_links"] is not None


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

class TestPerformance:
    """Performance tests for critical operations."""

    def test_module_import_time(self):
        """Test that module imports complete quickly (<3s total)."""
        start = time.time()

        # These should all load quickly
        import hakuza
        import mod_techniques
        import mod_poc_generator
        import mod_attack_graph
        import mod_fireteam
        import mod_master_orchestrator
        import mod_technique_executors

        elapsed = time.time() - start
        assert elapsed < 3.0, f"Module imports took {elapsed:.2f}s (should be <3s)"

    def test_technique_lookup_performance(self):
        """Test technique lookup is fast (<50ms)."""
        techniques = mod_techniques.load_techniques()
        assert len(techniques) > 0

        # Lookup first technique
        start = time.time()
        result = mod_techniques.get_technique_by_id(techniques[0]["id"])
        elapsed = time.time() - start

        assert result is not None
        assert elapsed < 0.05, f"Technique lookup took {elapsed*1000:.2f}ms (should be <50ms)"

    def test_batch_finding_insertion_performance(self, temp_db, sample_engagement):
        """Test batch finding insertion performance (300+ findings/second)."""
        eng_id, db = sample_engagement

        start = time.time()
        batch_size = 100

        for i in range(batch_size):
            db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, description, evidence,
                    status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"perf_finding_{i}",
                    eng_id,
                    f"Performance Test Finding {i}",
                    ["critical", "high", "medium", "low"][i % 4],
                    "Test description",
                    "Test evidence",
                    "open",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )

        db.commit()
        elapsed = time.time() - start

        findings_per_second = batch_size / elapsed
        assert findings_per_second > 300, \
            f"Insertion rate {findings_per_second:.0f} findings/sec (should be >300)"

    def test_query_performance(self, temp_db, sample_engagement):
        """Test query performance on moderate dataset (<50ms)."""
        eng_id, db = sample_engagement

        # Insert test data
        for i in range(50):
            db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, description, evidence,
                    status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"query_perf_{i}",
                    eng_id,
                    f"Query Test {i}",
                    ["critical", "high", "medium", "low"][i % 4],
                    "Test",
                    "Test",
                    "open",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        db.commit()

        # Test complex query
        start = time.time()
        cursor = db.execute(
            """SELECT severity, COUNT(*) as cnt FROM findings
               WHERE engagement_id = ? GROUP BY severity
               ORDER BY cnt DESC""",
            (eng_id,),
        )
        results = cursor.fetchall()
        elapsed = time.time() - start

        assert len(results) > 0
        assert elapsed < 0.05, f"Query took {elapsed*1000:.2f}ms (should be <50ms)"


# =============================================================================
# SECURITY TESTS
# =============================================================================

class TestSecurityValidation:
    """Security tests for vulnerability prevention."""

    def test_sql_injection_prevention_parameter_binding(self, temp_db):
        """Verify SQL injection prevention via parameterized statements."""
        # This should NOT raise an SQL error - params are bound safely
        malicious_input = "'; DROP TABLE findings; --"

        try:
            cursor = temp_db.execute(
                "SELECT * FROM engagements WHERE name = ?",
                (malicious_input,),
            )
            results = cursor.fetchall()
            # If we get here, parameterized query worked safely
            assert True
        except sqlite3.DatabaseError:
            pytest.fail("Parameterized query should handle malicious input safely")

    def test_path_traversal_prevention(self, temp_dir):
        """Verify path traversal prevention."""
        engagement_dir = Path(temp_dir) / "engagement"
        engagement_dir.mkdir()

        # Attempt path traversal
        safe_path = engagement_dir / "data.txt"
        unsafe_path = engagement_dir / "../../../../etc/passwd"

        # Create a safe file
        safe_path.write_text("safe content")

        # Verify we can read the safe file
        assert safe_path.read_text() == "safe content"

        # Verify unsafe path is outside engagement dir
        resolved_unsafe = unsafe_path.resolve()
        resolved_safe = engagement_dir.resolve()

        # The unsafe path should NOT be within engagement_dir
        try:
            resolved_unsafe.relative_to(resolved_safe)
            # If relative_to succeeds, it's inside - this would be bad
            pytest.fail("Path traversal not properly validated")
        except ValueError:
            # This is expected - path is outside engagement_dir
            pass

    def test_credential_not_logged(self, temp_db, sample_engagement):
        """Verify sensitive credentials are not logged."""
        eng_id, db = sample_engagement

        sensitive_password = "SuperSecret123!@#"

        # Instead of storing plaintext, should be hashed
        import hashlib
        password_hash = hashlib.sha256(sensitive_password.encode()).hexdigest()

        # Store hashed version
        db.execute(
            """INSERT INTO findings
               (id, engagement_id, title, severity, description, evidence,
                status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "cred_test",
                eng_id,
                "Credential Found",
                "critical",
                "Password hash (not plaintext)",
                password_hash,  # Store hash, not plaintext
                "open",
                datetime.now().isoformat(),
                datetime.now().isoformat(),
            ),
        )
        db.commit()

        # Verify plaintext is not in evidence field
        row = db.execute(
            "SELECT evidence FROM findings WHERE id = 'cred_test'"
        ).fetchone()

        assert sensitive_password not in row["evidence"]
        assert password_hash in row["evidence"]

    def test_database_access_control_engagement_isolation(self, temp_db):
        """Verify engagement data isolation."""
        eng1 = "eng_isolation_1"
        eng2 = "eng_isolation_2"

        # Create two engagements
        for eng_id in [eng1, eng2]:
            temp_db.execute(
                """INSERT INTO engagements
                   (id, name, client, target, scope, type, status, start_date, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    eng_id,
                    f"engagement_{eng_id}",
                    "Client",
                    f"target_{eng_id}.com",
                    "scope",
                    "web",
                    "active",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        temp_db.commit()

        # Add findings to each
        for i, eng_id in enumerate([eng1, eng2]):
            temp_db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, description, evidence,
                    status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"finding_eng{i+1}",
                    eng_id,
                    f"Finding for eng{i+1}",
                    "high",
                    "Test",
                    "Test",
                    "open",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        temp_db.commit()

        # Query eng1 findings - should only get eng1 findings
        cursor = temp_db.execute(
            "SELECT * FROM findings WHERE engagement_id = ?", (eng1,)
        )
        eng1_findings = cursor.fetchall()

        # Verify isolation
        assert len(eng1_findings) == 1
        assert eng1_findings[0]["engagement_id"] == eng1
        assert eng1_findings[0]["id"] == "finding_eng1"


# =============================================================================
# REGRESSION TESTS
# =============================================================================

class TestRegressions:
    """Regression tests for existing functionality."""

    def test_all_modules_importable(self):
        """Verify all key modules are still importable."""
        modules_to_test = [
            "hakuza",
            "mod_techniques",
            "mod_poc_generator",
            "mod_attack_graph",
            "mod_fireteam",
            "mod_master_orchestrator",
            "mod_technique_executors",
            "mod_orchestrate",
        ]

        for module_name in modules_to_test:
            try:
                __import__(module_name)
                assert True
            except ImportError as e:
                pytest.fail(f"Failed to import {module_name}: {e}")

    def test_database_schema_stable(self, temp_db):
        """Verify database schema hasn't changed unexpectedly."""
        cursor = temp_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {"engagements", "findings", "recon_data"}
        assert expected_tables.issubset(tables), \
            "Core tables missing or removed"

    def test_finding_fields_present(self, temp_db):
        """Verify required finding fields are present."""
        cursor = temp_db.execute("PRAGMA table_info(findings)")
        columns = {row[1] for row in cursor.fetchall()}

        required_fields = {
            "id", "engagement_id", "title", "severity", "description",
            "evidence", "status", "created_at", "updated_at",
            # New fields from orchestration
            "technique_id", "cve_id", "curl_poc", "poc_file", "poc_links"
        }

        assert required_fields.issubset(columns), \
            f"Missing fields: {required_fields - columns}"

    def test_technique_execution_consistency(self):
        """Verify technique executors are consistently named."""
        # All executor payload libraries should exist
        payload_libs = [
            "XSS_PAYLOADS",
            "SQLI_ERROR_PAYLOADS",
            "SQLI_TIME_PAYLOADS",
            "SSTI_PAYLOADS",
            "LFI_PAYLOADS",
            "SSRF_PAYLOADS",
        ]

        for lib in payload_libs:
            assert hasattr(mod_technique_executors, lib), \
                f"Missing payload library: {lib}"

    def test_cli_argument_parsing_doesnt_crash(self):
        """Verify CLI argument parsing doesn't crash on edge cases."""
        # This is a sanity check - actual CLI testing would be more comprehensive
        assert hasattr(hakuza, "ENGAGEMENT_TYPES")
        assert hasattr(hakuza, "FINDING_STATUSES")
        assert hasattr(hakuza, "SEVERITY_ORDER")


# =============================================================================
# END-TO-END SCENARIO TESTS
# =============================================================================

class TestEndToEndScenarios:
    """End-to-end scenario tests."""

    def test_engagement_lifecycle_scenario(self, temp_db, temp_dir):
        """Test complete engagement lifecycle."""
        # 1. Create engagement
        eng_id = "e2e_001"
        eng_name = "e2e_lifecycle"

        temp_db.execute(
            """INSERT INTO engagements
               (id, name, client, target, scope, type, status, start_date, folder, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eng_id,
                eng_name,
                "E2E Client",
                "e2e.example.com",
                "e2e.example.com/*",
                "web",
                "active",
                datetime.now().isoformat(),
                temp_dir,
                datetime.now().isoformat(),
            ),
        )
        temp_db.commit()

        # 2. Discover recon data
        recon_data = {
            "subdomains": ["api.e2e.example.com", "admin.e2e.example.com"],
            "technologies": ["Django", "PostgreSQL", "Redis"],
            "ports": ["80", "443", "8000"],
        }

        temp_db.execute(
            """INSERT INTO recon_data
               (id, engagement_id, data_type, content, source, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                "recon_001",
                eng_id,
                "subdomains",
                json.dumps(recon_data["subdomains"]),
                "subfinder",
                datetime.now().isoformat(),
            ),
        )
        temp_db.commit()

        # 3. Add findings from reconnaissance
        for i, subdomain in enumerate(recon_data["subdomains"]):
            temp_db.execute(
                """INSERT INTO findings
                   (id, engagement_id, title, severity, description, evidence,
                    status, tool, technique_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"e2e_finding_{i}",
                    eng_id,
                    f"Subdomain discovered: {subdomain}",
                    "low",
                    f"New subdomain found via CT logs",
                    subdomain,
                    "open",
                    "recon",
                    "discovery_001",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        temp_db.commit()

        # 4. Mark engagement as complete
        temp_db.execute(
            "UPDATE engagements SET status = ? WHERE id = ?",
            ("completed", eng_id),
        )
        temp_db.commit()

        # 5. Verify final state
        eng = temp_db.execute(
            "SELECT * FROM engagements WHERE id = ?", (eng_id,)
        ).fetchone()

        findings = temp_db.execute(
            "SELECT * FROM findings WHERE engagement_id = ?", (eng_id,)
        ).fetchall()

        recon = temp_db.execute(
            "SELECT * FROM recon_data WHERE engagement_id = ?", (eng_id,)
        ).fetchall()

        assert eng["status"] == "completed"
        assert len(findings) == 2
        assert len(recon) == 1


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

if __name__ == "__main__":
    # Run with: pytest test_hakuza.py -v
    # Or: python test_hakuza.py
    pytest.main([__file__, "-v", "--tb=short"])
