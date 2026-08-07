#!/usr/bin/env python3
"""
HAKUZA Comprehensive Test Suite - Shared Fixtures & Configuration
===================================================================

Provides shared fixtures, mocks, and utilities for all test suites:
- Database fixtures (SQLite, in-memory)
- Engagement and finding fixtures
- Mocking utilities
- Performance measurement fixtures
- Security testing utilities
- Test data generators
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
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from io import StringIO
import random
import string
import hashlib

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


# =============================================================================
# PYTEST CONFIGURATION HOOKS
# =============================================================================

def pytest_configure(config):
    """Configure pytest with custom plugins and settings."""
    # Register custom markers
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "performance: performance tests")
    config.addinivalue_line("markers", "security: security tests")
    config.addinivalue_line("markers", "stress: stress tests")
    config.addinivalue_line("markers", "chaos: chaos tests")


def pytest_collection_modifyitems(config, items):
    """Modify test items during collection."""
    for item in items:
        # Auto-mark based on test file name
        if "performance" in item.nodeid:
            item.add_marker(pytest.mark.performance)
        elif "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        elif "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        elif "e2e" in item.nodeid:
            item.add_marker(pytest.mark.e2e)
        else:
            item.add_marker(pytest.mark.unit)


# =============================================================================
# DATABASE FIXTURES
# =============================================================================

@pytest.fixture(scope="session")
def db_schema():
    """Provide the complete database schema for all tests."""
    return """
        CREATE TABLE IF NOT EXISTS engagements (
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

        CREATE TABLE IF NOT EXISTS findings (
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

        CREATE TABLE IF NOT EXISTS recon_data (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            data_type TEXT NOT NULL,
            content TEXT NOT NULL,
            source TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id)
        );

        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT,
            mitre_id TEXT,
            tags TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS technique_executions (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            result TEXT,
            evidence TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (engagement_id) REFERENCES engagements(id),
            FOREIGN KEY (technique_id) REFERENCES techniques(id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_recon_engagement ON recon_data(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_techniques_category ON techniques(category);
        CREATE INDEX IF NOT EXISTS idx_executions_engagement ON technique_executions(engagement_id);
    """


@pytest.fixture
def temp_db(db_schema):
    """Create a temporary in-memory SQLite database."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(db_schema)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def file_db(tmp_path, db_schema):
    """Create a temporary file-based SQLite database."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(db_schema)
    conn.commit()
    yield conn, db_path
    conn.close()


# =============================================================================
# ENGAGEMENT & FINDING FIXTURES
# =============================================================================

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
    return engagement_id, temp_db


@pytest.fixture
def multiple_engagements(temp_db):
    """Create multiple test engagements."""
    engagements = []
    for i in range(5):
        eng_id = f"test_eng_{i:03d}"
        temp_db.execute(
            """INSERT INTO engagements
               (id, name, client, target, scope, type, status, tester, start_date, folder, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                eng_id,
                f"engagement_{i}",
                f"Client_{i}",
                f"example{i}.com",
                f"example{i}.com/*",
                "web" if i % 2 == 0 else "api",
                "active" if i < 3 else "completed",
                f"Tester_{i}",
                (datetime.now() - timedelta(days=i*7)).isoformat(),
                f"/tmp/test_eng_{i}",
                datetime.now().isoformat(),
            ),
        )
        engagements.append(eng_id)
    temp_db.commit()
    return engagements, temp_db


@pytest.fixture
def sample_finding(sample_engagement):
    """Create a sample finding."""
    engagement_id, db = sample_engagement
    finding_id = "find_001"
    db.execute(
        """INSERT INTO findings
           (id, engagement_id, title, severity, cvss_score, cvss_vector, cwe, owasp,
            category, url, description, evidence, impact, remediation, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            engagement_id,
            "Test SQL Injection Vulnerability",
            "critical",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-89",
            "A03:2021",
            "Injection",
            "https://example.com/login?id=1",
            "SQL injection in login parameter",
            "Evidence of SQLi",
            "Unauthorized database access",
            "Use parameterized queries",
            "open",
            datetime.now().isoformat(),
            datetime.now().isoformat(),
        ),
    )
    db.commit()
    return finding_id, engagement_id, db


@pytest.fixture
def multiple_findings(sample_engagement):
    """Create multiple test findings with various severities."""
    engagement_id, db = sample_engagement
    findings = []
    severities = ["critical", "high", "medium", "low", "info"]

    for i, severity in enumerate(severities * 3):  # Create 15 findings
        finding_id = f"find_{i:03d}"
        db.execute(
            """INSERT INTO findings
               (id, engagement_id, title, severity, cvss_score, cvss_vector, cwe, owasp,
                category, url, description, evidence, impact, remediation, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                engagement_id,
                f"Test Vulnerability {i}: {severity.upper()}",
                severity,
                random.uniform(0.1, 10.0) if severity != "critical" else 9.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                f"CWE-{600+i}",
                f"A{(i%10):02d}:2021",
                ["Injection", "Broken Auth", "Crypto", "Logic", "Config"][i % 5],
                f"https://example.com/test{i}",
                f"Description of vuln {i}",
                f"Evidence {i}",
                f"Impact {i}",
                f"Remediation {i}",
                ["open", "in_progress", "closed"][i % 3],
                (datetime.now() - timedelta(days=i)).isoformat(),
                datetime.now().isoformat(),
            ),
        )
        findings.append(finding_id)
    db.commit()
    return findings, engagement_id, db


# =============================================================================
# DIRECTORY & FILE FIXTURES
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for file operations."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def project_structure(tmp_path):
    """Create a realistic project directory structure."""
    structure = {
        'engagements': {},
        'recon': {},
        'evidence': {},
        'reports': {},
        'payloads': {},
        'scripts': {},
    }

    for dir_name in structure.keys():
        (tmp_path / dir_name).mkdir(exist_ok=True)

    # Create sample engagement folder
    eng_folder = tmp_path / 'engagements' / 'test_engagement'
    eng_folder.mkdir(exist_ok=True)
    (eng_folder / 'recon').mkdir(exist_ok=True)
    (eng_folder / 'evidence').mkdir(exist_ok=True)
    (eng_folder / 'reports').mkdir(exist_ok=True)

    return tmp_path


# =============================================================================
# TEST DATA GENERATORS
# =============================================================================

@pytest.fixture
def random_string():
    """Generate random strings for testing."""
    def _generate(length=10):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return _generate


@pytest.fixture
def random_url():
    """Generate random URLs for testing."""
    def _generate(protocol='https', domain=None, path=None):
        if not domain:
            domain = f"test{random.randint(1, 999)}.com"
        if not path:
            path = f"/{''.join(random.choices(string.ascii_lowercase, k=5))}"
        return f"{protocol}://{domain}{path}"
    return _generate


@pytest.fixture
def sample_payloads():
    """Provide various test payloads for security testing."""
    return {
        'xss': [
            '<script>alert("XSS")</script>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            'javascript:alert("XSS")',
            '<img src=x onerror="alert(\'XSS\')">',
            '<svg onload="alert(\'XSS\')">',
        ],
        'sqli': [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "1' AND SLEEP(5)--",
            "1' OR 1=1;--",
        ],
        'command_injection': [
            '; cat /etc/passwd',
            '| whoami',
            '`id`',
            '$(whoami)',
            '& ipconfig',
        ],
        'path_traversal': [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
        ],
    }


@pytest.fixture
def mock_http_response():
    """Create mock HTTP responses."""
    def _create(status_code=200, content=None, headers=None):
        mock_resp = Mock()
        mock_resp.status_code = status_code
        mock_resp.text = content or f"Mock response with status {status_code}"
        mock_resp.content = (content or f"Mock response with status {status_code}").encode()
        mock_resp.headers = headers or {'Content-Type': 'text/html'}
        mock_resp.json = lambda: json.loads(content) if content else {}
        return mock_resp
    return _create


# =============================================================================
# MOCKING & PATCHING FIXTURES
# =============================================================================

@pytest.fixture
def mock_subprocess():
    """Mock subprocess for testing command execution."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Mock command output",
            stderr=""
        )
        yield mock_run


@pytest.fixture
def mock_requests():
    """Mock requests library."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.put') as mock_put, \
         patch('requests.delete') as mock_delete:

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = "Mock response"
        mock_resp.json = lambda: {}

        mock_get.return_value = mock_resp
        mock_post.return_value = mock_resp
        mock_put.return_value = mock_resp
        mock_delete.return_value = mock_resp

        yield {
            'get': mock_get,
            'post': mock_post,
            'put': mock_put,
            'delete': mock_delete,
        }


# =============================================================================
# PERFORMANCE & TIMING FIXTURES
# =============================================================================

@pytest.fixture
def timer():
    """Simple timer for performance testing."""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

        def __enter__(self):
            self.start()
            return self

        def __exit__(self, *args):
            self.stop()

    return Timer()


@pytest.fixture
def benchmark_data():
    """Track benchmark results."""
    data = {'results': []}
    return data


# =============================================================================
# SECURITY TESTING FIXTURES
# =============================================================================

@pytest.fixture
def vulnerability_database():
    """Provide vulnerability test database."""
    return {
        'sql_injection': {
            'payloads': ["' OR '1'='1", "1' UNION SELECT NULL--"],
            'patterns': ['SQL', 'error', 'exception'],
        },
        'xss': {
            'payloads': ['<script>alert(1)</script>', '"><script>'],
            'patterns': ['<script', 'onerror', 'onload'],
        },
        'command_injection': {
            'payloads': ['; whoami', '| id'],
            'patterns': ['uid=', 'bash', 'sh'],
        },
    }


@pytest.fixture
def jwt_test_tokens():
    """Provide JWT tokens for security testing."""
    # Note: These are example tokens for testing only
    return {
        'valid': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        'expired': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMjMwMjJ9.invalid',
        'invalid': 'not.a.jwt',
    }


# =============================================================================
# CLEANUP FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Automatically cleanup after each test."""
    yield
    # Cleanup code here
    pass


@pytest.fixture
def capture_logs(caplog):
    """Capture and return logs."""
    import logging
    caplog.set_level(logging.DEBUG)
    return caplog


# =============================================================================
# SESSION-SCOPED FIXTURES
# =============================================================================

@pytest.fixture(scope="session")
def test_config():
    """Provide test configuration."""
    return {
        'timeout': 30,
        'max_retries': 3,
        'parallel_workers': 4,
        'enable_debug': True,
        'test_data_dir': '/tmp/hakuza_test_data',
    }


@pytest.fixture(scope="session", autouse=True)
def setup_test_session(test_config):
    """Setup test session."""
    # Create test data directory
    test_dir = Path(test_config['test_data_dir'])
    test_dir.mkdir(exist_ok=True)

    yield

    # Cleanup test data directory
    shutil.rmtree(test_dir, ignore_errors=True)
