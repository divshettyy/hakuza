#!/usr/bin/env python3
"""
Comprehensive test suite for mod_engagement_telemetry.py

Tests cover:
- Finding tracking and recording
- Technique statistics computation
- Engagement metrics aggregation
- Import from Burp, Nuclei, Nessus
- ML training data generation
- Quality scoring
- Edge cases and error handling
"""

import unittest
import json
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from mod_engagement_telemetry import (
    Finding, FindingStatus, TechniqueContext, TechniqueStats, EngagementMetrics,
    EngagementTelemetry, EngagementImporter, MLTrainingDataGenerator,
    EngagementQualityScorer
)


# ─────────────────────────────────────────────────────────────────────────────
# TEST DATA FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

def create_test_finding(
    title: str = "Test Finding",
    severity: str = "high",
    status: FindingStatus = FindingStatus.DISCOVERED,
    discovered_offset: int = -100,
    confirmed_offset: int = None,
    exploited_offset: int = None
) -> Finding:
    """Create a test finding with default values."""
    now = datetime.now()

    return Finding(
        id=f"finding_{hash(title)}",
        title=title,
        severity=severity,
        category="Test Category",
        status=status,
        url="http://test.example.com",
        cvss_score=7.5,
        cwe="CWE-89",
        description="Test description",
        evidence="Test evidence",
        discovered_at=now + timedelta(seconds=discovered_offset),
        confirmed_at=now + timedelta(seconds=confirmed_offset) if confirmed_offset else None,
        exploited_at=now + timedelta(seconds=exploited_offset) if exploited_offset else None,
        tool="test_tool",
        confidence=0.95
    )


def create_test_engagement_metrics() -> EngagementMetrics:
    """Create test engagement metrics."""
    return EngagementMetrics(
        engagement_id="test_eng_001",
        engagement_name="Test Engagement",
        target="http://test.example.com",
        start_time=datetime.now() - timedelta(hours=5),
        end_time=datetime.now()
    )


# ─────────────────────────────────────────────────────────────────────────────
# FINDING TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding(unittest.TestCase):
    """Test Finding data model."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = create_test_finding()

        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.severity, "high")
        self.assertIsNotNone(finding.discovered_at)

    def test_time_to_exploitation(self):
        """Test time-to-exploitation calculation."""
        now = datetime.now()
        finding = Finding(
            id="test_001",
            title="RCE",
            severity="critical",
            category="RCE",
            status=FindingStatus.EXPLOITED,
            discovered_at=now,
            exploited_at=now + timedelta(seconds=300)  # 5 minutes
        )

        time_to_exploit = finding.time_to_exploitation_seconds()
        self.assertEqual(time_to_exploit, 300)

    def test_time_to_exploitation_none_without_dates(self):
        """Test that time-to-exploitation is None without proper dates."""
        finding = Finding(
            id="test_002",
            title="XSS",
            severity="medium",
            category="XSS",
            status=FindingStatus.DISCOVERED
        )

        time_to_exploit = finding.time_to_exploitation_seconds()
        self.assertIsNone(time_to_exploit)

    def test_time_to_confirmation(self):
        """Test time-to-confirmation calculation."""
        now = datetime.now()
        finding = Finding(
            id="test_003",
            title="SSRF",
            severity="high",
            category="SSRF",
            status=FindingStatus.CONFIRMED,
            discovered_at=now,
            confirmed_at=now + timedelta(seconds=120)
        )

        time_to_confirm = finding.time_to_confirmation_seconds()
        self.assertEqual(time_to_confirm, 120)


# ─────────────────────────────────────────────────────────────────────────────
# TECHNIQUE STATS TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestTechniqueStats(unittest.TestCase):
    """Test TechniqueStats calculations."""

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        stats = TechniqueStats(
            technique_id="xss_injection",
            technique_name="XSS Injection"
        )

        stats.total_runs = 10
        stats.successful_runs = 7

        self.assertEqual(stats.success_rate, 70.0)

    def test_false_positive_rate_calculation(self):
        """Test false positive rate calculation."""
        stats = TechniqueStats(
            technique_id="sql_injection",
            technique_name="SQL Injection"
        )

        stats.total_runs = 20
        stats.false_positives = 3

        self.assertAlmostEqual(stats.false_positive_rate, 15.0)

    def test_effectiveness_score(self):
        """Test effectiveness score calculation."""
        stats = TechniqueStats(
            technique_id="xxe",
            technique_name="XXE"
        )

        stats.total_runs = 100
        stats.successful_runs = 80
        stats.false_positives = 10

        # effectiveness = success_rate - (fp_rate * 0.5)
        # = 80.0 - (10.0 * 0.5) = 75.0
        expected = 75.0
        self.assertAlmostEqual(stats.effectiveness_score, expected)

    def test_zero_runs_handling(self):
        """Test handling of stats with zero runs."""
        stats = TechniqueStats(
            technique_id="test",
            technique_name="Test"
        )

        self.assertEqual(stats.success_rate, 0.0)
        self.assertEqual(stats.false_positive_rate, 0.0)
        self.assertEqual(stats.effectiveness_score, 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# ENGAGEMENT METRICS TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEngagementMetrics(unittest.TestCase):
    """Test EngagementMetrics calculations."""

    def test_duration_calculation(self):
        """Test engagement duration calculation."""
        start = datetime.now() - timedelta(hours=8)
        end = datetime.now()

        metrics = EngagementMetrics(
            engagement_id="test",
            engagement_name="Test",
            target="http://test.com",
            start_time=start,
            end_time=end
        )

        duration = metrics.duration_hours
        self.assertGreater(duration, 7.9)
        self.assertLess(duration, 8.1)

    def test_confirmation_rate(self):
        """Test confirmation rate calculation."""
        metrics = create_test_engagement_metrics()
        metrics.total_findings = 10
        metrics.confirmed_findings = 7

        self.assertEqual(metrics.confirmation_rate, 70.0)

    def test_exploitation_rate(self):
        """Test exploitation rate calculation."""
        metrics = create_test_engagement_metrics()
        metrics.total_findings = 10
        metrics.exploited_findings = 3

        self.assertEqual(metrics.exploitation_rate, 30.0)

    def test_average_severity(self):
        """Test average finding severity calculation."""
        metrics = create_test_engagement_metrics()
        metrics.critical_findings = 1  # 5 points
        metrics.high_findings = 2       # 8 points
        metrics.medium_findings = 3     # 9 points
        metrics.low_findings = 2        # 4 points
        metrics.info_findings = 2       # 2 points
        metrics.total_findings = 10

        # (1*5 + 2*4 + 3*3 + 2*2 + 2*1) / 10 = 28/10 = 2.8
        expected = 2.8
        self.assertAlmostEqual(metrics.average_finding_severity, expected)


# ─────────────────────────────────────────────────────────────────────────────
# ENGAGEMENT TELEMETRY TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEngagementTelemetry(unittest.TestCase):
    """Test core EngagementTelemetry functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.telemetry = EngagementTelemetry()
        self.telemetry.load_engagement(
            "test_eng_001",
            "Test Engagement",
            "http://test.example.com"
        )

    def test_record_finding(self):
        """Test recording a finding."""
        finding = create_test_finding()

        self.telemetry.record_finding(finding, "xss_injection")

        self.assertIn(finding.id, self.telemetry.findings)
        self.assertEqual(self.telemetry.findings[finding.id], finding)

    def test_technique_stats_tracking(self):
        """Test that technique stats are updated when findings are recorded."""
        finding1 = create_test_finding(
            title="XSS 1",
            status=FindingStatus.CONFIRMED,
            exploited_offset=-50
        )
        finding2 = create_test_finding(
            title="XSS 2",
            status=FindingStatus.CONFIRMED,
            exploited_offset=-75
        )
        finding3 = create_test_finding(
            title="XSS 3",
            status=FindingStatus.FALSE_POSITIVE
        )

        self.telemetry.record_finding(finding1, "xss_injection")
        self.telemetry.record_finding(finding2, "xss_injection")
        self.telemetry.record_finding(finding3, "xss_injection")

        stats = self.telemetry.get_technique_stats("xss_injection")

        self.assertIsNotNone(stats)
        self.assertEqual(stats.total_runs, 3)
        self.assertEqual(stats.successful_runs, 2)
        self.assertEqual(stats.false_positives, 1)
        self.assertGreater(stats.success_rate, 60.0)

    def test_engagement_metrics_update(self):
        """Test engagement metrics are updated with findings."""
        critical = create_test_finding(severity="critical")
        high = create_test_finding(severity="high")
        medium = create_test_finding(severity="medium")

        self.telemetry.record_finding(critical, "rce")
        self.telemetry.record_finding(high, "ssrf")
        self.telemetry.record_finding(medium, "xss")

        metrics = self.telemetry.get_engagement_metrics("test_eng_001")

        self.assertEqual(metrics.total_findings, 3)
        self.assertEqual(metrics.critical_findings, 1)
        self.assertEqual(metrics.high_findings, 1)
        self.assertEqual(metrics.medium_findings, 1)

    def test_finalize_engagement(self):
        """Test finalizing an engagement."""
        finding = create_test_finding(
            status=FindingStatus.EXPLOITED,
            exploited_offset=-300
        )

        self.telemetry.record_finding(finding, "rce")
        metrics = self.telemetry.finalize_engagement()

        self.assertIsNotNone(metrics)
        self.assertIsNotNone(metrics.end_time)
        self.assertEqual(metrics.total_findings, 1)

    def test_get_technique_success_rate(self):
        """Test retrieving technique success rate."""
        self.telemetry.record_finding(
            create_test_finding(status=FindingStatus.CONFIRMED),
            "sql_injection"
        )
        self.telemetry.record_finding(
            create_test_finding(status=FindingStatus.CONFIRMED),
            "sql_injection"
        )
        self.telemetry.record_finding(
            create_test_finding(status=FindingStatus.DISCOVERED),
            "sql_injection"
        )

        rate = self.telemetry.get_technique_success_rate("sql_injection")

        self.assertAlmostEqual(rate, 66.67, delta=1.0)


# ─────────────────────────────────────────────────────────────────────────────
# IMPORT HANDLER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEngagementImporter(unittest.TestCase):
    """Test engagement data importers."""

    def setUp(self):
        """Set up test fixtures."""
        self.telemetry = EngagementTelemetry()
        self.importer = EngagementImporter(self.telemetry)

    def test_parse_nuclei_result(self):
        """Test parsing a Nuclei JSON result."""
        nuclei_data = {
            "info": {
                "name": "SQL Injection",
                "severity": "high",
                "description": "Potential SQL injection",
                "tags": ["injection", "cwe-89"]
            },
            "template-id": "sql-injection-detection",
            "matched-at": "http://test.com/search?q=test"
        }

        finding = self.importer._parse_nuclei_result(nuclei_data)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.title, "SQL Injection")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.tool, "nuclei")
        self.assertIn("CWE-89", finding.cwe or "")

    def test_parse_burp_issue(self):
        """Test parsing a Burp XML issue element."""
        # Create mock XML element
        issue_elem = Mock()
        issue_elem.findtext = Mock(side_effect=lambda tag, default="": {
            "name": "Cross-site scripting (reflected)",
            "severity": "high",
            "description": "The application reflects XSS payloads in responses",
            "evidence": "<img src=x onerror=alert(1)>",
            "url": "http://test.com/page?param=payload"
        }.get(tag, default))

        finding = self.importer._parse_burp_issue(issue_elem)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.title, "Cross-site scripting (reflected)")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.tool, "burp")

    def test_parse_nessus_row(self):
        """Test parsing a Nessus CSV row."""
        row = {
            "Name": "OpenSSL 1.0.1 - Multiple Vulnerabilities",
            "Severity": "High",
            "Description": "OpenSSL 1.0.1 has multiple vulnerabilities. CWE-20",
            "Solution": "Upgrade to latest version",
            "Plugin ID": "12345",
            "Host": "192.168.1.1"
        }

        finding = self.importer._parse_nessus_row(row)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.title, "OpenSSL 1.0.1 - Multiple Vulnerabilities")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.tool, "nessus")

    def test_import_nuclei_json_file(self):
        """Test importing a Nuclei JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Write test data
            json.dump({
                "info": {"name": "Finding 1", "severity": "high"},
                "template-id": "test-1",
                "matched-at": "http://test.com"
            }, f)
            f.write('\n')

            json.dump({
                "info": {"name": "Finding 2", "severity": "medium"},
                "template-id": "test-2",
                "matched-at": "http://test.com"
            }, f)

            temp_path = f.name

        try:
            num_imported, errors = self.importer.import_nuclei_json(temp_path)

            self.assertEqual(num_imported, 2)
            self.assertEqual(len(errors), 0)
            self.assertEqual(len(self.telemetry.findings), 2)
        finally:
            Path(temp_path).unlink()

    def test_import_nuclei_json_invalid_lines(self):
        """Test importing Nuclei JSON with invalid lines."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            # Valid line
            json.dump({
                "info": {"name": "Finding 1", "severity": "high"},
                "template-id": "test-1",
                "matched-at": "http://test.com"
            }, f)
            f.write('\n')

            # Invalid JSON
            f.write("not valid json\n")

            # Valid line
            json.dump({
                "info": {"name": "Finding 2", "severity": "medium"},
                "template-id": "test-2",
                "matched-at": "http://test.com"
            }, f)

            temp_path = f.name

        try:
            num_imported, errors = self.importer.import_nuclei_json(temp_path)

            self.assertEqual(num_imported, 2)
            self.assertGreater(len(errors), 0)
        finally:
            Path(temp_path).unlink()


# ─────────────────────────────────────────────────────────────────────────────
# ML TRAINING DATA TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestMLTrainingDataGenerator(unittest.TestCase):
    """Test ML training data generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.telemetry = EngagementTelemetry()
        self.telemetry.load_engagement("test", "Test", "http://test.com")
        self.generator = MLTrainingDataGenerator(self.telemetry)

    def test_extract_features(self):
        """Test feature extraction from findings."""
        finding = Finding(
            id="test_001",
            title="Test",
            severity="critical",
            category="Test",
            status=FindingStatus.CONFIRMED,
            cvss_score=9.5,
            cwe="CWE-89",
            url="http://test.com",
            description="A" * 1000,
            evidence="B" * 500,
            confidence=0.95,
            requires_auth=True,
            attack_chain_depth=3
        )

        features = self.generator._extract_features(finding)

        self.assertIn("severity_weight", features)
        self.assertEqual(features["severity_weight"], 1.0)  # critical
        self.assertEqual(features["has_cvss"], 1.0)
        self.assertEqual(features["has_cwe"], 1.0)
        self.assertEqual(features["has_url"], 1.0)
        self.assertGreater(features["description_length"], 0.9)
        self.assertGreater(features["evidence_length"], 0.4)
        self.assertEqual(features["is_confirmed"], 1.0)
        self.assertEqual(features["requires_auth"], 1.0)

    def test_generate_feature_vectors(self):
        """Test generating feature vectors for ML."""
        self.telemetry.record_finding(
            create_test_finding(title="XSS Finding", status=FindingStatus.CONFIRMED),
            "xss"
        )
        self.telemetry.record_finding(
            create_test_finding(title="RCE Finding", status=FindingStatus.EXPLOITED),
            "rce"
        )
        self.telemetry.record_finding(
            create_test_finding(title="SSRF Finding", status=FindingStatus.DISCOVERED),
            "ssrf"
        )

        X, y, feature_names = self.generator.generate_feature_vectors()

        self.assertEqual(len(X), 3)
        self.assertEqual(len(y), 3)
        self.assertIsNotNone(feature_names)
        self.assertGreater(len(feature_names), 5)

        # Check labels
        self.assertEqual(y[0], 1)  # CONFIRMED
        self.assertEqual(y[1], 1)  # EXPLOITED
        self.assertEqual(y[2], 0)  # DISCOVERED

    def test_generate_technique_dataset(self):
        """Test generating technique dataset."""
        self.telemetry.record_finding(
            create_test_finding(status=FindingStatus.CONFIRMED),
            "sql_injection"
        )
        self.telemetry.record_finding(
            create_test_finding(status=FindingStatus.CONFIRMED),
            "sql_injection"
        )

        dataset = self.generator.generate_technique_dataset()

        self.assertIn("sql_injection", dataset)
        stats = dataset["sql_injection"]

        self.assertEqual(stats["total_runs"], 2)
        self.assertEqual(stats["successful_runs"], 2)
        self.assertEqual(stats["success_rate"], 100.0)


# ─────────────────────────────────────────────────────────────────────────────
# QUALITY SCORER TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestEngagementQualityScorer(unittest.TestCase):
    """Test engagement quality scoring."""

    def test_score_finding_quality_exploited(self):
        """Test quality score for exploited finding."""
        finding = Finding(
            id="test_001",
            title="RCE",
            severity="critical",
            category="RCE",
            status=FindingStatus.EXPLOITED,
            evidence="Full RCE with code execution proof",
            cwe="CWE-78",
            confidence=1.0
        )

        score = EngagementQualityScorer.score_finding_quality(finding)

        self.assertGreater(score, 0.8)

    def test_score_finding_quality_false_positive(self):
        """Test quality score for false positive."""
        finding = Finding(
            id="test_002",
            title="False Positive",
            severity="medium",
            category="Test",
            status=FindingStatus.FALSE_POSITIVE,
            confidence=1.0
        )

        score = EngagementQualityScorer.score_finding_quality(finding)

        self.assertEqual(score, 0.0)

    def test_score_finding_quality_discovered_only(self):
        """Test quality score for discovered but not confirmed."""
        finding = Finding(
            id="test_003",
            title="Discovered",
            severity="high",
            category="Test",
            status=FindingStatus.DISCOVERED,
            confidence=0.6
        )

        score = EngagementQualityScorer.score_finding_quality(finding)

        # Score should be 0.4 (for DISCOVERED) * 0.6 (confidence) = 0.24
        self.assertGreater(score, 0.1)
        self.assertLess(score, 0.5)

    def test_score_engagement_quality_comprehensive(self):
        """Test comprehensive engagement quality scoring."""
        telemetry = EngagementTelemetry()
        telemetry.load_engagement("test", "Test Engagement", "http://test.com")

        # Add findings
        telemetry.record_finding(
            create_test_finding(severity="critical", status=FindingStatus.EXPLOITED),
            "rce"
        )
        telemetry.record_finding(
            create_test_finding(severity="high", status=FindingStatus.CONFIRMED),
            "ssrf"
        )
        telemetry.record_finding(
            create_test_finding(severity="medium", status=FindingStatus.DISCOVERED),
            "xss"
        )

        metrics = telemetry.finalize_engagement()
        score = EngagementQualityScorer.score_engagement_quality(metrics, telemetry)

        # With exploited, confirmed, and discovered findings, score should be reasonable
        self.assertGreater(score, 0.2)
        self.assertLessEqual(score, 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestTelemetryIntegration(unittest.TestCase):
    """Integration tests for complete telemetry workflow."""

    def test_end_to_end_workflow(self):
        """Test complete telemetry workflow."""
        # Initialize
        telemetry = EngagementTelemetry()
        telemetry.load_engagement(
            "enterprise_app_2024",
            "Enterprise App Pentest",
            "https://app.enterprise.com"
        )

        # Record findings from multiple techniques
        techniques = ["xss_injection", "sql_injection", "ssrf_detection", "rce_os_injection"]

        for i, technique in enumerate(techniques):
            for j in range(5):  # 5 findings per technique
                status = FindingStatus.CONFIRMED if j < 3 else FindingStatus.DISCOVERED
                severity = ["critical", "high", "medium", "low"][i % 4]

                finding = create_test_finding(
                    title=f"{technique} #{j}",
                    severity=severity,
                    status=status,
                    exploited_offset=-100 if status == FindingStatus.CONFIRMED else None
                )

                telemetry.record_finding(finding, technique)

        # Finalize
        metrics = telemetry.finalize_engagement()

        # Verify
        self.assertEqual(metrics.total_findings, 20)
        self.assertEqual(len(metrics.techniques_used), 4)
        self.assertGreater(metrics.confirmation_rate, 0)

        # Check technique stats
        stats = telemetry.get_all_technique_stats()
        self.assertEqual(len(stats), 4)

        for stat in stats.values():
            self.assertGreater(stat.total_runs, 0)
            self.assertGreaterEqual(stat.success_rate, 0)
            self.assertLessEqual(stat.success_rate, 100)

    def test_import_and_quality_assessment(self):
        """Test importing data and assessing quality."""
        # Create test Nuclei JSON file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            for i in range(5):
                json.dump({
                    "info": {
                        "name": f"Finding {i}",
                        "severity": ["critical", "high", "medium", "low", "info"][i],
                        "tags": ["injection", "cwe-89"]
                    },
                    "template-id": f"test-{i}",
                    "matched-at": "http://test.com"
                }, f)
                f.write('\n')
            temp_path = f.name

        try:
            # Import
            telemetry = EngagementTelemetry()
            telemetry.load_engagement("test", "Test", "http://test.com")
            importer = EngagementImporter(telemetry)

            num_imported, errors = importer.import_nuclei_json(temp_path)

            self.assertEqual(num_imported, 5)

            # Check quality
            metrics = telemetry.finalize_engagement()
            score = EngagementQualityScorer.score_engagement_quality(metrics, telemetry)

            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)
        finally:
            Path(temp_path).unlink()


# ─────────────────────────────────────────────────────────────────────────────
# RUN TESTS
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
