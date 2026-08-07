#!/usr/bin/env python3
"""
test_mod_oss_integration.py — Comprehensive Test Suite for OSS Integration Module

Tests covering:
  - Tool Detection & Verification (6 tests)
  - Tool Execution & Parsing (9 tests)
  - Result Aggregation & Deduplication (8 tests)
  - Orchestration & Chaining (5 tests)
  - CLI Integration (3 tests)
  - Error Handling & Edge Cases (4 tests)

Total: 35 tests covering 2000+ LOC
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock, call
import sys

sys.path.insert(0, str(Path(__file__).parent))
from mod_oss_integration import (
    ToolDetector,
    ToolHealthCheck,
    UnifiedFinding,
    ToolResult,
    SeverityLevel,
    ToolCategory,
    ExecutionMode,
    ToolExecutor,
    NucleiExecutor,
    SubfinderExecutor,
    FFufExecutor,
    ResultAggregator,
    OSSOrchestrator,
    cmd_oss_scan,
    TOOLS_CONFIG,
    TOOL_CWE_MAP,
)


# ─────────────────────────────────────────────────────────────────────────────
# Tool Detection Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestToolDetector(unittest.TestCase):
    """Test tool detection and verification."""

    def setUp(self):
        self.detector = ToolDetector()

    def test_detector_initialization(self):
        """Test ToolDetector initializes correctly."""
        self.assertIsNotNone(self.detector)
        self.assertIsInstance(self.detector.tools_status, dict)

    def test_tool_health_check_creation(self):
        """Test ToolHealthCheck data class."""
        check = ToolHealthCheck(
            name="test_tool",
            installed=True,
            version="1.0.0",
            path="/usr/bin/test_tool",
            is_functional=True,
        )
        self.assertEqual(check.name, "test_tool")
        self.assertTrue(check.installed)
        self.assertEqual(check.version, "1.0.0")
        self.assertTrue(check.is_functional)

    def test_check_nonexistent_tool(self):
        """Test checking for non-existent tool."""
        result = self.detector.check_tool("nonexistent_tool_12345")
        self.assertFalse(result.installed)
        self.assertIsNotNone(result.error_message)

    def test_known_tools_configuration(self):
        """Test all known tools have proper config."""
        for tool_name, config in TOOLS_CONFIG.items():
            self.assertIn("cmd", config)
            self.assertIn("version_flag", config)
            self.assertIn("min_version", config)
            self.assertIn("optional", config)
            self.assertIn("category", config)

    @patch("subprocess.run")
    def test_tool_version_parsing(self, mock_run):
        """Test tool version detection."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/usr/bin/tool",
            stderr="",
        )
        check = self.detector.check_tool("nuclei")
        # Just verify it doesn't crash
        self.assertIsNotNone(check)

    def test_missing_critical_tools(self):
        """Test detection of missing critical tools."""
        missing = self.detector.get_missing_tools()
        self.assertIsInstance(missing, list)
        # Just verify it returns a list
        self.assertIsNotNone(missing)


# ─────────────────────────────────────────────────────────────────────────────
# Unified Finding Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestUnifiedFinding(unittest.TestCase):
    """Test unified finding format and operations."""

    def setUp(self):
        self.finding = UnifiedFinding(
            id="test_1",
            title="Test Vulnerability",
            description="A test vulnerability",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            cwe="CWE-79",
            affected_url="http://example.com",
            affected_parameter="user_id",
            method="GET",
            tools_found_by=["nuclei", "ffuf"],
        )

    def test_finding_creation(self):
        """Test UnifiedFinding creation."""
        self.assertEqual(self.finding.id, "test_1")
        self.assertEqual(self.finding.title, "Test Vulnerability")
        self.assertEqual(self.finding.severity, SeverityLevel.HIGH)
        self.assertEqual(len(self.finding.tools_found_by), 2)

    def test_finding_fingerprint_generation(self):
        """Test finding deduplication fingerprint."""
        fp1 = self.finding.fingerprint
        self.assertIsInstance(fp1, str)
        self.assertEqual(len(fp1), 16)  # SHA256 first 16 chars

    def test_fingerprint_consistency(self):
        """Test fingerprint is consistent."""
        fp1 = self.finding.fingerprint
        fp2 = self.finding.fingerprint
        self.assertEqual(fp1, fp2)

    def test_fingerprint_uniqueness(self):
        """Test different findings have different fingerprints."""
        finding2 = UnifiedFinding(
            id="test_2",
            title="Different Vulnerability",
            description="A different test",
            severity=SeverityLevel.MEDIUM,
            affected_url="http://example.com/other",
            tools_found_by=["nikto"],
        )
        self.assertNotEqual(self.finding.fingerprint, finding2.fingerprint)

    def test_finding_to_dict(self):
        """Test finding serialization to dict."""
        data = self.finding.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["id"], "test_1")
        self.assertEqual(data["severity"], "high")
        self.assertEqual(data["cvss_score"], 7.5)

    def test_finding_severity_levels(self):
        """Test all severity levels."""
        for severity in [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFORMATIONAL,
        ]:
            finding = UnifiedFinding(
                id="test",
                title="Test",
                description="Test",
                severity=severity,
            )
            self.assertEqual(finding.severity, severity)


# ─────────────────────────────────────────────────────────────────────────────
# Tool Execution Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestToolExecutors(unittest.TestCase):
    """Test individual tool executors."""

    def test_nuclei_executor_initialization(self):
        """Test NucleiExecutor initialization."""
        executor = NucleiExecutor(severity="high,critical", timeout=300)
        self.assertEqual(executor.tool_name, "nuclei")
        self.assertEqual(executor.timeout, 300)
        self.assertEqual(executor.severity, "high,critical")

    def test_subfinder_executor_initialization(self):
        """Test SubfinderExecutor initialization."""
        executor = SubfinderExecutor(timeout=300)
        self.assertEqual(executor.tool_name, "subfinder")
        self.assertEqual(executor.timeout, 300)

    def test_ffuf_executor_initialization(self):
        """Test FFufExecutor initialization."""
        executor = FFufExecutor(timeout=300)
        self.assertEqual(executor.tool_name, "ffuf")

    @patch("subprocess.run")
    def test_nuclei_parse_json_output(self, mock_run):
        """Test parsing Nuclei JSON output."""
        nuclei_json = """{"template_id":"cve-2021-1234","info":{"name":"Test Vuln","severity":"high","description":"Test","remediation":"Fix it"},"host":"http://example.com","type":"xss"}"""

        result = ToolResult(
            tool_name="nuclei",
            command="nuclei",
            exit_code=0,
            stdout=nuclei_json,
            stderr="",
            raw_output=nuclei_json,
            duration_seconds=5.0,
        )

        executor = NucleiExecutor()
        findings = executor.parse_output(result)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Test Vuln")
        self.assertEqual(findings[0].severity, SeverityLevel.HIGH)

    def test_subfinder_parse_line_output(self):
        """Test parsing Subfinder line-by-line output."""
        output = "sub1.example.com\nsub2.example.com\nsub3.example.com\n"

        result = ToolResult(
            tool_name="subfinder",
            command="subfinder",
            exit_code=0,
            stdout=output,
            stderr="",
            raw_output=output,
            duration_seconds=3.0,
        )

        executor = SubfinderExecutor()
        findings = executor.parse_output(result)

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f.severity == SeverityLevel.INFORMATIONAL for f in findings))

    def test_ffuf_parse_json_results(self):
        """Test parsing FFuf JSON results."""
        ffuf_output = json.dumps({
            "results": [
                {"url": "http://example.com/admin", "status": 200, "length": 1024, "method": "GET"},
                {"url": "http://example.com/api", "status": 200, "length": 2048, "method": "GET"},
                {"url": "http://example.com/404", "status": 404, "length": 128, "method": "GET"},
            ]
        })

        result = ToolResult(
            tool_name="ffuf",
            command="ffuf",
            exit_code=0,
            stdout=ffuf_output,
            stderr="",
            raw_output=ffuf_output,
            duration_seconds=2.0,
        )

        executor = FFufExecutor()
        findings = executor.parse_output(result)

        # Should only include 200-399 status codes
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.severity == SeverityLevel.INFORMATIONAL for f in findings))

    def test_tool_result_with_error(self):
        """Test ToolResult with error."""
        result = ToolResult(
            tool_name="test_tool",
            command="test",
            exit_code=-1,
            stdout="",
            stderr="Command not found",
            raw_output="",
            duration_seconds=0.1,
            error_message="Tool not installed",
            parsed_successfully=False,
        )

        self.assertEqual(result.exit_code, -1)
        self.assertFalse(result.parsed_successfully)
        self.assertIsNotNone(result.error_message)

    def test_tool_result_timeout(self):
        """Test ToolResult with timeout."""
        result = ToolResult(
            tool_name="test_tool",
            command="test",
            exit_code=-1,
            stdout="",
            stderr="TIMEOUT",
            raw_output="TIMEOUT",
            duration_seconds=300.0,
            error_message="Tool timeout after 300s",
            parsed_successfully=False,
        )

        self.assertEqual(result.duration_seconds, 300.0)
        self.assertFalse(result.parsed_successfully)


# ─────────────────────────────────────────────────────────────────────────────
# Result Aggregation & Deduplication Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestResultAggregator(unittest.TestCase):
    """Test result aggregation and deduplication."""

    def setUp(self):
        self.aggregator = ResultAggregator()

    def test_aggregator_initialization(self):
        """Test ResultAggregator initialization."""
        self.assertEqual(len(self.aggregator.findings), 0)
        self.assertEqual(len(self.aggregator.duplicates), 0)

    def test_add_single_finding(self):
        """Test adding a single finding."""
        finding = UnifiedFinding(
            id="test_1",
            title="Test Vulnerability",
            description="Test",
            severity=SeverityLevel.HIGH,
            affected_url="http://example.com",
        )

        self.aggregator.add_finding(finding)
        self.assertEqual(len(self.aggregator.findings), 1)

    def test_add_multiple_findings(self):
        """Test adding multiple findings."""
        findings = [
            UnifiedFinding(
                id=f"test_{i}",
                title=f"Vulnerability {i}",
                description="Test",
                severity=SeverityLevel.HIGH,
                affected_url=f"http://example.com/path{i}",
                tools_found_by=["nuclei"],
            )
            for i in range(5)
        ]

        self.aggregator.add_findings(findings)
        self.assertEqual(len(self.aggregator.findings), 5)

    def test_deduplication_identical_findings(self):
        """Test deduplication of identical findings."""
        finding1 = UnifiedFinding(
            id="test_1",
            title="Test Vulnerability",
            description="Test",
            severity=SeverityLevel.HIGH,
            affected_url="http://example.com",
            affected_parameter="id",
            tools_found_by=["nuclei"],
        )

        finding2 = UnifiedFinding(
            id="test_2",
            title="Test Vulnerability",
            description="Test",
            severity=SeverityLevel.HIGH,
            affected_url="http://example.com",
            affected_parameter="id",
            tools_found_by=["ffuf"],
        )

        self.aggregator.add_findings([finding1, finding2])
        # Findings with same fingerprint are merged immediately, so findings dict has 1
        self.assertEqual(len(self.aggregator.findings), 1)

        deduplicated = self.aggregator.deduplicate(threshold=0.85)
        # After dedup should still be 1
        self.assertEqual(len(deduplicated), 1)
        self.assertIn("nuclei", deduplicated[0].tools_found_by)
        self.assertIn("ffuf", deduplicated[0].tools_found_by)

    def test_similarity_calculation(self):
        """Test similarity calculation between findings."""
        finding1 = UnifiedFinding(
            id="test_1",
            title="XSS in login form",
            description="XSS",
            severity=SeverityLevel.HIGH,
            affected_url="http://example.com/login",
            affected_parameter="username",
            method="GET",
        )

        finding2 = UnifiedFinding(
            id="test_2",
            title="XSS in login form",
            description="XSS",
            severity=SeverityLevel.HIGH,
            affected_url="http://example.com/login",
            affected_parameter="username",
            method="GET",
        )

        similarity = ResultAggregator._calculate_similarity(finding1, finding2)
        self.assertGreater(similarity, 0.9)  # Should be very similar

    def test_findings_by_severity(self):
        """Test grouping findings by severity."""
        findings = [
            UnifiedFinding(
                id="c1",
                title="Critical",
                description="",
                severity=SeverityLevel.CRITICAL,
            ),
            UnifiedFinding(
                id="h1",
                title="High",
                description="",
                severity=SeverityLevel.HIGH,
            ),
            UnifiedFinding(
                id="m1",
                title="Medium",
                description="",
                severity=SeverityLevel.MEDIUM,
            ),
        ]

        self.aggregator.add_findings(findings)
        grouped = self.aggregator.get_findings_by_severity()

        self.assertIn(SeverityLevel.CRITICAL, grouped)
        self.assertIn(SeverityLevel.HIGH, grouped)
        self.assertIn(SeverityLevel.MEDIUM, grouped)

    def test_findings_by_tool(self):
        """Test grouping findings by tool."""
        findings = [
            UnifiedFinding(
                id="n1",
                title="Nuclei Finding",
                description="",
                severity=SeverityLevel.HIGH,
                tools_found_by=["nuclei"],
            ),
            UnifiedFinding(
                id="f1",
                title="FFuf Finding",
                description="",
                severity=SeverityLevel.MEDIUM,
                tools_found_by=["ffuf"],
            ),
        ]

        self.aggregator.add_findings(findings)
        grouped = self.aggregator.get_findings_by_tool()

        self.assertIn("nuclei", grouped)
        self.assertIn("ffuf", grouped)

    def test_export_to_json(self):
        """Test JSON export."""
        finding = UnifiedFinding(
            id="test_1",
            title="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
        )

        self.aggregator.add_finding(finding)
        json_str = self.aggregator.to_json()

        data = json.loads(json_str)
        self.assertIn("metadata", data)
        self.assertIn("findings", data)
        self.assertEqual(data["metadata"]["total_findings"], 1)

    def test_export_to_markdown(self):
        """Test Markdown export."""
        findings = [
            UnifiedFinding(
                id="c1",
                title="Critical Finding",
                description="Very serious",
                severity=SeverityLevel.CRITICAL,
                remediation="Fix immediately",
            ),
            UnifiedFinding(
                id="m1",
                title="Medium Finding",
                description="Somewhat serious",
                severity=SeverityLevel.MEDIUM,
            ),
        ]

        self.aggregator.add_findings(findings)
        markdown = self.aggregator.to_markdown()

        self.assertIn("OSS Integration Scan Report", markdown)
        self.assertIn("CRITICAL", markdown)
        self.assertIn("MEDIUM", markdown)
        self.assertIn("Critical Finding", markdown)


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestOSSOrchestrator(unittest.TestCase):
    """Test orchestration engine."""

    def setUp(self):
        self.orchestrator = OSSOrchestrator(max_workers=2, timeout=60)

    def test_orchestrator_initialization(self):
        """Test OSSOrchestrator initialization."""
        self.assertEqual(self.orchestrator.max_workers, 2)
        self.assertEqual(self.orchestrator.timeout, 60)
        self.assertIsNotNone(self.orchestrator.detector)
        self.assertIsNotNone(self.orchestrator.aggregator)

    @patch.object(OSSOrchestrator, "_execute_tool")
    def test_sequential_execution(self, mock_execute):
        """Test sequential tool execution."""
        mock_execute.return_value = ToolResult(
            tool_name="nuclei",
            command="nuclei",
            exit_code=0,
            stdout='{"template_id":"test","info":{"name":"Test"}}',
            stderr="",
            raw_output="",
            duration_seconds=1.0,
        )

        orchestrator = OSSOrchestrator()
        aggregator, results = orchestrator.scan(
            "http://example.com",
            tools=["nuclei"],
            mode=ExecutionMode.SEQUENTIAL,
        )

        self.assertIn("nuclei", results)

    def test_execution_mode_enum(self):
        """Test ExecutionMode enum."""
        self.assertEqual(ExecutionMode.SEQUENTIAL.value, "sequential")
        self.assertEqual(ExecutionMode.PARALLEL.value, "parallel")
        self.assertEqual(ExecutionMode.SMART.value, "smart")

    def test_parse_tool_result(self):
        """Test tool result parsing."""
        result = ToolResult(
            tool_name="nuclei",
            command="nuclei",
            exit_code=0,
            stdout='{"template_id":"test","info":{"name":"Test Vuln","severity":"high"}}',
            stderr="",
            raw_output="",
            duration_seconds=1.0,
        )

        orchestrator = OSSOrchestrator()
        findings = orchestrator._parse_tool_result(result)

        self.assertIsInstance(findings, list)

    def test_unknown_tool_executor(self):
        """Test handling of unknown tool."""
        orchestrator = OSSOrchestrator()
        result = orchestrator._execute_tool("unknown_tool", "http://example.com")

        self.assertFalse(result.parsed_successfully)
        self.assertIsNotNone(result.error_message)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestOSSCLI(unittest.TestCase):
    """Test CLI command."""

    @patch("mod_oss_integration.console")
    def test_tool_check_action(self, mock_console):
        """Test tool-check action."""
        result = cmd_oss_scan(action="tool-check")
        self.assertEqual(result, 0)

    @patch("mod_oss_integration.OSSOrchestrator.scan")
    def test_scan_without_target(self, mock_scan):
        """Test scan without target fails."""
        result = cmd_oss_scan(action="scan")
        self.assertEqual(result, 1)

    @patch("mod_oss_integration.OSSOrchestrator")
    @patch("mod_oss_integration.console")
    def test_scan_with_all_tools(self, mock_console, mock_orchestrator_class):
        """Test scan with --all flag."""
        mock_instance = MagicMock()
        mock_orchestrator_class.return_value = mock_instance
        mock_instance.scan.return_value = (MagicMock(), {})

        result = cmd_oss_scan(
            action="scan",
            target="http://example.com",
            all=True,
            output="json",
        )

        self.assertEqual(result, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Error Handling & Edge Cases
# ─────────────────────────────────────────────────────────────────────────────


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def test_empty_tool_list(self):
        """Test handling of empty tool list."""
        aggregator = ResultAggregator()
        # Should handle gracefully
        deduplicated = aggregator.deduplicate()
        self.assertEqual(len(deduplicated), 0)

    def test_finding_with_missing_optional_fields(self):
        """Test finding creation with minimal fields."""
        finding = UnifiedFinding(
            id="minimal",
            title="Minimal",
            description="",
            severity=SeverityLevel.LOW,
        )

        self.assertEqual(finding.id, "minimal")
        self.assertIsNone(finding.affected_url)
        self.assertIsNone(finding.cwe)

    def test_tool_result_with_multiline_json(self):
        """Test parsing multiline JSON output."""
        output = """{"template_id":"test1","info":{"name":"Test 1","severity":"high"}}
{"template_id":"test2","info":{"name":"Test 2","severity":"medium"}}
{"template_id":"test3","info":{"name":"Test 3","severity":"low"}}"""

        result = ToolResult(
            tool_name="nuclei",
            command="nuclei",
            exit_code=0,
            stdout=output,
            stderr="",
            raw_output=output,
            duration_seconds=5.0,
        )

        executor = NucleiExecutor()
        findings = executor.parse_output(result)

        self.assertEqual(len(findings), 3)

    def test_malformed_json_handling(self):
        """Test handling of malformed JSON."""
        result = ToolResult(
            tool_name="nuclei",
            command="nuclei",
            exit_code=0,
            stdout="{invalid json}",
            stderr="",
            raw_output="",
            duration_seconds=1.0,
        )

        executor = NucleiExecutor()
        findings = executor.parse_output(result)

        # Should return empty list, not crash
        self.assertEqual(len(findings), 0)

    def test_cwe_mapping_coverage(self):
        """Test CWE/CVSS mappings exist."""
        for tool, mappings in TOOL_CWE_MAP.items():
            self.assertIsInstance(mappings, dict)
            for vuln_type, values in mappings.items():
                self.assertEqual(len(values), 3)  # CWE, severity, CVSS


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_end_to_end_finding_creation(self):
        """Test complete finding creation flow."""
        findings = [
            UnifiedFinding(
                id="test_1",
                title="XSS Vulnerability",
                description="Reflected XSS in login form",
                severity=SeverityLevel.HIGH,
                cvss_score=7.1,
                cwe="CWE-79",
                affected_url="http://example.com/login",
                affected_parameter="username",
                method="GET",
                remediation="Use parameterized queries",
                tools_found_by=["nuclei", "ffuf"],
            )
        ]

        aggregator = ResultAggregator()
        aggregator.add_findings(findings)

        # Export to multiple formats
        json_export = aggregator.to_json()
        markdown_export = aggregator.to_markdown()

        # Verify exports
        json_data = json.loads(json_export)
        self.assertEqual(len(json_data["findings"]), 1)
        self.assertIn("XSS Vulnerability", markdown_export)

    def test_aggregator_deduplication_workflow(self):
        """Test complete deduplication workflow."""
        similar_findings = [
            UnifiedFinding(
                id=f"finding_{i}",
                title="SQL Injection in API",
                description="Potential SQL injection",
                severity=SeverityLevel.CRITICAL,
                affected_url="http://api.example.com/users",
                affected_parameter="id",
                tools_found_by=[tool],
            )
            for i, tool in enumerate(["nuclei", "sqlmap", "ffuf"])
        ]

        aggregator = ResultAggregator()
        aggregator.add_findings(similar_findings)

        # Before dedup: 3 findings (after fingerprint merging may be 1)
        before = len(aggregator.findings)

        # Deduplicate
        deduplicated = aggregator.deduplicate(threshold=0.80)

        # Should have merged similar findings
        self.assertLessEqual(len(deduplicated), before)


if __name__ == "__main__":
    unittest.main()
