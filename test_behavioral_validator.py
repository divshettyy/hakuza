#!/usr/bin/env python3
"""
test_behavioral_validator.py — Comprehensive tests for behavioral validation module

Tests cover:
- Baseline capture and snapshots
- HTTP delta analysis
- Success confirmation for RCE, auth bypass, data exposure
- Impact quantification
- False positive detection
- End-to-end validation workflows
"""

import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from mod_behavioral_validator import (
    HTTPSnapshot,
    BehaviorDelta,
    ExploitationResult,
    BaselineCapture,
    BehaviorMonitor,
    DeltaAnalyzer,
    SuccessConfirmer,
    ImpactQuantifier,
    FalsePositiveEliminator,
    AutomaticReporting,
    BehavioralValidator,
)


class TestHTTPSnapshot(unittest.TestCase):
    """Test HTTPSnapshot data model."""

    def test_snapshot_creation(self):
        snap = HTTPSnapshot(
            timestamp="2024-01-01T00:00:00",
            method="GET",
            url="http://example.com/api",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": "test"}',
            body_hash="abc123",
            response_time_ms=45.5,
            content_length=18,
        )
        self.assertEqual(snap.status_code, 200)
        self.assertEqual(snap.response_time_ms, 45.5)

    def test_snapshot_to_dict(self):
        snap = HTTPSnapshot(
            timestamp="2024-01-01T00:00:00",
            method="POST",
            url="http://example.com/login",
            status_code=401,
            headers={},
            body="",
            body_hash="",
            response_time_ms=50.0,
            content_length=0,
        )
        d = snap.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["status_code"], 401)


class TestBehaviorDelta(unittest.TestCase):
    """Test BehaviorDelta analysis."""

    def test_delta_detection_no_changes(self):
        delta = BehaviorDelta()
        self.assertFalse(delta.has_changes())

    def test_delta_detection_with_changes(self):
        delta = BehaviorDelta()
        delta.changed_status_codes["/api"] = {"before": 401, "after": 200}
        self.assertTrue(delta.has_changes())

    def test_delta_with_body_differences(self):
        delta = BehaviorDelta()
        delta.body_differences.append(("http://example.com", "before", "after"))
        self.assertTrue(delta.has_changes())


class TestBaselineCapture(unittest.TestCase):
    """Test baseline state capture."""

    def test_baseline_initialization(self):
        capture = BaselineCapture("http://example.com")
        self.assertEqual(capture.target_url, "http://example.com")
        self.assertIsNotNone(capture.baseline_timestamp)

    @patch("mod_behavioral_validator.HAS_REQUESTS", False)
    def test_baseline_without_requests(self):
        capture = BaselineCapture("http://example.com")
        snap = capture.capture_endpoint("/")
        self.assertIsNone(snap)

    @patch("requests.Session.get")
    def test_capture_endpoint_success(self, mock_get):
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        mock_response.headers = {"Content-Type": "application/json"}
        mock_get.return_value = mock_response

        capture = BaselineCapture("http://example.com")
        snap = capture.capture_endpoint("/api/health")

        self.assertIsNotNone(snap)
        self.assertEqual(snap.status_code, 200)
        self.assertIn("status", snap.body)

    @patch("requests.Session.get")
    def test_capture_endpoint_error(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")

        capture = BaselineCapture("http://example.com")
        snap = capture.capture_endpoint("/")

        self.assertIsNone(snap)

    @patch("requests.Session.get")
    def test_capture_common_endpoints(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ok"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        capture = BaselineCapture("http://example.com")
        snapshots = capture.capture_common_endpoints()

        # Should capture multiple endpoints
        self.assertGreater(len(snapshots), 0)


class TestBehaviorMonitor(unittest.TestCase):
    """Test exploitation monitoring."""

    def test_monitor_initialization(self):
        monitor = BehaviorMonitor("http://example.com")
        self.assertEqual(monitor.target_url, "http://example.com")
        self.assertEqual(len(monitor.execution_events), 0)

    @patch("requests.Session.get")
    def test_capture_post_exploit_state(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "sensitive_data_exposed"
        mock_response.headers = {}
        mock_get.return_value = mock_response

        monitor = BehaviorMonitor("http://example.com")
        snap = monitor.capture_post_exploit_state("/admin")

        self.assertIsNotNone(snap)
        self.assertEqual(snap.status_code, 200)
        self.assertIn("sensitive", snap.body)

    def test_record_event(self):
        monitor = BehaviorMonitor("http://example.com")
        monitor.record_event("exploit_attempt", {"payload": "test", "result": "executed"})

        self.assertEqual(len(monitor.execution_events), 1)
        self.assertEqual(monitor.execution_events[0]["type"], "exploit_attempt")


class TestDeltaAnalyzer(unittest.TestCase):
    """Test HTTP delta analysis."""

    def test_analyze_status_code_changes(self):
        baseline = {
            "http://example.com/admin": HTTPSnapshot(
                timestamp="2024-01-01T00:00:00",
                method="GET",
                url="http://example.com/admin",
                status_code=401,
                headers={},
                body="Unauthorized",
                body_hash="hash1",
                response_time_ms=50.0,
                content_length=12,
            )
        }

        post_exploit = {
            "http://example.com/admin": HTTPSnapshot(
                timestamp="2024-01-01T00:00:01",
                method="GET",
                url="http://example.com/admin",
                status_code=200,
                headers={},
                body="Admin Panel",
                body_hash="hash2",
                response_time_ms=55.0,
                content_length=11,
            )
        }

        delta = DeltaAnalyzer.analyze_http_changes(baseline, post_exploit)

        self.assertIn("http://example.com/admin", delta.changed_status_codes)
        self.assertEqual(delta.changed_status_codes["http://example.com/admin"]["before"], 401)
        self.assertEqual(delta.changed_status_codes["http://example.com/admin"]["after"], 200)

    def test_detect_new_accessible_endpoints(self):
        baseline = {}

        post_exploit = {
            "http://example.com/secret": HTTPSnapshot(
                timestamp="2024-01-01T00:00:00",
                method="GET",
                url="http://example.com/secret",
                status_code=200,
                headers={},
                body="Secret data",
                body_hash="hash",
                response_time_ms=50.0,
                content_length=11,
            )
        }

        delta = DeltaAnalyzer.analyze_http_changes(baseline, post_exploit)

        self.assertIn("http://example.com/secret", delta.new_endpoints_accessible)

    def test_extract_data_exposure_api_keys(self):
        before = "No secrets here"
        after = 'API_KEY="sk_live_1234567890abcdef1234"'

        exposure = DeltaAnalyzer.extract_data_exposure(before, after)

        self.assertIn("api_keys", exposure)
        self.assertGreater(exposure["api_keys"], 0)

    def test_extract_data_exposure_emails(self):
        before = "contact us"
        after = "admin@example.com user@test.com support@domain.org"

        exposure = DeltaAnalyzer.extract_data_exposure(before, after)

        self.assertIn("email_addresses", exposure)
        self.assertEqual(exposure["email_addresses"], 3)

    def test_extract_data_exposure_credentials(self):
        before = "Login page"
        after = 'password="secretpass123" pwd="admin123"'

        exposure = DeltaAnalyzer.extract_data_exposure(before, after)

        self.assertIn("credentials", exposure)
        self.assertGreater(exposure["credentials"], 0)

    def test_detect_timing_anomalies(self):
        snapshots = [
            HTTPSnapshot(
                timestamp="2024-01-01T00:00:00",
                method="GET",
                url="http://example.com/1",
                status_code=200,
                headers={},
                body="",
                body_hash="",
                response_time_ms=50.0,
                content_length=0,
            ),
            HTTPSnapshot(
                timestamp="2024-01-01T00:00:01",
                method="GET",
                url="http://example.com/2",
                status_code=200,
                headers={},
                body="",
                body_hash="",
                response_time_ms=5000.0,  # Suspicious: 5 seconds
                content_length=0,
            ),
        ]

        anomalies = DeltaAnalyzer.detect_timing_anomalies(snapshots, threshold_ms=3000)

        self.assertGreater(len(anomalies), 0)


class TestSuccessConfirmer(unittest.TestCase):
    """Test exploitation success confirmation."""

    def test_confirm_rce_with_id_output(self):
        output = "uid=0(root) gid=0(root) groups=0(root)"
        success, confidence = SuccessConfirmer.confirm_rce(output)

        self.assertTrue(success)
        self.assertGreaterEqual(confidence, 0.4)

    def test_confirm_rce_with_ls_output(self):
        output = "total 24\ndrwx------ 5 root root 4096 Jan  1 00:00 .\ndrwxr-xr-x 3 root root 4096 Jan  1 00:00 .."
        success, confidence = SuccessConfirmer.confirm_rce(output)

        self.assertTrue(success)
        self.assertGreaterEqual(confidence, 0.4)

    def test_confirm_rce_no_output(self):
        output = ""
        success, confidence = SuccessConfirmer.confirm_rce(output)

        self.assertFalse(success)
        self.assertEqual(confidence, 0.0)

    def test_confirm_rce_with_error(self):
        output = "command not found"
        success, confidence = SuccessConfirmer.confirm_rce(output)

        self.assertFalse(success)
        self.assertLess(confidence, 0.5)

    def test_confirm_auth_bypass_401_to_200(self):
        delta = BehaviorDelta()
        delta.changed_status_codes["http://example.com/admin"] = {"before": 401, "after": 200}

        success, confidence = SuccessConfirmer.confirm_auth_bypass(delta)

        self.assertTrue(success)
        self.assertEqual(confidence, 0.95)

    def test_confirm_auth_bypass_403_to_200(self):
        delta = BehaviorDelta()
        delta.changed_status_codes["http://example.com/secret"] = {"before": 403, "after": 200}

        success, confidence = SuccessConfirmer.confirm_auth_bypass(delta)

        self.assertTrue(success)

    def test_confirm_auth_bypass_no_changes(self):
        delta = BehaviorDelta()

        success, confidence = SuccessConfirmer.confirm_auth_bypass(delta)

        self.assertFalse(success)

    def test_confirm_data_exposure(self):
        delta = BehaviorDelta()
        delta.data_exposure = {
            "email_addresses": 5,
            "credentials": 3,
            "api_keys": 2,
        }

        success, confidence = SuccessConfirmer.confirm_data_exposure(delta)

        self.assertTrue(success)
        self.assertGreater(confidence, 0.5)

    def test_confirm_from_custom_indicators(self):
        output = "Successfully retrieved admin credentials"
        indicators = ["Successfully", "admin", "credentials"]

        success, confidence = SuccessConfirmer.confirm_from_indicators(output, BehaviorDelta(), indicators)

        self.assertTrue(success)
        self.assertGreater(confidence, 0.5)


class TestImpactQuantifier(unittest.TestCase):
    """Test impact measurement."""

    def test_quantify_data_exposure_emails(self):
        exposure = {"email_addresses": 100, "credentials": 5}

        result = ImpactQuantifier.quantify_data_exposure(exposure)

        self.assertGreater(result["estimated_records"], 100)
        self.assertEqual(result["severity_estimate"], "high")

    def test_quantify_data_exposure_credentials(self):
        exposure = {"credentials": 50}

        result = ImpactQuantifier.quantify_data_exposure(exposure)

        self.assertGreater(result["estimated_records"], 100)
        self.assertIn(result["severity_estimate"], ["high", "critical"])

    def test_quantify_data_exposure_critical(self):
        exposure = {
            "api_keys": 10,
            "credentials": 50,
            "email_addresses": 1000,
        }

        result = ImpactQuantifier.quantify_data_exposure(exposure)

        self.assertGreater(result["estimated_records"], 1000)
        self.assertEqual(result["severity_estimate"], "critical")

    def test_quantify_privilege_escalation_admin(self):
        access = ["admin panel", "user management", "admin interface"]

        result = ImpactQuantifier.quantify_privilege_escalation(access)

        self.assertEqual(result["access_level_after"], "admin")
        self.assertEqual(result["privilege_increase"], 2)

    def test_quantify_privilege_escalation_root(self):
        access = ["root shell", "system commands"]

        result = ImpactQuantifier.quantify_privilege_escalation(access)

        self.assertEqual(result["access_level_after"], "root")
        self.assertEqual(result["privilege_increase"], 3)

    def test_estimate_cvss_rce(self):
        delta = BehaviorDelta()
        delta.new_endpoints_accessible = ["/shell", "/cmd", "/exec"]

        score, severity = ImpactQuantifier.estimate_cvss_impact("rce", delta, {})

        self.assertGreater(score, 9.0)
        self.assertEqual(severity, "critical")

    def test_estimate_cvss_auth_bypass(self):
        score, severity = ImpactQuantifier.estimate_cvss_impact("auth_bypass", BehaviorDelta(), {})

        self.assertGreater(score, 7.0)
        self.assertIn(severity, ["high", "critical"])

    def test_estimate_cvss_data_exposure(self):
        score, severity = ImpactQuantifier.estimate_cvss_impact("data_exposure", BehaviorDelta(), {})

        self.assertGreater(score, 5.0)


class TestFalsePositiveEliminator(unittest.TestCase):
    """Test false positive detection."""

    def test_empty_poc_output(self):
        delta = BehaviorDelta()
        risk, indicators = FalsePositiveEliminator.check_false_positives(delta, "")

        self.assertGreater(risk, 0.2)
        self.assertGreater(len(indicators), 0)

    def test_error_only_output(self):
        delta = BehaviorDelta()
        risk, indicators = FalsePositiveEliminator.check_false_positives(delta, "Error: command failed")

        self.assertGreater(risk, 0.1)

    def test_no_http_changes(self):
        delta = BehaviorDelta()  # No changes
        risk, indicators = FalsePositiveEliminator.check_false_positives(delta, "output")

        self.assertGreater(risk, 0.3)
        self.assertTrue(any("no http" in i.lower() for i in indicators))

    def test_redirect_status_codes(self):
        delta = BehaviorDelta()
        delta.changed_status_codes["http://example.com"] = {"before": 200, "after": 301}

        risk, indicators = FalsePositiveEliminator.check_false_positives(delta, "output")

        self.assertGreater(risk, 0.3)

    def test_legitimate_exploitation(self):
        delta = BehaviorDelta()
        delta.body_differences.append(("http://example.com", "before", "admin panel"))
        delta.data_exposure["email_addresses"] = 5

        risk, indicators = FalsePositiveEliminator.check_false_positives(
            delta,
            "Successfully exploited target"
        )

        self.assertLess(risk, 0.3)


class TestAutomaticReporting(unittest.TestCase):
    """Test report generation."""

    def test_generate_finding_evidence(self):
        result = ExploitationResult(
            exploit_executed=True,
            success_confirmed=True,
            confidence_score=0.95,
            evidence=["RCE confirmed via command output"],
            impact_type="rce",
            impact_severity="critical",
            data_exfiltrated={},
            access_gained=["root shell"],
        )

        evidence = AutomaticReporting.generate_finding_evidence(result)

        self.assertIn("Exploitation Evidence", evidence)
        self.assertIn("Confirmed", evidence)
        self.assertIn("critical", evidence)
        self.assertIn("root shell", evidence)

    def test_generate_json_report(self):
        result = ExploitationResult(
            exploit_executed=True,
            success_confirmed=True,
            confidence_score=0.85,
            evidence=["Data exposed"],
            impact_type="data_exposure",
            impact_severity="high",
            data_exfiltrated={"emails": 100},
            access_gained=[],
        )

        json_report = AutomaticReporting.generate_json_report(result)

        parsed = json.loads(json_report)
        self.assertEqual(parsed["impact_severity"], "high")
        self.assertEqual(parsed["confidence_score"], 0.85)


class TestBehavioralValidator(unittest.TestCase):
    """Test end-to-end validation workflow."""

    def test_validator_initialization(self):
        validator = BehavioralValidator("http://example.com")

        self.assertEqual(validator.target_url, "http://example.com")
        self.assertIsNone(validator.baseline)

    @patch("mod_behavioral_validator.BaselineCapture.capture_common_endpoints")
    @patch("mod_behavioral_validator.BehaviorMonitor.capture_post_exploit_state")
    @patch.object(BehavioralValidator, "_execute_poc")
    def test_validate_poc_success(self, mock_execute, mock_post, mock_baseline):
        # Create proper HTTPSnapshot objects
        snap = HTTPSnapshot(
            timestamp="2024-01-01T00:00:00",
            method="GET",
            url="http://example.com/",
            status_code=200,
            headers={},
            body="test",
            body_hash="abc123",
            response_time_ms=50.0,
            content_length=4,
        )
        mock_baseline.return_value = {"http://example.com/": snap}

        # Mock PoC execution
        mock_execute.return_value = ("uid=0(root)", True)

        # Mock post-exploit
        mock_post.return_value = snap

        validator = BehavioralValidator("http://example.com")
        result = validator.validate_poc("whoami")

        self.assertIsNotNone(result)
        self.assertTrue(result.exploit_executed)

    def test_execute_poc_python_script(self):
        poc_script = """#!/usr/bin/env python3
print("Test output")
exit(0)
"""
        validator = BehavioralValidator("http://example.com")
        output, success = validator._execute_poc(poc_script)

        self.assertTrue(success)
        self.assertIn("Test", output)

    def test_execute_poc_shell_command(self):
        poc_script = "echo 'test output'"
        validator = BehavioralValidator("http://example.com")
        output, success = validator._execute_poc(poc_script)

        self.assertTrue(success)
        self.assertIn("test", output)

    def test_execute_poc_timeout(self):
        poc_script = "sleep 60"  # Will timeout
        validator = BehavioralValidator("http://example.com")
        output, success = validator._execute_poc(poc_script)

        self.assertFalse(success)


class TestIntegrationScenarios(unittest.TestCase):
    """Test realistic exploitation scenarios."""

    def test_scenario_rce_via_command_injection(self):
        """Simulate RCE via command injection."""
        delta = BehaviorDelta()
        delta.body_differences.append(
            ("http://target.com/search", "No results", "uid=33(www-data) gid=33(www-data)")
        )
        delta.data_exposure["ip_addresses"] = 2

        poc_output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"

        # Confirm success
        success, confidence = SuccessConfirmer.confirm_rce(poc_output)
        self.assertTrue(success)

        # Measure impact
        cvss_score, severity = ImpactQuantifier.estimate_cvss_impact("rce", delta, {})
        self.assertGreater(cvss_score, 9.0)

    def test_scenario_sql_injection_data_extraction(self):
        """Simulate SQLi with data extraction."""
        delta = BehaviorDelta()
        delta.body_differences.append(
            ("http://target.com/products", "Normal", "admin@site.com|password123|user@site.com|pass456")
        )
        exposure = DeltaAnalyzer.extract_data_exposure("Normal", "admin@site.com|password123")

        result = ImpactQuantifier.quantify_data_exposure(exposure)
        self.assertGreater(result["estimated_records"], 0)

    def test_scenario_auth_bypass(self):
        """Simulate authentication bypass."""
        delta = BehaviorDelta()
        delta.changed_status_codes["http://target.com/admin"] = {"before": 403, "after": 200}
        delta.body_differences.append(
            ("http://target.com/admin", "Forbidden", "Admin Dashboard")
        )

        success, confidence = SuccessConfirmer.confirm_auth_bypass(delta)
        self.assertTrue(success)

    def test_scenario_with_false_positive_redirect(self):
        """Test distinguishing real exploits from redirects."""
        # False positive case: just a redirect
        delta = BehaviorDelta()
        delta.changed_status_codes["http://target.com"] = {"before": 301, "after": 304}

        risk, indicators = FalsePositiveEliminator.check_false_positives(delta, "minimal output")

        self.assertGreater(risk, 0.2)  # High FP risk for just redirects


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_empty_baseline_and_post_exploit(self):
        delta = DeltaAnalyzer.analyze_http_changes({}, {})
        self.assertFalse(delta.has_changes())

    def test_large_body_truncation(self):
        large_body = "x" * 100000
        snap = HTTPSnapshot(
            timestamp="2024-01-01",
            method="GET",
            url="http://example.com",
            status_code=200,
            headers={},
            body=large_body[:10000],
            body_hash="hash",
            response_time_ms=100.0,
            content_length=100000,
        )
        self.assertEqual(len(snap.body), 10000)

    def test_null_indicators(self):
        success, confidence = SuccessConfirmer.confirm_from_indicators(
            "output", BehaviorDelta(), None
        )
        self.assertFalse(success)

    def test_malformed_poc_script(self):
        validator = BehavioralValidator("http://example.com")
        output, success = validator._execute_poc("this is not valid python or bash ]][ @@")
        # Should still execute (as shell command) even if malformed
        self.assertIsNotNone(output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
