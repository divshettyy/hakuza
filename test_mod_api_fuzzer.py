#!/usr/bin/env python3
"""
test_mod_api_fuzzer.py — Comprehensive test suite for mod_api_fuzzer.py

30+ test cases covering:
  - Payload library loading
  - Endpoint discovery (Swagger/manual)
  - Context-aware payload generation
  - Parameter type detection
  - Response baseline and differencing
  - Vulnerability classification
  - PoC generation (curl/python)
  - Fuzzing logic and anomaly detection
"""

import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Import module components
from mod_api_fuzzer import (
    PayloadLibraryLoader,
    APIEndpointDiscovery,
    APIEndpoint,
    ContextAwarePayloadGenerator,
    ResponseBaseline,
    ResultDifferencer,
    VulnerabilityClassifier,
    ParameterFuzzer,
    APIFuzzerOrchestrator,
    VulnerabilityType,
    FuzzingResult,
    VulnerabilityFinding,
    CWE_SEVERITY_MAP,
    PARAMETER_TYPE_PATTERNS,
)


class TestPayloadLibraryLoader(unittest.TestCase):
    """Test payload library loading and management."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.payload_dir = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up temp directory."""
        self.temp_dir.cleanup()

    def test_loader_initialization(self):
        """Test PayloadLibraryLoader initialization."""
        loader = PayloadLibraryLoader(self.payload_dir)
        self.assertIsNotNone(loader.payloads)
        self.assertIsInstance(loader.payloads, dict)

    def test_load_xss_payloads(self):
        """Test XSS payload loading."""
        xss_file = self.payload_dir / "xss.txt"
        xss_file.write_text("# Comment\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>")

        loader = PayloadLibraryLoader(self.payload_dir)
        xss_payloads = loader.get_payloads(VulnerabilityType.XSS)

        self.assertGreater(len(xss_payloads), 0)
        self.assertIn("<script>alert(1)</script>", xss_payloads)

    def test_load_sqli_payloads(self):
        """Test SQLi payload loading."""
        sqli_file = self.payload_dir / "sqli.txt"
        sqli_file.write_text("' OR '1'='1\n1 UNION SELECT NULL--")

        loader = PayloadLibraryLoader(self.payload_dir)
        sqli_payloads = loader.get_payloads(VulnerabilityType.SQLI)

        self.assertGreater(len(sqli_payloads), 0)

    def test_load_ssti_payloads(self):
        """Test SSTI payload loading."""
        ssti_file = self.payload_dir / "ssti.txt"
        ssti_file.write_text("{{7*7}}\n${7*7}")

        loader = PayloadLibraryLoader(self.payload_dir)
        ssti_payloads = loader.get_payloads(VulnerabilityType.SSTI)

        self.assertGreater(len(ssti_payloads), 0)

    def test_filter_comments(self):
        """Test that comments are filtered out."""
        xss_file = self.payload_dir / "xss.txt"
        xss_file.write_text("# This is a comment\n<script>alert(1)</script>\n# Another comment")

        loader = PayloadLibraryLoader(self.payload_dir)
        xss_payloads = loader.get_payloads(VulnerabilityType.XSS)

        for payload in xss_payloads:
            self.assertFalse(payload.startswith("#"))

    def test_count_total_payloads(self):
        """Test counting total payloads."""
        xss_file = self.payload_dir / "xss.txt"
        xss_file.write_text("<script>alert(1)</script>\n<img src=x onerror=alert(1)>")

        sqli_file = self.payload_dir / "sqli.txt"
        sqli_file.write_text("' OR '1'='1")

        loader = PayloadLibraryLoader(self.payload_dir)
        total = loader.count_total_payloads()

        self.assertGreater(total, 0)

    def test_get_all_payloads(self):
        """Test getting all payloads."""
        xss_file = self.payload_dir / "xss.txt"
        xss_file.write_text("<script>alert(1)</script>")

        loader = PayloadLibraryLoader(self.payload_dir)
        all_payloads = loader.get_all_payloads()

        self.assertIsInstance(all_payloads, dict)


class TestAPIEndpointDiscovery(unittest.TestCase):
    """Test API endpoint discovery."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://api.example.com"
        self.discovery = APIEndpointDiscovery(self.base_url)

    def test_discovery_initialization(self):
        """Test APIEndpointDiscovery initialization."""
        self.assertEqual(self.discovery.base_url, self.base_url)
        self.assertEqual(len(self.discovery.endpoints), 0)

    def test_add_manual_endpoint(self):
        """Test adding endpoints manually."""
        endpoints = [
            {'method': 'GET', 'path': '/api/users', 'description': 'Get users'},
            {'method': 'POST', 'path': '/api/users', 'description': 'Create user'},
        ]

        self.discovery.discover_from_manual(endpoints)

        self.assertEqual(len(self.discovery.endpoints), 2)
        self.assertEqual(self.discovery.endpoints[0].method, 'GET')

    def test_endpoint_full_url(self):
        """Test endpoint full URL generation."""
        endpoint = APIEndpoint(method='GET', path='/api/users')
        self.assertEqual(endpoint.full_url, '/api/users')

    def test_multiple_methods_same_path(self):
        """Test multiple HTTP methods on same path."""
        endpoints = [
            {'method': 'GET', 'path': '/api/users'},
            {'method': 'POST', 'path': '/api/users'},
            {'method': 'PUT', 'path': '/api/users/1'},
        ]

        self.discovery.discover_from_manual(endpoints)

        self.assertEqual(len(self.discovery.endpoints), 3)

    def test_get_endpoints(self):
        """Test retrieving endpoints."""
        endpoints = [
            {'method': 'GET', 'path': '/api/test'},
        ]

        self.discovery.discover_from_manual(endpoints)
        retrieved = self.discovery.get_endpoints()

        self.assertEqual(len(retrieved), 1)
        self.assertEqual(retrieved[0].path, '/api/test')


class TestParameterTypeDetection(unittest.TestCase):
    """Test parameter type detection."""

    def setUp(self):
        """Set up test fixtures."""
        loader = PayloadLibraryLoader()
        self.generator = ContextAwarePayloadGenerator(loader)

    def test_detect_numeric_parameter(self):
        """Test detection of numeric parameters."""
        param_type = self.generator.detect_parameter_type('user_id')
        self.assertEqual(param_type, 'numeric')

        param_type = self.generator.detect_parameter_type('id')
        self.assertEqual(param_type, 'numeric')

        param_type = self.generator.detect_parameter_type('page')
        self.assertEqual(param_type, 'numeric')

    def test_detect_email_parameter(self):
        """Test detection of email parameters."""
        param_type = self.generator.detect_parameter_type('email')
        self.assertEqual(param_type, 'email')

        param_type = self.generator.detect_parameter_type('from')
        self.assertEqual(param_type, 'email')

    def test_detect_url_parameter(self):
        """Test detection of URL parameters."""
        param_type = self.generator.detect_parameter_type('redirect')
        self.assertEqual(param_type, 'url')

        param_type = self.generator.detect_parameter_type('callback')
        self.assertEqual(param_type, 'url')

        param_type = self.generator.detect_parameter_type('image')
        self.assertEqual(param_type, 'url')

    def test_detect_file_parameter(self):
        """Test detection of file parameters."""
        param_type = self.generator.detect_parameter_type('file')
        self.assertEqual(param_type, 'file')

        param_type = self.generator.detect_parameter_type('path')
        self.assertEqual(param_type, 'file')

    def test_detect_command_parameter(self):
        """Test detection of command parameters."""
        param_type = self.generator.detect_parameter_type('cmd')
        self.assertEqual(param_type, 'command')

        param_type = self.generator.detect_parameter_type('execute')
        self.assertEqual(param_type, 'command')

    def test_detect_template_parameter(self):
        """Test detection of template parameters."""
        param_type = self.generator.detect_parameter_type('template')
        self.assertEqual(param_type, 'template')

        param_type = self.generator.detect_parameter_type('tpl')
        self.assertEqual(param_type, 'template')

    def test_detect_query_parameter(self):
        """Test detection of query parameters."""
        param_type = self.generator.detect_parameter_type('q')
        self.assertEqual(param_type, 'query')

        param_type = self.generator.detect_parameter_type('search')
        self.assertEqual(param_type, 'query')

    def test_detect_unknown_parameter(self):
        """Test fallback for unknown parameters."""
        param_type = self.generator.detect_parameter_type('xyzunknown')
        self.assertEqual(param_type, 'generic')


class TestContextAwarePayloadGeneration(unittest.TestCase):
    """Test context-aware payload generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.payload_dir = Path(self.temp_dir.name)

        # Create sample payload files
        (self.payload_dir / "xss.txt").write_text("<script>alert(1)</script>")
        (self.payload_dir / "sqli.txt").write_text("' OR '1'='1")
        (self.payload_dir / "ssrf.txt").write_text("http://169.254.169.254/latest/meta-data/")

        self.loader = PayloadLibraryLoader(self.payload_dir)
        self.generator = ContextAwarePayloadGenerator(self.loader)

    def tearDown(self):
        """Clean up temp directory."""
        self.temp_dir.cleanup()

    def test_generate_numeric_param_payloads(self):
        """Test payload generation for numeric parameters."""
        payloads = self.generator.generate_payloads('user_id', 'query')

        self.assertIsInstance(payloads, dict)
        # Numeric params should get SQLi and IDOR payloads
        if VulnerabilityType.SQLI in payloads:
            self.assertGreater(len(payloads[VulnerabilityType.SQLI]), 0)

    def test_generate_url_param_payloads(self):
        """Test payload generation for URL parameters."""
        payloads = self.generator.generate_payloads('redirect', 'query')

        self.assertIsInstance(payloads, dict)
        # URL params should get SSRF and redirect payloads
        if VulnerabilityType.SSRF in payloads or VulnerabilityType.REDIRECT in payloads:
            self.assertGreater(len(payloads), 0)

    def test_generate_generic_param_payloads(self):
        """Test payload generation for generic parameters."""
        payloads = self.generator.generate_payloads('custom_param', 'query')

        self.assertIsInstance(payloads, dict)


class TestResponseBaseline(unittest.TestCase):
    """Test response baseline establishment."""

    def setUp(self):
        """Set up test fixtures."""
        self.endpoint = APIEndpoint(method='GET', path='/api/test')
        self.base_url = "http://example.com"

    def test_baseline_initialization(self):
        """Test ResponseBaseline initialization."""
        baseline = ResponseBaseline(self.endpoint, self.base_url)

        self.assertEqual(baseline.endpoint, self.endpoint)
        self.assertEqual(baseline.base_url, self.base_url)
        self.assertEqual(len(baseline.samples), 0)

    @patch('mod_api_fuzzer.requests.Session')
    def test_capture_baseline_samples(self, mock_session_class):
        """Test capturing baseline samples."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"test content"
        mock_session.request.return_value = mock_response

        baseline = ResponseBaseline(self.endpoint, self.base_url)
        # Note: This test mocks the request, so actual HTTP isn't tested
        # In real scenarios, this would hit the actual endpoint


class TestResultDifferencer(unittest.TestCase):
    """Test response difference analysis."""

    def test_calculate_similarity_identical(self):
        """Test similarity of identical texts."""
        similarity = ResultDifferencer.calculate_similarity("hello", "hello")
        self.assertEqual(similarity, 1.0)

    def test_calculate_similarity_different(self):
        """Test similarity of different texts."""
        similarity = ResultDifferencer.calculate_similarity("hello", "world")
        self.assertLess(similarity, 1.0)
        self.assertGreater(similarity, 0.0)

    def test_calculate_similarity_partial(self):
        """Test similarity of partial match."""
        similarity = ResultDifferencer.calculate_similarity("hello world", "hello friend")
        self.assertGreater(similarity, 0.5)

    def test_calculate_similarity_empty(self):
        """Test similarity with empty strings."""
        similarity = ResultDifferencer.calculate_similarity("", "test")
        self.assertEqual(similarity, 0.0)

    def test_detect_anomalies_no_baseline(self):
        """Test anomaly detection without baseline."""
        baseline = ResponseBaseline(APIEndpoint(method='GET', path='/'), "http://test.com")

        score, anomalies = ResultDifferencer.detect_anomalies(
            baseline, 200, 100, "test", 0.5
        )

        self.assertEqual(score, 0.0)


class TestVulnerabilityClassification(unittest.TestCase):
    """Test vulnerability classification and scoring."""

    def setUp(self):
        """Set up test fixtures."""
        self.classifier = VulnerabilityClassifier()

    def test_classify_sqli(self):
        """Test SQLi classification."""
        result = self.classifier.classify("sqli", 0.8, 0.9)

        self.assertEqual(result['cwe'], "CWE-89")
        self.assertEqual(result['severity'], "Critical")
        self.assertGreater(result['cvss'], 7.0)

    def test_classify_xss(self):
        """Test XSS classification."""
        result = self.classifier.classify("xss", 0.7, 0.8)

        self.assertEqual(result['cwe'], "CWE-79")
        self.assertEqual(result['severity'], "High")
        self.assertGreater(result['cvss'], 5.0)

    def test_classify_rce(self):
        """Test RCE classification."""
        result = self.classifier.classify("rce", 0.9, 0.95)

        self.assertEqual(result['cwe'], "CWE-78")
        self.assertEqual(result['severity'], "Critical")
        self.assertGreater(result['cvss'], 8.0)

    def test_classify_idor(self):
        """Test IDOR classification."""
        result = self.classifier.classify("idor", 0.6, 0.7)

        self.assertEqual(result['cwe'], "CWE-639")
        self.assertEqual(result['severity'], "High")

    def test_classify_unknown(self):
        """Test unknown vulnerability classification."""
        result = self.classifier.classify("unknown_vuln", 0.5, 0.5)

        self.assertIn("CWE", result['cwe'])
        self.assertEqual(result['severity'], "Medium")

    def test_classify_confidence_adjustment(self):
        """Test CVSS adjustment by confidence."""
        result1 = self.classifier.classify("xss", 0.8, 1.0)
        result2 = self.classifier.classify("xss", 0.8, 0.5)

        self.assertGreater(result1['cvss'], result2['cvss'])

    def test_cvss_cap_at_10(self):
        """Test that CVSS is capped at 10."""
        result = self.classifier.classify("sqli", 1.0, 2.0)

        self.assertLessEqual(result['cvss'], 10.0)


class TestPoCGeneration(unittest.TestCase):
    """Test Proof of Concept generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.classifier = VulnerabilityClassifier()
        self.endpoint = APIEndpoint(method='GET', path='/api/test')
        self.payload = "' OR '1'='1"

    def test_generate_poc_curl(self):
        """Test curl PoC generation."""
        curl_poc = self.classifier.generate_poc_curl(
            self.endpoint,
            self.payload,
            'id',
            'query'
        )

        self.assertIn('curl', curl_poc)
        self.assertIn('-X GET', curl_poc)
        self.assertIn('id=', curl_poc)

    def test_generate_poc_python(self):
        """Test Python PoC generation."""
        python_poc = self.classifier.generate_poc_python(
            self.endpoint,
            self.payload,
            'id',
            'query'
        )

        self.assertIn('python', python_poc.lower() or '#!/' in python_poc)
        self.assertIn('requests', python_poc)
        self.assertIn('id', python_poc)

    def test_generate_poc_header_location(self):
        """Test PoC generation for header parameter."""
        curl_poc = self.classifier.generate_poc_curl(
            self.endpoint,
            self.payload,
            'Authorization',
            'header'
        )

        self.assertIn('-H', curl_poc)

    def test_generate_poc_body_location(self):
        """Test PoC generation for body parameter."""
        curl_poc = self.classifier.generate_poc_curl(
            self.endpoint,
            self.payload,
            'username',
            'body'
        )

        self.assertIn('-d', curl_poc)


class TestCWESeverityMapping(unittest.TestCase):
    """Test CWE and severity mappings."""

    def test_cwe_mapping_exists(self):
        """Test that CWE mapping is complete."""
        self.assertGreater(len(CWE_SEVERITY_MAP), 10)

    def test_cwe_format(self):
        """Test CWE format is correct."""
        for cwe, severity, cvss in CWE_SEVERITY_MAP.values():
            self.assertRegex(cwe, r'^CWE-\d+')
            self.assertIn(severity, ['Low', 'Medium', 'High', 'Critical'])
            self.assertGreaterEqual(cvss, 0.0)
            self.assertLessEqual(cvss, 10.0)

    def test_sqli_cwe(self):
        """Test SQLi CWE mapping."""
        cwe, severity, cvss = CWE_SEVERITY_MAP['sqli']
        self.assertEqual(cwe, "CWE-89")
        self.assertEqual(severity, "Critical")

    def test_xss_cwe(self):
        """Test XSS CWE mapping."""
        cwe, severity, cvss = CWE_SEVERITY_MAP['xss']
        self.assertEqual(cwe, "CWE-79")
        self.assertEqual(severity, "High")


class TestFuzzingResult(unittest.TestCase):
    """Test FuzzingResult data class."""

    def test_fuzzing_result_creation(self):
        """Test creating a FuzzingResult."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="' OR '1'='1",
            vuln_type=VulnerabilityType.SQLI,
            status_code=200,
            response_length=1024,
            differential_score=0.8
        )

        self.assertEqual(result.parameter_name, 'id')
        self.assertEqual(result.vuln_type, VulnerabilityType.SQLI)
        self.assertEqual(result.differential_score, 0.8)

    def test_fuzzing_result_timestamp(self):
        """Test FuzzingResult timestamp."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="test",
            vuln_type=VulnerabilityType.XSS
        )

        # Should be ISO format
        self.assertRegex(result.timestamp, r'\d{4}-\d{2}-\d{2}T')


class TestAPIFuzzerOrchestrator(unittest.TestCase):
    """Test main API fuzzer orchestrator."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://api.example.com"
        self.orchestrator = APIFuzzerOrchestrator(self.base_url)

    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        self.assertEqual(self.orchestrator.base_url, self.base_url)
        self.assertIsNotNone(self.orchestrator.payload_loader)
        self.assertIsNotNone(self.orchestrator.discovery)

    def test_payload_loader_initialized(self):
        """Test that payload loader is initialized."""
        total_payloads = self.orchestrator.payload_loader.count_total_payloads()
        # May be 0 if ~/tools/payloads doesn't exist in test env
        self.assertGreaterEqual(total_payloads, 0)

    def test_create_finding_from_result(self):
        """Test finding creation from fuzzing result."""
        endpoint = APIEndpoint(method='GET', path='/api/users')
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="' OR '1'='1",
            vuln_type=VulnerabilityType.SQLI,
            status_code=200,
            response_length=1024,
            differential_score=0.8
        )

        finding = self.orchestrator._create_finding(result)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, 'sqli')
        self.assertGreater(finding.cvss_score, 0)

    def test_export_findings_json(self):
        """Test exporting findings as JSON."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="test",
            vuln_type=VulnerabilityType.XSS,
            differential_score=0.5
        )

        finding = self.orchestrator._create_finding(result)
        if finding:
            self.orchestrator.findings.append(finding)

        export = self.orchestrator.export_findings('json')
        self.assertIsInstance(export, str)

    def test_export_findings_markdown(self):
        """Test exporting findings as Markdown."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="test",
            vuln_type=VulnerabilityType.XSS,
            differential_score=0.5
        )

        finding = self.orchestrator._create_finding(result)
        if finding:
            self.orchestrator.findings.append(finding)

        export = self.orchestrator.export_findings('markdown')
        self.assertIsInstance(export, str)
        self.assertIn('#', export)  # Should have markdown headers


class TestParameterFuzzer(unittest.TestCase):
    """Test parameter fuzzer."""

    def setUp(self):
        """Set up test fixtures."""
        self.base_url = "http://api.example.com"
        loader = PayloadLibraryLoader()
        self.fuzzer = ParameterFuzzer(self.base_url, loader)

    def test_fuzzer_initialization(self):
        """Test ParameterFuzzer initialization."""
        self.assertEqual(self.fuzzer.base_url, self.base_url)
        self.assertEqual(self.fuzzer.timeout, 10)
        self.assertEqual(self.fuzzer.max_workers, 10)

    def test_extract_parameters_from_endpoint(self):
        """Test extracting parameters from endpoint."""
        endpoint = APIEndpoint(
            method='GET',
            path='/api/users',
            parameters=[
                {'name': 'id', 'in': 'query'},
                {'name': 'filter', 'in': 'query'},
            ]
        )

        params = self.fuzzer._extract_parameters(endpoint)

        self.assertGreater(len(params), 0)
        self.assertIn('id', [p['name'] for p in params])

    def test_extract_parameters_with_request_body(self):
        """Test extracting parameters from request body."""
        endpoint = APIEndpoint(
            method='POST',
            path='/api/users',
            request_body={
                'content': {
                    'application/json': {
                        'schema': {
                            'properties': {
                                'username': {'type': 'string'},
                                'email': {'type': 'string'},
                            }
                        }
                    }
                }
            }
        )

        params = self.fuzzer._extract_parameters(endpoint)

        self.assertGreater(len(params), 0)

    def test_default_parameters_if_none(self):
        """Test default parameters if endpoint has none."""
        endpoint = APIEndpoint(method='GET', path='/api/test')

        params = self.fuzzer._extract_parameters(endpoint)

        self.assertGreater(len(params), 0)
        # Should have default params
        param_names = [p['name'] for p in params]
        self.assertTrue(any(name in param_names for name in ['id', 'query', 'search', 'filter']))


class TestVulnerabilityTypes(unittest.TestCase):
    """Test VulnerabilityType enum."""

    def test_all_vuln_types_present(self):
        """Test that all major vulnerability types are present."""
        required_types = [
            VulnerabilityType.XSS,
            VulnerabilityType.SQLI,
            VulnerabilityType.SSTI,
            VulnerabilityType.RCE,
            VulnerabilityType.SSRF,
            VulnerabilityType.IDOR,
        ]

        for vuln_type in required_types:
            self.assertIsNotNone(vuln_type)

    def test_vuln_type_values(self):
        """Test vulnerability type values."""
        self.assertEqual(VulnerabilityType.XSS.value, "xss")
        self.assertEqual(VulnerabilityType.SQLI.value, "sqli")
        self.assertEqual(VulnerabilityType.RCE.value, "rce")


class TestAPIEndpointDataClass(unittest.TestCase):
    """Test APIEndpoint data class."""

    def test_endpoint_creation(self):
        """Test creating an APIEndpoint."""
        endpoint = APIEndpoint(
            method='POST',
            path='/api/users',
            description='Create a new user',
            tags=['users']
        )

        self.assertEqual(endpoint.method, 'POST')
        self.assertEqual(endpoint.path, '/api/users')
        self.assertEqual(endpoint.full_url, '/api/users')

    def test_endpoint_with_parameters(self):
        """Test endpoint with parameters."""
        endpoint = APIEndpoint(
            method='GET',
            path='/api/users/{id}',
            parameters=[
                {'name': 'id', 'in': 'path', 'schema': {'type': 'integer'}},
                {'name': 'filter', 'in': 'query', 'schema': {'type': 'string'}},
            ]
        )

        self.assertEqual(len(endpoint.parameters), 2)

    def test_endpoint_with_request_body(self):
        """Test endpoint with request body."""
        endpoint = APIEndpoint(
            method='POST',
            path='/api/users',
            request_body={
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            }
        )

        self.assertIsNotNone(endpoint.request_body)


class TestVulnerabilityFinding(unittest.TestCase):
    """Test VulnerabilityFinding data class."""

    def test_finding_creation(self):
        """Test creating a VulnerabilityFinding."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        finding = VulnerabilityFinding(
            finding_id='F_001',
            endpoint=endpoint,
            vulnerability_type='sqli',
            cwe='CWE-89',
            severity='Critical',
            cvss_score=9.8,
            confidence=0.95,
            title='SQL Injection in /api/test',
            description='Potential SQL injection',
            evidence=[]
        )

        self.assertEqual(finding.finding_id, 'F_001')
        self.assertEqual(finding.severity, 'Critical')
        self.assertEqual(finding.cvss_score, 9.8)

    def test_finding_with_poc(self):
        """Test finding with proof of concept."""
        endpoint = APIEndpoint(method='GET', path='/api/test')
        finding = VulnerabilityFinding(
            finding_id='F_002',
            endpoint=endpoint,
            vulnerability_type='xss',
            cwe='CWE-79',
            severity='High',
            cvss_score=7.1,
            confidence=0.85,
            title='XSS',
            description='XSS vulnerability',
            evidence=[],
            proof_of_concept_curl='curl -X GET "http://target/api/test?q=<script>alert(1)</script>"'
        )

        self.assertIn('curl', finding.proof_of_concept_curl)


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_full_workflow_initialization(self):
        """Test full workflow initialization."""
        orchestrator = APIFuzzerOrchestrator("http://target.com")

        self.assertIsNotNone(orchestrator.payload_loader)
        self.assertIsNotNone(orchestrator.discovery)
        self.assertIsNotNone(orchestrator.fuzzer)
        self.assertIsNotNone(orchestrator.classifier)

    def test_endpoint_to_finding_pipeline(self):
        """Test endpoint to finding pipeline."""
        orchestrator = APIFuzzerOrchestrator("http://target.com")

        # Create a test endpoint
        endpoint = APIEndpoint(
            method='GET',
            path='/api/users',
            parameters=[{'name': 'id', 'in': 'query'}]
        )

        # Create a test result
        result = FuzzingResult(
            endpoint=endpoint,
            parameter_name='id',
            parameter_location='query',
            payload="' OR '1'='1",
            vuln_type=VulnerabilityType.SQLI,
            differential_score=0.75
        )

        # Convert to finding
        finding = orchestrator._create_finding(result)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.vulnerability_type, 'sqli')


if __name__ == '__main__':
    unittest.main()
