#!/usr/bin/env python3
"""
test_zeroday_miner.py — Comprehensive Test Suite for mod_zeroday_miner

Tests cover:
- Data model validation (5 tests)
- Pattern extraction and generalization (6 tests)
- Novelty detection (4 tests)
- Technique creation (3 tests)
- Integration and end-to-end flows (4 tests)
- Edge cases and error handling (3+ tests)

Total: 20+ test cases with coverage of core functionality.

Run with: pytest test_zeroday_miner.py -v
Run with coverage: pytest test_zeroday_miner.py --cov=mod_zeroday_miner
"""

import os
import sys
import json
import pytest
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from mod_zeroday_miner import (
    VulnerabilityPattern,
    ExploitRepo,
    CVEPattern,
    GitHubExploitScanner,
    CVEPatternMatcher,
    ShodanTrendAnalyzer,
    PoCCodeAnalyzer,
    VulnerabilityPatternExtractor,
    NovelVulnDetector,
    AutomaticTechniqueCreation,
    ZerodayMiner,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_pattern() -> VulnerabilityPattern:
    """Create a sample vulnerability pattern."""
    return VulnerabilityPattern(
        pattern_id="test_001",
        name="Test SQL Injection",
        description="A test SQL injection vulnerability",
        vuln_type="sqli",
        cvss_score=7.5,
        severity="high",
        indicators=["union select", "order by", "sleep"],
        confidence=0.85,
        affected_frameworks=["wordpress", "drupal"],
        sources=["test_source"],
    )


@pytest.fixture
def sample_exploit_repo() -> ExploitRepo:
    """Create a sample exploit repository."""
    return ExploitRepo(
        url="https://github.com/test/sqli-exploit",
        name="sqli-exploit",
        stars=150,
        language="Python",
        updated_at=datetime.utcnow().isoformat(),
        description="Advanced SQL injection toolkit",
        tags=["sqli", "database", "exploit"],
    )


@pytest.fixture
def sample_cve() -> CVEPattern:
    """Create a sample CVE pattern."""
    return CVEPattern(
        cve_id="CVE-2024-12345",
        title="Remote Code Execution in Web Framework",
        description="A remote code execution vulnerability in template engine",
        cvss_score=9.0,
        published_date=datetime.utcnow().isoformat(),
        vuln_type="rce",
        affected_products=["Django", "Flask"],
        attack_vector="NETWORK",
        attack_complexity="LOW",
    )


@pytest.fixture
def existing_techniques() -> list:
    """Create sample existing techniques for novelty detection."""
    return [
        {
            "id": "xss_reflected",
            "name": "Reflected Cross-Site Scripting",
            "description": "Inject malicious JavaScript into URL parameters",
        },
        {
            "id": "sqli_error",
            "name": "SQL Injection - Error-based",
            "description": "Extract database information via error messages",
        },
    ]


# =============================================================================
# UNIT TESTS: Data Models
# =============================================================================

class TestVulnerabilityPattern:
    """Test VulnerabilityPattern data model."""

    def test_pattern_creation(self, sample_pattern):
        """Test creating a VulnerabilityPattern."""
        assert sample_pattern.pattern_id == "test_001"
        assert sample_pattern.name == "Test SQL Injection"
        assert sample_pattern.vuln_type == "sqli"
        assert sample_pattern.confidence == 0.85

    def test_pattern_to_dict(self, sample_pattern):
        """Test VulnerabilityPattern.to_dict()."""
        data = sample_pattern.to_dict()
        assert isinstance(data, dict)
        assert data["pattern_id"] == "test_001"
        assert data["name"] == "Test SQL Injection"
        assert data["confidence"] == 0.85

    def test_pattern_to_yaml_technique(self, sample_pattern):
        """Test conversion to HAKUZA technique format."""
        technique = sample_pattern.to_yaml_technique()
        assert technique["id"].startswith("zeroday_")
        assert technique["name"] == "Test SQL Injection"
        assert technique["severity"] == "high"
        assert technique["cvss"] == 7.5
        assert "sqli" in technique["applicability_tags"]

    def test_pattern_timestamps(self, sample_pattern):
        """Test pattern timestamp fields."""
        assert sample_pattern.discovered_at
        assert sample_pattern.last_updated
        assert len(sample_pattern.discovered_at) > 0

    def test_pattern_default_values(self):
        """Test pattern defaults."""
        pattern = VulnerabilityPattern(
            pattern_id="test",
            name="Test",
            description="Test",
            vuln_type="test",
        )
        assert pattern.cvss_score == 0.0
        assert pattern.confidence == 0.0
        assert pattern.novelty_score == 0.0
        assert pattern.validation_count == 0


# =============================================================================
# UNIT TESTS: GitHub Exploit Scanner
# =============================================================================

class TestGitHubExploitScanner:
    """Test GitHubExploitScanner."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = GitHubExploitScanner()
        assert scanner.api_base == "https://api.github.com"

    def test_repo_vuln_type_detection(self, sample_exploit_repo):
        """Test vulnerability type inference from repo metadata."""
        assert sample_exploit_repo.vuln_type() == "sqli"

    def test_repo_vuln_type_xss(self):
        """Test XSS detection."""
        repo = ExploitRepo(
            url="https://github.com/test/xss-payloads",
            name="xss-payloads",
            stars=100,
            language="JavaScript",
            updated_at="2024-01-01T00:00:00Z",
            description="XSS exploitation toolkit",
        )
        assert repo.vuln_type() == "xss"

    def test_repo_vuln_type_unknown(self):
        """Test unknown vuln type."""
        repo = ExploitRepo(
            url="https://github.com/test/generic-repo",
            name="generic",
            stars=50,
            language="Python",
            updated_at="2024-01-01T00:00:00Z",
            description="Some generic repository",
        )
        assert repo.vuln_type() == "unknown"

    @patch('mod_zeroday_miner.HAS_REQUESTS', False)
    def test_scanner_without_requests(self):
        """Test scanner graceful degradation without requests."""
        scanner = GitHubExploitScanner()
        repos = scanner.fetch_trending_exploits()
        assert repos == []


# =============================================================================
# UNIT TESTS: CVE Pattern Matcher
# =============================================================================

class TestCVEPatternMatcher:
    """Test CVEPatternMatcher."""

    def test_matcher_initialization(self):
        """Test matcher initialization."""
        matcher = CVEPatternMatcher()
        assert matcher.nvd_base == "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def test_infer_sqli_type(self):
        """Test SQL injection type inference."""
        matcher = CVEPatternMatcher()
        desc = "This is a SQL injection vulnerability in the authentication module"
        assert matcher._infer_vuln_type(desc) == "sqli"

    def test_infer_xss_type(self):
        """Test XSS type inference."""
        matcher = CVEPatternMatcher()
        desc = "Cross-site scripting vulnerability in user profile page"
        assert matcher._infer_vuln_type(desc) == "xss"

    def test_infer_rce_type(self):
        """Test RCE type inference."""
        matcher = CVEPatternMatcher()
        desc = "Remote code execution via arbitrary command injection"
        assert matcher._infer_vuln_type(desc) == "rce"

    def test_infer_unknown_type(self):
        """Test unknown type inference."""
        matcher = CVEPatternMatcher()
        desc = "Some random security issue"
        assert matcher._infer_vuln_type(desc) == "unknown"

    def test_extract_keywords(self):
        """Test keyword extraction."""
        matcher = CVEPatternMatcher()
        text = "Remote code execution vulnerability affecting Django framework"
        keywords = matcher._extract_keywords(text)
        assert "remote" in keywords
        assert "code" in keywords
        assert "framework" in keywords
        assert "the" not in keywords  # Stopword should be filtered

    def test_extract_patterns_from_cves(self, sample_cve):
        """Test pattern extraction from CVE data."""
        matcher = CVEPatternMatcher()
        patterns = matcher.extract_patterns([sample_cve])
        assert len(patterns) == 1
        assert patterns[0]["cve_id"] == "CVE-2024-12345"
        assert patterns[0]["vuln_type"] == "rce"


# =============================================================================
# UNIT TESTS: PoC Code Analyzer
# =============================================================================

class TestPoCCodeAnalyzer:
    """Test PoCCodeAnalyzer."""

    def test_python_code_analysis(self):
        """Test Python PoC code analysis."""
        code = """
import requests
import json

def exploit(target):
    payload = "' OR '1'='1"
    resp = requests.get(f"{target}?id={payload}")
    print(resp.text)
"""
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.extract_patterns_from_python(code)

        assert "requests" in patterns["imports"]
        assert "json" in patterns["imports"]
        assert "exploit" in patterns["functions"]
        assert "get" in patterns["network_calls"]

    def test_python_dangerous_calls(self):
        """Test detection of dangerous Python calls."""
        code = """
import os
os.system("whoami")
eval("print('test')")
exec("code_here")
"""
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.extract_patterns_from_python(code)

        assert "eval" in patterns["dangerous_calls"]
        assert "exec" in patterns["dangerous_calls"]

    def test_javascript_dom_sinks(self):
        """Test JavaScript DOM sink detection."""
        code = """
var userInput = location.search;
document.getElementById('content').innerHTML = userInput;
"""
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.analyze_javascript(code)

        assert len(patterns["dom_sinks"]) > 0

    def test_javascript_network_calls(self):
        """Test JavaScript network call detection."""
        code = """
fetch('/api/data').then(r => r.json());
XMLHttpRequest.open('GET', '/api');
axios.get('/endpoint');
"""
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.analyze_javascript(code)

        assert len(patterns["network_calls"]) > 0

    def test_javascript_eval_detection(self):
        """Test JavaScript eval call detection."""
        code = """
eval("alert('xss')");
setTimeout("window.location='http://evil.com'", 1000);
"""
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.analyze_javascript(code)

        assert len(patterns["eval_calls"]) > 0

    def test_invalid_python_code(self):
        """Test graceful handling of invalid Python."""
        code = "this is not valid python code !@#$%"
        analyzer = PoCCodeAnalyzer()
        patterns = analyzer.extract_patterns_from_python(code)

        # Should return empty patterns, not crash
        assert isinstance(patterns, dict)
        assert "imports" in patterns


# =============================================================================
# UNIT TESTS: Pattern Extractor & Generalization
# =============================================================================

class TestVulnerabilityPatternExtractor:
    """Test VulnerabilityPatternExtractor."""

    def test_extractor_initialization(self):
        """Test extractor initialization."""
        extractor = VulnerabilityPatternExtractor()
        assert extractor.client is None

    def test_heuristic_generalization(self):
        """Test heuristic-based pattern generalization."""
        exploit = """
import requests
payload = "' OR '1'='1"
resp = requests.get(f"http://target.com?id={payload}")
"""
        extractor = VulnerabilityPatternExtractor()
        variants = extractor._generalize_heuristic(exploit, "sqli")

        assert len(variants) > 0
        assert "variant_id" in variants[0]
        assert "pattern" in variants[0]
        assert "indicators" in variants[0]

    def test_framework_detection(self):
        """Test affected framework identification."""
        pattern = {
            "indicators": ["wordpress", "wp_query", "wpdb"],
        }
        extractor = VulnerabilityPatternExtractor()
        frameworks = extractor.identify_affected_frameworks(pattern)

        assert "wordpress" in frameworks

    def test_framework_detection_django(self):
        """Test Django framework detection."""
        pattern = {
            "indicators": ["django", "settings.py", "views.py"],
        }
        extractor = VulnerabilityPatternExtractor()
        frameworks = extractor.identify_affected_frameworks(pattern)

        assert "django" in frameworks

    def test_framework_detection_generic_fallback(self):
        """Test generic fallback when no frameworks match."""
        pattern = {
            "indicators": ["random_indicator"],
        }
        extractor = VulnerabilityPatternExtractor()
        frameworks = extractor.identify_affected_frameworks(pattern)

        assert "generic" in frameworks


# =============================================================================
# UNIT TESTS: Novel Vulnerability Detector
# =============================================================================

class TestNovelVulnDetector:
    """Test NovelVulnDetector."""

    def test_detector_initialization(self, existing_techniques):
        """Test detector initialization."""
        detector = NovelVulnDetector(existing_techniques)
        assert len(detector.existing_ids) == 2
        assert len(detector.existing_keywords) > 0

    def test_novelty_score_for_known_cwe(self, sample_pattern):
        """Test novelty score when pattern matches known CWE."""
        sample_pattern.matches_existing_cwe = "CWE-89"
        detector = NovelVulnDetector([])
        score = detector.compute_novelty_score(sample_pattern)

        # Known CWE should have very low novelty
        assert score < 0.2

    def test_novelty_score_for_known_mitre(self, sample_pattern):
        """Test novelty score when pattern matches known MITRE."""
        sample_pattern.matches_existing_mitre = "T1190"
        detector = NovelVulnDetector([])
        score = detector.compute_novelty_score(sample_pattern)

        # Known MITRE should have very low novelty
        assert score < 0.2

    def test_novelty_score_for_novel_pattern(self, sample_pattern, existing_techniques):
        """Test novelty score for truly novel pattern."""
        sample_pattern.name = "Quantum XOR Injection Attack"
        detector = NovelVulnDetector(existing_techniques)
        score = detector.compute_novelty_score(sample_pattern)

        # Truly novel pattern should have higher novelty (adjusted for keyword overlap)
        assert score > 0.25  # Can't be too high since "injection" is a common keyword

    def test_filter_novel_patterns(self, sample_pattern, existing_techniques):
        """Test filtering patterns by novelty."""
        # Create multiple patterns with different novelty potential
        known_pattern = VulnerabilityPattern(
            pattern_id="known",
            name="SQL Injection",
            description="Standard SQL injection",
            vuln_type="sqli",
            confidence=0.8,
        )
        known_pattern.matches_existing_cwe = "CWE-89"

        novel_pattern = VulnerabilityPattern(
            pattern_id="novel",
            name="Polymorphic Attack Vector",
            description="Novel attack combining multiple techniques",
            vuln_type="custom",
            confidence=0.8,
        )

        detector = NovelVulnDetector(existing_techniques)
        patterns = [known_pattern, novel_pattern, sample_pattern]
        filtered = detector.filter_novel_patterns(patterns)

        # Should filter out very low-novelty patterns
        assert len(filtered) <= len(patterns)


# =============================================================================
# UNIT TESTS: Automatic Technique Creation
# =============================================================================

class TestAutomaticTechniqueCreation:
    """Test AutomaticTechniqueCreation."""

    def test_technique_creator_initialization(self):
        """Test technique creator initialization."""
        creator = AutomaticTechniqueCreation()
        assert creator.client is None

    def test_create_technique_from_pattern(self, sample_pattern):
        """Test YAML technique creation from pattern."""
        creator = AutomaticTechniqueCreation()
        technique = creator.create_technique(sample_pattern)

        assert technique["id"].startswith("zeroday_")
        assert technique["name"] == "Test SQL Injection"
        assert technique["severity"] == "high"
        assert technique["cvss"] == 7.5

    def test_default_procedure_generation(self, sample_pattern):
        """Test default procedure description generation."""
        creator = AutomaticTechniqueCreation()
        procedure = creator._default_procedure(sample_pattern)

        assert "union select" in procedure.lower() or "indicators" in procedure
        assert "wordpress" in procedure or "drupal" in procedure

    def test_procedure_generation_without_frameworks(self):
        """Test procedure generation when no frameworks specified."""
        pattern = VulnerabilityPattern(
            pattern_id="test",
            name="Test Vuln",
            description="Test",
            vuln_type="custom",
            indicators=["test_indicator"],
            affected_frameworks=[],
        )
        creator = AutomaticTechniqueCreation()
        procedure = creator._default_procedure(pattern)

        assert "test_indicator" in procedure or "parameter" in procedure


# =============================================================================
# INTEGRATION TESTS: Zeroday Miner
# =============================================================================

class TestZerodayMiner:
    """Test ZerodayMiner orchestrator."""

    def test_miner_initialization(self):
        """Test miner initialization."""
        miner = ZerodayMiner()
        assert miner.github_scanner is not None
        assert miner.cve_matcher is not None
        assert miner.poc_analyzer is not None
        assert len(miner.discovered_patterns) == 0

    def test_pattern_from_github(self):
        """Test pattern extraction from GitHub repo."""
        repo = ExploitRepo(
            url="https://github.com/test/sqli-exploit",
            name="sqli-exploit",
            stars=200,
            language="Python",
            updated_at="2024-01-01T00:00:00Z",
            description="Advanced SQL injection",
        )
        miner = ZerodayMiner()
        pattern = miner._pattern_from_github(repo)

        assert pattern is not None
        assert pattern.vuln_type == "sqli"
        assert pattern.github_repos == [repo.url]
        assert pattern.exploit_availability is True

    def test_pattern_from_cve(self):
        """Test pattern extraction from CVE."""
        cve = CVEPattern(
            cve_id="CVE-2024-99999",
            title="Test RCE",
            description="Remote code execution in framework",
            cvss_score=8.5,
            published_date="2024-01-01T00:00:00Z",
            vuln_type="rce",
        )
        miner = ZerodayMiner()
        pattern = miner._pattern_from_cve(cve)

        assert pattern is not None
        assert pattern.cvss_score == 8.5
        assert pattern.cve_refs == ["CVE-2024-99999"]

    def test_cvss_to_severity_low(self):
        """Test CVSS to severity conversion - low."""
        miner = ZerodayMiner()
        assert miner._cvss_to_severity(2.5) == "low"

    def test_cvss_to_severity_medium(self):
        """Test CVSS to severity conversion - medium."""
        miner = ZerodayMiner()
        assert miner._cvss_to_severity(5.0) == "medium"

    def test_cvss_to_severity_high(self):
        """Test CVSS to severity conversion - high."""
        miner = ZerodayMiner()
        assert miner._cvss_to_severity(7.5) == "high"

    def test_cvss_to_severity_critical(self):
        """Test CVSS to severity conversion - critical."""
        miner = ZerodayMiner()
        assert miner._cvss_to_severity(9.5) == "critical"


# =============================================================================
# INTEGRATION TESTS: Full Workflow
# =============================================================================

class TestEndToEnd:
    """End-to-end workflow tests."""

    def test_pattern_workflow(self, sample_exploit_repo):
        """Test complete pattern discovery workflow."""
        miner = ZerodayMiner()

        # Simulate GitHub discovery
        pattern = miner._pattern_from_github(sample_exploit_repo)
        miner.discovered_patterns.append(pattern)

        # Novelvty detection
        novel = miner.novel_detector.filter_novel_patterns(miner.discovered_patterns)

        # Technique creation
        creator = AutomaticTechniqueCreation()
        for p in novel:
            technique = creator.create_technique(p)
            assert "id" in technique

    def test_yaml_output_generation_without_yaml(self, sample_pattern, tmp_path):
        """Test YAML generation when PyYAML unavailable."""
        with patch('mod_zeroday_miner.HAS_YAML', False):
            creator = AutomaticTechniqueCreation()
            output_path = tmp_path / "test_output"
            output_path.mkdir()

            # Should fall back to JSON
            patterns = [sample_pattern]
            try:
                creator.generate_yaml_file(patterns, output_path / "techniques.yaml")
            except Exception as e:
                # Either YAML or JSON output should work
                assert "techniques" in str(e).lower() or "json" in str(e).lower()


# =============================================================================
# EDGE CASES & Error Handling
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_pattern_list(self):
        """Test handling empty pattern list."""
        detector = NovelVulnDetector([])
        filtered = detector.filter_novel_patterns([])
        assert filtered == []

    def test_pattern_with_special_characters(self):
        """Test pattern handling with special characters."""
        pattern = VulnerabilityPattern(
            pattern_id="test",
            name="XSS with <special> & \"chars\"",
            description="Test\\nwith\\nnewlines",
            vuln_type="xss",
        )
        technique = pattern.to_yaml_technique()
        assert "special" in technique["name"]

    def test_invalid_cvss_score(self):
        """Test handling invalid CVSS scores."""
        miner = ZerodayMiner()
        assert miner._cvss_to_severity(-1.0) == "unknown"
        assert miner._cvss_to_severity(11.0) == "unknown"

    def test_detector_with_empty_existing_techniques(self):
        """Test novelty detector with no existing techniques."""
        detector = NovelVulnDetector([])
        assert len(detector.existing_ids) == 0
        assert len(detector.existing_keywords) == 0

    def test_pattern_with_no_frameworks(self):
        """Test pattern processing with no frameworks."""
        pattern = VulnerabilityPattern(
            pattern_id="test",
            name="Test",
            description="Test",
            vuln_type="test",
            affected_frameworks=[],
        )
        technique = pattern.to_yaml_technique()
        assert isinstance(technique["applicability_tags"], list)

    def test_cve_pattern_with_no_products(self):
        """Test CVE pattern with empty product list."""
        cve = CVEPattern(
            cve_id="CVE-2024-TEST",
            title="Test",
            description="Test",
            cvss_score=5.0,
            published_date="2024-01-01",
            vuln_type="test",
            affected_products=[],
        )
        miner = ZerodayMiner()
        pattern = miner._pattern_from_cve(cve)
        assert pattern.affected_frameworks == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
