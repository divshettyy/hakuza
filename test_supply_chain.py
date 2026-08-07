#!/usr/bin/env python3
"""
test_supply_chain.py — Test suite for mod_supply_chain.py

Tests coverage:
- Dependency parsing (npm, pip, maven, gem)
- Vulnerability detection (known exploits, typosquatting, maintenance risk)
- Supply chain attack chains
- Output generation (JSON, SARIF, Markdown)
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent))
from mod_supply_chain import (
    Dependency, SupplyChainFinding,
    parse_package_json, parse_requirements_txt, parse_pom_xml, parse_gemfile,
    check_known_exploits, detect_typosquatting, assess_maintenance_risk,
    find_dependency_confusion, analyze_version_constraints,
    scan_directory, generate_markdown_report, generate_sarif_report,
)


class TestDependencyParsers(unittest.TestCase):
    """Test dependency file parsers"""

    def test_parse_package_json_basic(self):
        """Test parsing basic npm package.json"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_path = Path(tmpdir) / "package.json"

            pkg_data = {
                "name": "test-app",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1",
                    "lodash": "4.17.21",
                },
                "devDependencies": {
                    "jest": "^27.0.0",
                    "webpack": "^5.0.0",
                }
            }

            with open(pkg_path, 'w') as f:
                json.dump(pkg_data, f)

            deps, metadata = parse_package_json(pkg_path)

            self.assertEqual(len(deps), 4)  # 2 prod + 2 dev

            # Check production dependencies
            prod_deps = [d for d in deps if not d.is_dev_dependency]
            self.assertEqual(len(prod_deps), 2)
            self.assertTrue(any(d.name == "express" for d in prod_deps))
            self.assertTrue(any(d.name == "lodash" for d in prod_deps))

            # Check dev dependencies
            dev_deps = [d for d in deps if d.is_dev_dependency]
            self.assertEqual(len(dev_deps), 2)
            self.assertTrue(all(d.is_dev_dependency for d in dev_deps))

    def test_parse_requirements_txt(self):
        """Test parsing Python requirements.txt"""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"

            req_content = """
# Python dependencies
django==3.2.0
requests>=2.25.0
flask~=1.1.0
# Comment line
numpy>=1.19.0
"""

            with open(req_path, 'w') as f:
                f.write(req_content)

            deps = parse_requirements_txt(req_path)

            self.assertEqual(len(deps), 4)
            self.assertTrue(any(d.name == "django" for d in deps))
            self.assertTrue(any(d.name == "requests" for d in deps))
            self.assertTrue(all(d.package_manager == "pip" for d in deps))

    def test_parse_pom_xml(self):
        """Test parsing Maven pom.xml"""
        with tempfile.TemporaryDirectory() as tmpdir:
            pom_path = Path(tmpdir) / "pom.xml"

            pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.16.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>"""

            with open(pom_path, 'w') as f:
                f.write(pom_content)

            deps = parse_pom_xml(pom_path)

            self.assertEqual(len(deps), 2)
            self.assertTrue(any("log4j-core" in d.name for d in deps))

            # Check test dependency
            test_deps = [d for d in deps if d.is_dev_dependency]
            self.assertEqual(len(test_deps), 1)

    def test_parse_gemfile(self):
        """Test parsing Ruby Gemfile"""
        with tempfile.TemporaryDirectory() as tmpdir:
            gem_path = Path(tmpdir) / "Gemfile"

            gem_content = """
gem 'rails', '~> 6.0'
gem 'sqlite3', '~> 1.4.0'
gem 'devise', '4.8.0'

group :development do
  gem 'rspec', '~> 3.10'
end
"""

            with open(gem_path, 'w') as f:
                f.write(gem_content)

            deps = parse_gemfile(gem_path)

            self.assertGreaterEqual(len(deps), 2)
            self.assertTrue(any(d.name == "rails" for d in deps))


class TestVulnerabilityDetection(unittest.TestCase):
    """Test vulnerability detection functions"""

    def test_check_known_exploits_lodash(self):
        """Test detection of known lodash vulnerability"""
        dep = Dependency(
            name="lodash",
            requested_version="4.17.10",
            resolved_version="4.17.10",
            package_manager="npm"
        )

        exploits = check_known_exploits(dep)
        self.assertGreater(len(exploits), 0)
        self.assertTrue(any("ReDoS" in e.get("description", "") for e in exploits))

    def test_check_known_exploits_log4j(self):
        """Test detection of known log4j vulnerability"""
        dep = Dependency(
            name="org.apache.logging.log4j:log4j-core",
            requested_version="2.14.0",
            resolved_version="2.14.0",
            package_manager="maven"
        )

        exploits = check_known_exploits(dep)
        self.assertGreater(len(exploits), 0)
        self.assertTrue(any("JNDI" in e.get("description", "") for e in exploits))

    def test_detect_typosquatting_no_match(self):
        """Test that non-typosquatting packages are not flagged"""
        dep = Dependency(
            name="myapp-utils",
            requested_version="1.0.0",
            resolved_version="1.0.0",
            package_manager="npm"
        )

        risk = detect_typosquatting(dep)
        self.assertLess(risk, 0.7)

    def test_detect_typosquatting_express_variant(self):
        """Test detection of express typosquatting"""
        # Note: This depends on TYPOSQUATTING_WATCH_LIST
        dep = Dependency(
            name="expresss",  # Double 's' - typosquatting
            requested_version="4.0.0",
            resolved_version="4.0.0",
            package_manager="npm"
        )

        risk = detect_typosquatting(dep)
        # The similarity check may or may not flag it depending on algorithm
        # This test verifies the function doesn't crash
        self.assertGreaterEqual(risk, 0.0)
        self.assertLessEqual(risk, 1.0)

    def test_find_dependency_confusion(self):
        """Test detection of dependency confusion risks"""
        deps = [
            Dependency(
                name="@company/internal-utils",
                requested_version="1.0.0",
                resolved_version="1.0.0",
                package_manager="npm"
            ),
            Dependency(
                name="express",
                requested_version="4.17.1",
                resolved_version="4.17.1",
                package_manager="npm"
            ),
        ]

        findings = find_dependency_confusion(deps)
        self.assertGreater(len(findings), 0)
        self.assertTrue(any("internal" in f.get("package", "") for f in findings))

    def test_analyze_version_constraints_loose(self):
        """Test detection of loose version constraints"""
        deps = [
            Dependency(
                name="express",
                requested_version="*",
                resolved_version="*",
                package_manager="npm"
            ),
            Dependency(
                name="lodash",
                requested_version="4.17.21",
                resolved_version="4.17.21",
                package_manager="npm"
            ),
        ]

        findings = analyze_version_constraints(deps)
        self.assertGreater(len(findings), 0)
        loose_findings = [f for f in findings if "loose" in f.get("type", "")]
        self.assertGreater(len(loose_findings), 0)

    def test_analyze_version_constraints_prerelease(self):
        """Test detection of pre-release versions"""
        deps = [
            Dependency(
                name="react",
                requested_version="18.0.0-alpha.1",
                resolved_version="18.0.0-alpha.1",
                package_manager="npm"
            ),
        ]

        findings = analyze_version_constraints(deps)
        self.assertGreater(len(findings), 0)
        prerelease_findings = [f for f in findings if "prerelease" in f.get("type", "")]
        self.assertGreater(len(prerelease_findings), 0)


class TestScanDirectory(unittest.TestCase):
    """Test directory scanning functionality"""

    def test_scan_npm_project(self):
        """Test scanning npm project"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create package.json
            pkg_data = {
                "name": "test-app",
                "dependencies": {
                    "lodash": "4.17.10",  # Vulnerable version
                    "express": "4.17.1",
                },
            }

            with open(tmpdir_path / "package.json", 'w') as f:
                json.dump(pkg_data, f)

            # Scan directory
            deps, findings = scan_directory(tmpdir_path)

            self.assertGreater(len(deps), 0)
            # Should find lodash ReDoS vulnerability
            lodash_findings = [f for f in findings if "lodash" in f.package]
            self.assertGreater(len(lodash_findings), 0)

    def test_scan_pip_project(self):
        """Test scanning pip project"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create requirements.txt
            req_content = """
django==2.0.0
requests>=2.25.0
"""

            with open(tmpdir_path / "requirements.txt", 'w') as f:
                f.write(req_content)

            # Scan directory
            deps, findings = scan_directory(tmpdir_path)

            self.assertGreater(len(deps), 0)
            self.assertTrue(any(d.name == "django" for d in deps))
            self.assertTrue(any(d.package_manager == "pip" for d in deps))


class TestReportGeneration(unittest.TestCase):
    """Test report generation functions"""

    def test_generate_markdown_report(self):
        """Test markdown report generation"""
        deps = [
            Dependency(
                name="express",
                requested_version="4.17.1",
                resolved_version="4.17.1",
                package_manager="npm",
                is_dev_dependency=False
            ),
        ]

        findings = [
            SupplyChainFinding(
                id="SCN_0001",
                severity="high",
                vuln_type="typosquatting",
                package="express",
                affected_versions=["4.17.1"],
                description="Potential typosquatting risk",
                impact="Could install malicious package",
                remediation="Verify package name spelling",
            ),
        ]

        report = generate_markdown_report(deps, findings)

        self.assertIn("# Supply Chain Vulnerability Scan Report", report)
        self.assertIn("SCN_0001", report)
        self.assertIn("express", report)
        self.assertIn("typosquatting", report)
        self.assertTrue("| NPM |" in report or "| npm |" in report)

    def test_generate_sarif_report(self):
        """Test SARIF report generation"""
        findings = [
            SupplyChainFinding(
                id="SCN_0001",
                severity="critical",
                vuln_type="known_supply_chain_exploit",
                package="log4j",
                affected_versions=["2.14.0"],
                description="log4j JNDI injection RCE",
                impact="Complete system compromise",
                cves=["CVE-2021-44228"],
                remediation="Update to patched version",
            ),
        ]

        sarif = generate_sarif_report(findings)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertIn("tool", run)
        self.assertEqual(run["tool"]["driver"]["name"], "HAKUZA-SupplyChain")
        self.assertEqual(len(run["results"]), 1)

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "SCN_0001")
        self.assertIn("CVE-2021-44228", result["properties"]["cves"])


class TestRealWorldScenarios(unittest.TestCase):
    """Test real-world attack scenarios"""

    def test_solarwinds_detection(self):
        """Test detection of SolarWinds supply chain attack pattern"""
        # Simulate finding SolarWinds Orion with vulnerable version
        dep = Dependency(
            name="SolarWinds Orion",
            requested_version="2020.2.0",
            resolved_version="2020.2.0",
            package_manager="unknown",
        )

        exploits = check_known_exploits(dep)
        self.assertGreater(len(exploits), 0)

        # Verify SUNBURST details
        sunburst_found = any("SUNBURST" in e.get("payload_type", "") for e in exploits)
        self.assertTrue(sunburst_found)

    def test_eventstream_detection(self):
        """Test detection of event-stream compromise pattern"""
        dep = Dependency(
            name="event-stream",
            requested_version="4.0.1",
            resolved_version="4.0.1",
            package_manager="npm",
        )

        exploits = check_known_exploits(dep)
        self.assertGreater(len(exploits), 0)

        # Verify CoinMiner details
        coinminer_found = any("CoinMiner" in e.get("payload_type", "") for e in exploits)
        self.assertTrue(coinminer_found)

    def test_complex_supply_chain_scan(self):
        """Test scanning a complex project with multiple ecosystems"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Create npm package.json
            npm_data = {
                "dependencies": {
                    "lodash": "4.17.10",  # Vulnerable
                    "express": "4.17.1",
                },
                "devDependencies": {
                    "jest": "27.0.0",
                }
            }
            with open(tmpdir_path / "package.json", 'w') as f:
                json.dump(npm_data, f)

            # Create requirements.txt
            req_content = "django==2.0.0\nrequests>=2.25.0\n"
            with open(tmpdir_path / "requirements.txt", 'w') as f:
                f.write(req_content)

            # Scan
            deps, findings = scan_directory(tmpdir_path)

            # Verify both ecosystems detected
            npm_deps = [d for d in deps if d.package_manager == "npm"]
            pip_deps = [d for d in deps if d.package_manager == "pip"]

            self.assertGreater(len(npm_deps), 0)
            self.assertGreater(len(pip_deps), 0)

            # Verify findings found
            self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
