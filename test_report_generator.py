#!/usr/bin/env python3
"""
HAKUZA Test Report Generator
=============================

Generates comprehensive test reports in multiple formats:
- HTML: Interactive test results with charts
- JSON: Machine-readable format for CI/CD
- Markdown: Readable format for documentation
- XML: JUnit format for CI integration

Usage:
    python test_report_generator.py [--format html|json|md|xml]
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import sys
import argparse


class TestReportGenerator:
    """Generate test reports in multiple formats."""

    def __init__(self, results_file="test-results.xml", coverage_file="coverage.json"):
        self.results_file = Path(results_file)
        self.coverage_file = Path(coverage_file)
        self.report_data = self._load_results()
        self.coverage_data = self._load_coverage()

    def _load_results(self) -> Dict[str, Any]:
        """Load test results from JUnit XML."""
        if not self.results_file.exists():
            return {"tests": [], "summary": {}}

        try:
            tree = ET.parse(self.results_file)
            root = tree.getroot()

            tests = []
            for testcase in root.findall(".//testcase"):
                test = {
                    "name": testcase.get("name"),
                    "classname": testcase.get("classname"),
                    "time": float(testcase.get("time", 0)),
                    "status": "passed",
                    "message": None,
                }

                # Check for failures
                failure = testcase.find("failure")
                if failure is not None:
                    test["status"] = "failed"
                    test["message"] = failure.get("message")

                # Check for skips
                skip = testcase.find("skipped")
                if skip is not None:
                    test["status"] = "skipped"
                    test["message"] = skip.get("message")

                tests.append(test)

            # Generate summary
            passed = sum(1 for t in tests if t["status"] == "passed")
            failed = sum(1 for t in tests if t["status"] == "failed")
            skipped = sum(1 for t in tests if t["status"] == "skipped")
            total = len(tests)

            return {
                "tests": tests,
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "skipped": skipped,
                    "success_rate": (passed / total * 100) if total > 0 else 0,
                }
            }
        except Exception as e:
            print(f"Error loading test results: {e}")
            return {"tests": [], "summary": {}}

    def _load_coverage(self) -> Dict[str, Any]:
        """Load coverage data from JSON."""
        if not self.coverage_file.exists():
            return {}

        try:
            with open(self.coverage_file) as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading coverage data: {e}")
            return {}

    def generate_html_report(self, output_file="test_report_generated.html"):
        """Generate HTML report."""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HAKUZA Test Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .content {{
            padding: 40px;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card.passed {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        }}

        .stat-card.failed {{
            background: linear-gradient(135deg, #ff9a56 0%, #ff6a88 100%);
        }}

        .stat-card.skipped {{
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        }}

        .stat-card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
            color: white;
        }}

        .stat-card p {{
            color: white;
            font-weight: 500;
        }}

        .coverage {{
            background: #f5f7fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 40px;
        }}

        .coverage h3 {{
            margin-bottom: 15px;
            color: #333;
        }}

        .progress-bar {{
            background: #e0e0e0;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin-bottom: 10px;
        }}

        .progress-fill {{
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}

        .tests-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        .tests-table th {{
            background: #f5f7fa;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #ddd;
            font-weight: 600;
            color: #333;
        }}

        .tests-table td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}

        .tests-table tr:hover {{
            background: #f9f9f9;
        }}

        .status {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
        }}

        .status.passed {{
            background: #d4edda;
            color: #155724;
        }}

        .status.failed {{
            background: #f8d7da;
            color: #721c24;
        }}

        .status.skipped {{
            background: #fff3cd;
            color: #856404;
        }}

        .footer {{
            background: #f5f7fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>HAKUZA Test Report</h1>
            <p>Comprehensive Test Suite Results</p>
        </div>

        <div class="content">
            <div class="summary">
                <div class="stat-card">
                    <h3>{self.report_data['summary'].get('total', 0)}</h3>
                    <p>Total Tests</p>
                </div>
                <div class="stat-card passed">
                    <h3>{self.report_data['summary'].get('passed', 0)}</h3>
                    <p>Passed</p>
                </div>
                <div class="stat-card failed">
                    <h3>{self.report_data['summary'].get('failed', 0)}</h3>
                    <p>Failed</p>
                </div>
                <div class="stat-card skipped">
                    <h3>{self.report_data['summary'].get('skipped', 0)}</h3>
                    <p>Skipped</p>
                </div>
            </div>

            <div class="coverage">
                <h3>Code Coverage</h3>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {self.coverage_data.get('meta', {}).get('percent_covered', 0)}%">
                        {self.coverage_data.get('meta', {}).get('percent_covered', 0):.1f}%
                    </div>
                </div>
            </div>

            <h3>Test Results</h3>
            <table class="tests-table">
                <thead>
                    <tr>
                        <th>Test Name</th>
                        <th>Class</th>
                        <th>Status</th>
                        <th>Duration (s)</th>
                    </tr>
                </thead>
                <tbody>
"""

        for test in self.report_data['tests'][:50]:  # Show first 50
            html_content += f"""
                    <tr>
                        <td>{test['name']}</td>
                        <td>{test['classname']}</td>
                        <td><span class="status {test['status']}">{test['status'].upper()}</span></td>
                        <td>{test['time']:.3f}</td>
                    </tr>
"""

        html_content += """
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated on """ + datetime.now().isoformat() + """</p>
        </div>
    </div>
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html_content)

        print(f"HTML report generated: {output_file}")

    def generate_json_report(self, output_file="test_report_generated.json"):
        """Generate JSON report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.report_data["summary"],
            "tests": self.report_data["tests"],
            "coverage": self.coverage_data.get("meta", {}),
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"JSON report generated: {output_file}")

    def generate_markdown_report(self, output_file="TEST_REPORT.md"):
        """Generate Markdown report."""
        md_content = f"""# HAKUZA Test Report

**Generated:** {datetime.now().isoformat()}

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {self.report_data['summary'].get('total', 0)} |
| Passed | {self.report_data['summary'].get('passed', 0)} |
| Failed | {self.report_data['summary'].get('failed', 0)} |
| Skipped | {self.report_data['summary'].get('skipped', 0)} |
| Success Rate | {self.report_data['summary'].get('success_rate', 0):.1f}% |

## Coverage

"""
        coverage_percent = self.coverage_data.get('meta', {}).get('percent_covered', 0)
        md_content += f"**Code Coverage:** {coverage_percent:.1f}%\n\n"

        md_content += "## Test Results\n\n"
        md_content += "| Test Name | Status | Duration |\n"
        md_content += "|-----------|--------|----------|\n"

        for test in self.report_data['tests'][:20]:  # First 20
            md_content += f"| {test['name']} | {test['status'].upper()} | {test['time']:.3f}s |\n"

        if len(self.report_data['tests']) > 20:
            md_content += f"\n*... and {len(self.report_data['tests']) - 20} more tests*\n"

        md_content += "\n## Notes\n\n"
        md_content += "- All tests must pass before deployment\n"
        md_content += "- Code coverage must be >= 85%\n"
        md_content += "- Performance tests track baseline metrics\n"

        with open(output_file, 'w') as f:
            f.write(md_content)

        print(f"Markdown report generated: {output_file}")

    def generate_xml_report(self, output_file="test_report_generated.xml"):
        """Generate XML report."""
        root = ET.Element("testsuites")
        root.set("tests", str(self.report_data['summary'].get('total', 0)))
        root.set("failures", str(self.report_data['summary'].get('failed', 0)))
        root.set("skipped", str(self.report_data['summary'].get('skipped', 0)))
        root.set("time", str(sum(t['time'] for t in self.report_data['tests'])))

        testsuite = ET.SubElement(root, "testsuite")
        testsuite.set("name", "HAKUZA Comprehensive Test Suite")
        testsuite.set("tests", str(self.report_data['summary'].get('total', 0)))
        testsuite.set("failures", str(self.report_data['summary'].get('failed', 0)))
        testsuite.set("skipped", str(self.report_data['summary'].get('skipped', 0)))

        for test in self.report_data['tests']:
            testcase = ET.SubElement(testsuite, "testcase")
            testcase.set("name", test['name'])
            testcase.set("classname", test['classname'])
            testcase.set("time", str(test['time']))

            if test['status'] == 'failed':
                failure = ET.SubElement(testcase, "failure")
                failure.set("message", test.get('message', ''))
            elif test['status'] == 'skipped':
                skip = ET.SubElement(testcase, "skipped")
                skip.set("message", test.get('message', ''))

        tree = ET.ElementTree(root)
        tree.write(output_file, encoding='utf-8', xml_declaration=True)

        print(f"XML report generated: {output_file}")

    def generate_all(self):
        """Generate all report formats."""
        print("Generating test reports...")
        self.generate_html_report()
        self.generate_json_report()
        self.generate_markdown_report()
        self.generate_xml_report()
        print("All reports generated successfully!")


def main():
    parser = argparse.ArgumentParser(description="Generate test reports")
    parser.add_argument("--format", choices=["html", "json", "md", "xml", "all"],
                       default="all", help="Report format")
    parser.add_argument("--results", default="test-results.xml",
                       help="Test results file")
    parser.add_argument("--coverage", default="coverage.json",
                       help="Coverage file")

    args = parser.parse_args()

    generator = TestReportGenerator(args.results, args.coverage)

    if args.format == "all":
        generator.generate_all()
    elif args.format == "html":
        generator.generate_html_report()
    elif args.format == "json":
        generator.generate_json_report()
    elif args.format == "md":
        generator.generate_markdown_report()
    elif args.format == "xml":
        generator.generate_xml_report()


if __name__ == "__main__":
    main()
