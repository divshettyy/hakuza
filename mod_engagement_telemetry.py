#!/usr/bin/env python3
"""
HAKUZA Engagement Telemetry Pipeline
=====================================

Real-world pentesting data ingestion and ML training data generation.

Ingests findings from:
- Burp XML/JSON exports
- Nuclei JSON outputs
- Nessus CSV/XML
- Manual findings from HAKUZA database

Tracks:
- Time-to-exploit per technique
- Success rates by target type/configuration
- False positive rates
- Finding depth & quality metrics
- Attack chain effectiveness

Feeds ML model training with high-fidelity historical engagement data.

Usage:
    from mod_engagement_telemetry import EngagementTelemetry

    telemetry = EngagementTelemetry()
    telemetry.load_engagement(engagement_id)
    telemetry.record_finding(finding)
    telemetry.compute_success_rate("sql_injection")

    # CLI: hakuza telemetry --import burp.xml
"""

import sqlite3
import json
import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
import hashlib
import re
from enum import Enum

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

class FindingStatus(Enum):
    """Status of a finding in engagement."""
    DISCOVERED = "discovered"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class TechniqueContext(Enum):
    """Context in which a technique was tested."""
    WEB_APP = "web_app"
    WEB_API = "web_api"
    NETWORK = "network"
    CLOUD = "cloud"
    MOBILE = "mobile"
    THICK_CLIENT = "thick_client"
    IOT = "iot"
    AD = "active_directory"


@dataclass
class Finding:
    """A security finding from an engagement."""
    id: str  # Unique finding ID
    title: str
    severity: str  # critical, high, medium, low, info
    category: str  # SQL injection, XSS, SSRF, etc.
    status: FindingStatus
    url: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    discovered_at: Optional[datetime] = None
    confirmed_at: Optional[datetime] = None
    exploited_at: Optional[datetime] = None
    tool: Optional[str] = None  # nuclei, burp, manual, etc.
    confidence: float = 1.0  # 0.0-1.0
    false_positive_reason: Optional[str] = None
    attack_chain_depth: int = 0  # How many steps to full compromise
    requires_user_interaction: bool = False
    requires_auth: bool = False

    def time_to_exploitation_seconds(self) -> Optional[int]:
        """Calculate time from discovery to exploitation."""
        if self.discovered_at and self.exploited_at:
            delta = self.exploited_at - self.discovered_at
            return int(delta.total_seconds())
        return None

    def time_to_confirmation_seconds(self) -> Optional[int]:
        """Calculate time from discovery to confirmation."""
        if self.discovered_at and self.confirmed_at:
            delta = self.confirmed_at - self.discovered_at
            return int(delta.total_seconds())
        return None


@dataclass
class TechniqueStats:
    """Statistics for a security testing technique."""
    technique_id: str
    technique_name: str
    total_runs: int = 0
    successful_runs: int = 0
    false_positives: int = 0
    avg_time_to_success_seconds: float = 0.0
    contexts_tested: Set[str] = field(default_factory=set)
    severities_found: List[str] = field(default_factory=list)
    avg_confidence: float = 1.0
    target_types: Set[str] = field(default_factory=set)

    @property
    def success_rate(self) -> float:
        """Success rate as percentage."""
        if self.total_runs == 0:
            return 0.0
        return (self.successful_runs / self.total_runs) * 100.0

    @property
    def false_positive_rate(self) -> float:
        """False positive rate as percentage."""
        if self.total_runs == 0:
            return 0.0
        return (self.false_positives / self.total_runs) * 100.0

    @property
    def effectiveness_score(self) -> float:
        """Composite effectiveness: success_rate - (fp_rate * 0.5)."""
        return self.success_rate - (self.false_positive_rate * 0.5)


@dataclass
class EngagementMetrics:
    """High-level metrics for a complete engagement."""
    engagement_id: str
    engagement_name: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    false_positives: int = 0
    confirmed_findings: int = 0
    exploited_findings: int = 0
    techniques_used: Set[str] = field(default_factory=set)
    avg_time_to_confirmation_seconds: float = 0.0
    avg_time_to_exploitation_seconds: float = 0.0
    unique_attack_chains: int = 0
    max_chain_depth: int = 0

    @property
    def duration_hours(self) -> float:
        """Engagement duration in hours."""
        end = self.end_time or datetime.now()
        delta = end - self.start_time
        return delta.total_seconds() / 3600.0

    @property
    def average_finding_severity(self) -> float:
        """Average severity as numeric score (0-5)."""
        if self.total_findings == 0:
            return 0.0
        severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        total_score = (
            self.critical_findings * 5 +
            self.high_findings * 4 +
            self.medium_findings * 3 +
            self.low_findings * 2 +
            self.info_findings * 1
        )
        return total_score / self.total_findings

    @property
    def confirmation_rate(self) -> float:
        """Percentage of findings that were confirmed."""
        if self.total_findings == 0:
            return 0.0
        return (self.confirmed_findings / self.total_findings) * 100.0

    @property
    def exploitation_rate(self) -> float:
        """Percentage of findings that were exploited."""
        if self.total_findings == 0:
            return 0.0
        return (self.exploited_findings / self.total_findings) * 100.0


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY CLASS
# ─────────────────────────────────────────────────────────────────────────────

class EngagementTelemetry:
    """
    Core telemetry engine for tracking engagement outcomes and computing
    statistics for ML model training.
    """

    def __init__(self, db_path: Optional[str] = None):
        """Initialize telemetry system."""
        if db_path is None:
            db_path = str(Path.home() / ".hakuza" / "hakuza.db")

        self.db_path = db_path
        self.findings: Dict[str, Finding] = {}
        self.engagement_metrics: Dict[str, EngagementMetrics] = {}
        self.technique_stats: Dict[str, TechniqueStats] = {}
        self.current_engagement_id: Optional[str] = None

    def record_finding(self, finding: Finding, technique_id: Optional[str] = None) -> None:
        """Record a finding and update stats."""
        self.findings[finding.id] = finding

        # Update engagement metrics if we have current engagement
        if self.current_engagement_id:
            self._update_engagement_metrics(finding, technique_id)

        # Update technique stats
        if technique_id:
            self._update_technique_stats(technique_id, finding)

    def _update_engagement_metrics(self, finding: Finding, technique_id: Optional[str] = None) -> None:
        """Update engagement metrics based on finding."""
        if self.current_engagement_id not in self.engagement_metrics:
            return

        metrics = self.engagement_metrics[self.current_engagement_id]
        metrics.total_findings += 1

        # Count by severity
        severity_map = {
            "critical": "critical_findings",
            "high": "high_findings",
            "medium": "medium_findings",
            "low": "low_findings",
            "info": "info_findings"
        }

        if finding.severity in severity_map:
            field_name = severity_map[finding.severity]
            setattr(metrics, field_name, getattr(metrics, field_name) + 1)

        # Count by status
        if finding.status == FindingStatus.FALSE_POSITIVE:
            metrics.false_positives += 1
        elif finding.status == FindingStatus.CONFIRMED:
            metrics.confirmed_findings += 1
        elif finding.status == FindingStatus.EXPLOITED:
            metrics.exploited_findings += 1

        # Track attack chain depth
        if finding.attack_chain_depth > metrics.max_chain_depth:
            metrics.max_chain_depth = finding.attack_chain_depth

        # Track technique used
        if technique_id:
            metrics.techniques_used.add(technique_id)

    def _update_technique_stats(self, technique_id: str, finding: Finding) -> None:
        """Update technique statistics based on finding."""
        if technique_id not in self.technique_stats:
            # Map technique ID to human name
            tech_name = technique_id.replace("_", " ").title()
            self.technique_stats[technique_id] = TechniqueStats(
                technique_id=technique_id,
                technique_name=tech_name
            )

        stats = self.technique_stats[technique_id]
        stats.total_runs += 1

        # Track success
        if finding.status in (FindingStatus.CONFIRMED, FindingStatus.EXPLOITED):
            stats.successful_runs += 1

            # Track time to success
            if finding.exploited_at:
                time_to_success = finding.time_to_exploitation_seconds()
                if time_to_success is not None:
                    # Running average
                    if stats.avg_time_to_success_seconds == 0.0:
                        stats.avg_time_to_success_seconds = float(time_to_success)
                    else:
                        stats.avg_time_to_success_seconds = (
                            stats.avg_time_to_success_seconds * 0.8 +
                            time_to_success * 0.2
                        )

        # Track false positives
        if finding.status == FindingStatus.FALSE_POSITIVE:
            stats.false_positives += 1

        # Update confidence
        stats.avg_confidence = (
            stats.avg_confidence * 0.9 + finding.confidence * 0.1
        )

        # Track severity found
        if finding.severity not in stats.severities_found:
            stats.severities_found.append(finding.severity)

    def load_engagement(self, engagement_id: str, engagement_name: str, target: str) -> None:
        """Load/initialize an engagement for telemetry."""
        self.current_engagement_id = engagement_id

        self.engagement_metrics[engagement_id] = EngagementMetrics(
            engagement_id=engagement_id,
            engagement_name=engagement_name,
            target=target,
            start_time=datetime.now()
        )

    def finalize_engagement(self) -> Optional[EngagementMetrics]:
        """Finalize current engagement metrics."""
        if not self.current_engagement_id:
            return None

        metrics = self.engagement_metrics.get(self.current_engagement_id)
        if metrics:
            metrics.end_time = datetime.now()

            # Compute averages
            times_to_confirmation = []
            times_to_exploitation = []

            for finding in self.findings.values():
                tc = finding.time_to_confirmation_seconds()
                if tc is not None:
                    times_to_confirmation.append(tc)
                te = finding.time_to_exploitation_seconds()
                if te is not None:
                    times_to_exploitation.append(te)

            if times_to_confirmation:
                metrics.avg_time_to_confirmation_seconds = sum(times_to_confirmation) / len(times_to_confirmation)
            if times_to_exploitation:
                metrics.avg_time_to_exploitation_seconds = sum(times_to_exploitation) / len(times_to_exploitation)

        return metrics

    def get_technique_success_rate(self, technique_id: str) -> float:
        """Get success rate for a specific technique."""
        if technique_id not in self.technique_stats:
            return 0.0
        return self.technique_stats[technique_id].success_rate

    def get_technique_stats(self, technique_id: str) -> Optional[TechniqueStats]:
        """Get detailed stats for a technique."""
        return self.technique_stats.get(technique_id)

    def get_all_technique_stats(self) -> Dict[str, TechniqueStats]:
        """Get stats for all techniques."""
        return self.technique_stats

    def get_engagement_metrics(self, engagement_id: str) -> Optional[EngagementMetrics]:
        """Get metrics for a specific engagement."""
        return self.engagement_metrics.get(engagement_id)

    def save_to_database(self) -> None:
        """Persist telemetry data to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Ensure telemetry tables exist
            self._create_telemetry_tables(cursor)

            # Save technique stats
            for tech_id, stats in self.technique_stats.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO technique_telemetry
                    (technique_id, technique_name, total_runs, successful_runs, false_positives,
                     avg_time_to_success, avg_confidence, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    stats.technique_id,
                    stats.technique_name,
                    stats.total_runs,
                    stats.successful_runs,
                    stats.false_positives,
                    stats.avg_time_to_success_seconds,
                    stats.avg_confidence,
                    datetime.now().isoformat()
                ))

            # Save engagement metrics
            for eng_id, metrics in self.engagement_metrics.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO engagement_telemetry
                    (engagement_id, engagement_name, target, start_time, end_time,
                     total_findings, critical, high, medium, low, info, false_positives,
                     confirmed, exploited, avg_confirmation_time, avg_exploitation_time,
                     max_chain_depth, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metrics.engagement_id,
                    metrics.engagement_name,
                    metrics.target,
                    metrics.start_time.isoformat(),
                    metrics.end_time.isoformat() if metrics.end_time else None,
                    metrics.total_findings,
                    metrics.critical_findings,
                    metrics.high_findings,
                    metrics.medium_findings,
                    metrics.low_findings,
                    metrics.info_findings,
                    metrics.false_positives,
                    metrics.confirmed_findings,
                    metrics.exploited_findings,
                    metrics.avg_time_to_confirmation_seconds,
                    metrics.avg_time_to_exploitation_seconds,
                    metrics.max_chain_depth,
                    datetime.now().isoformat()
                ))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving telemetry to database: {e}")

    def _create_telemetry_tables(self, cursor) -> None:
        """Create telemetry tables if they don't exist."""
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS technique_telemetry (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT NOT NULL,
                total_runs INTEGER DEFAULT 0,
                successful_runs INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                avg_time_to_success REAL DEFAULT 0.0,
                avg_confidence REAL DEFAULT 1.0,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS engagement_telemetry (
                engagement_id TEXT PRIMARY KEY,
                engagement_name TEXT NOT NULL,
                target TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                total_findings INTEGER DEFAULT 0,
                critical INTEGER DEFAULT 0,
                high INTEGER DEFAULT 0,
                medium INTEGER DEFAULT 0,
                low INTEGER DEFAULT 0,
                info INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                confirmed INTEGER DEFAULT 0,
                exploited INTEGER DEFAULT 0,
                avg_confirmation_time REAL DEFAULT 0.0,
                avg_exploitation_time REAL DEFAULT 0.0,
                max_chain_depth INTEGER DEFAULT 0,
                updated_at TEXT
            );
        """)


# ─────────────────────────────────────────────────────────────────────────────
# IMPORT HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

class EngagementImporter:
    """
    Import engagement data from various sources (Burp, Nuclei, Nessus, etc.)
    """

    def __init__(self, telemetry: EngagementTelemetry):
        """Initialize importer."""
        self.telemetry = telemetry

    def import_burp_xml(self, filepath: str) -> Tuple[int, List[str]]:
        """
        Import findings from Burp Suite XML export.

        Returns:
            (num_imported, error_list)
        """
        findings_imported = 0
        errors = []

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for issue in root.findall(".//issue"):
                try:
                    finding = self._parse_burp_issue(issue)
                    if finding:
                        self.telemetry.record_finding(finding, "burp_import")
                        findings_imported += 1
                except Exception as e:
                    errors.append(f"Error parsing Burp issue: {e}")

        except Exception as e:
            errors.append(f"Error reading Burp XML: {e}")

        return findings_imported, errors

    def import_nuclei_json(self, filepath: str) -> Tuple[int, List[str]]:
        """
        Import findings from Nuclei JSON output (one per line).

        Returns:
            (num_imported, error_list)
        """
        findings_imported = 0
        errors = []

        try:
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        data = json.loads(line.strip())
                        finding = self._parse_nuclei_result(data)
                        if finding:
                            self.telemetry.record_finding(finding, data.get("template-id", "nuclei"))
                            findings_imported += 1
                    except json.JSONDecodeError:
                        errors.append(f"Line {line_num}: Invalid JSON")
                    except Exception as e:
                        errors.append(f"Line {line_num}: {e}")

        except Exception as e:
            errors.append(f"Error reading Nuclei JSON: {e}")

        return findings_imported, errors

    def import_nessus_csv(self, filepath: str) -> Tuple[int, List[str]]:
        """
        Import findings from Nessus CSV export.

        Returns:
            (num_imported, error_list)
        """
        findings_imported = 0
        errors = []

        try:
            import csv

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    try:
                        finding = self._parse_nessus_row(row)
                        if finding:
                            self.telemetry.record_finding(finding, "nessus")
                            findings_imported += 1
                    except Exception as e:
                        errors.append(f"Error parsing Nessus row: {e}")

        except Exception as e:
            errors.append(f"Error reading Nessus CSV: {e}")

        return findings_imported, errors

    def _parse_burp_issue(self, issue_elem) -> Optional[Finding]:
        """Parse a Burp Suite issue XML element."""
        try:
            title = issue_elem.findtext("name", "Unknown")
            severity = issue_elem.findtext("severity", "low").lower()
            description = issue_elem.findtext("description", "")
            evidence = issue_elem.findtext("evidence", "")
            url = issue_elem.findtext("url", "")

            # Map Burp severity to standard
            severity_map = {
                "informational": "info",
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical"
            }
            severity = severity_map.get(severity, "medium")

            # Extract CWE if available
            cwe = None
            if "<CWE>" in description:
                match = re.search(r'CWE-(\d+)', description)
                if match:
                    cwe = f"CWE-{match.group(1)}"

            finding_id = hashlib.md5(f"{title}{url}".encode()).hexdigest()[:16]

            return Finding(
                id=finding_id,
                title=title,
                severity=severity,
                category="Web Security",
                status=FindingStatus.DISCOVERED,
                url=url,
                description=description,
                evidence=evidence,
                discovered_at=datetime.now(),
                tool="burp",
                cwe=cwe
            )
        except Exception as e:
            print(f"Error parsing Burp issue: {e}")
            return None

    def _parse_nuclei_result(self, data: Dict) -> Optional[Finding]:
        """Parse a Nuclei JSON result."""
        try:
            title = data.get("info", {}).get("name", "Unknown")
            severity = data.get("info", {}).get("severity", "info").lower()
            template_id = data.get("template-id", "nuclei")
            url = data.get("matched-at", "")
            description = data.get("info", {}).get("description", "")

            # Get CWE from tags
            cwe = None
            tags = data.get("info", {}).get("tags", [])
            if isinstance(tags, list):
                for tag in tags:
                    if "cwe" in tag.lower():
                        match = re.search(r'cwe[\s-]*(\d+)', tag, re.I)
                        if match:
                            cwe = f"CWE-{match.group(1)}"
                            break

            finding_id = hashlib.md5(f"{title}{url}".encode()).hexdigest()[:16]

            return Finding(
                id=finding_id,
                title=title,
                severity=severity,
                category=template_id.replace("-", " ").title(),
                status=FindingStatus.DISCOVERED,
                url=url,
                description=description,
                discovered_at=datetime.now(),
                tool="nuclei",
                cwe=cwe,
                confidence=0.8  # Nuclei is generally reliable
            )
        except Exception as e:
            print(f"Error parsing Nuclei result: {e}")
            return None

    def _parse_nessus_row(self, row: Dict) -> Optional[Finding]:
        """Parse a Nessus CSV row."""
        try:
            title = row.get("Name", "Unknown")
            severity = row.get("Severity", "Medium").lower()
            description = row.get("Description", "")
            solution = row.get("Solution", "")
            plugin_id = row.get("Plugin ID", "")
            host = row.get("Host", "")

            # Extract CWE if available
            cwe = None
            if "CWE" in description:
                match = re.search(r'CWE-(\d+)', description)
                if match:
                    cwe = f"CWE-{match.group(1)}"

            finding_id = hashlib.md5(f"{title}{host}{plugin_id}".encode()).hexdigest()[:16]

            return Finding(
                id=finding_id,
                title=title,
                severity=severity,
                category="Network/Vulnerability",
                status=FindingStatus.DISCOVERED,
                url=host,
                description=description,
                discovered_at=datetime.now(),
                tool="nessus",
                cwe=cwe,
                confidence=0.9
            )
        except Exception as e:
            print(f"Error parsing Nessus row: {e}")
            return None


# ─────────────────────────────────────────────────────────────────────────────
# ML TRAINING DATA GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class MLTrainingDataGenerator:
    """
    Generate ML training data from engagement telemetry.
    Feeds mod_ml_training_pipeline with high-quality historical data.
    """

    def __init__(self, telemetry: EngagementTelemetry):
        """Initialize generator."""
        self.telemetry = telemetry

    def generate_feature_vectors(self) -> Tuple[List, List, List[str]]:
        """
        Generate ML feature vectors from findings.

        Returns:
            (X, y, feature_names) where:
            - X: list of feature vectors
            - y: list of labels (1 = successful, 0 = not)
            - feature_names: names of features
        """
        X = []
        y = []
        feature_names = None

        for finding in self.telemetry.findings.values():
            features = self._extract_features(finding)

            if feature_names is None:
                feature_names = list(features.keys())

            feature_vector = [features[name] for name in feature_names]
            X.append(feature_vector)

            # Label: 1 if exploited/confirmed, 0 otherwise
            label = 1 if finding.status in (FindingStatus.EXPLOITED, FindingStatus.CONFIRMED) else 0
            y.append(label)

        return X, y, feature_names

    def _extract_features(self, finding: Finding) -> Dict:
        """Extract features from a finding for ML model."""
        severity_weight = {
            "critical": 1.0, "high": 0.8, "medium": 0.6,
            "low": 0.4, "info": 0.2
        }.get(finding.severity, 0.5)

        description_len = len(finding.description or "")
        evidence_len = len(finding.evidence or "")

        return {
            "severity_weight": severity_weight,
            "has_cvss": 1.0 if finding.cvss_score else 0.0,
            "has_cwe": 1.0 if finding.cwe else 0.0,
            "has_url": 1.0 if finding.url else 0.0,
            "description_length": min(1.0, description_len / 1000.0),
            "evidence_length": min(1.0, evidence_len / 1000.0),
            "is_confirmed": 1.0 if finding.status in (FindingStatus.CONFIRMED, FindingStatus.EXPLOITED) else 0.0,
            "is_false_positive": 1.0 if finding.status == FindingStatus.FALSE_POSITIVE else 0.0,
            "confidence": finding.confidence,
            "requires_auth": 1.0 if finding.requires_auth else 0.0,
            "requires_interaction": 1.0 if finding.requires_user_interaction else 0.0,
            "attack_chain_depth": min(1.0, finding.attack_chain_depth / 10.0),
        }

    def generate_technique_dataset(self) -> Dict:
        """
        Generate dataset of technique statistics for prioritization model.

        Returns:
            Dict mapping technique_id to stats dict
        """
        dataset = {}

        for tech_id, stats in self.telemetry.technique_stats.items():
            dataset[tech_id] = {
                "technique_id": stats.technique_id,
                "technique_name": stats.technique_name,
                "total_runs": stats.total_runs,
                "successful_runs": stats.successful_runs,
                "success_rate": stats.success_rate,
                "false_positive_rate": stats.false_positive_rate,
                "effectiveness_score": stats.effectiveness_score,
                "avg_time_to_success": stats.avg_time_to_success_seconds,
                "avg_confidence": stats.avg_confidence,
                "contexts_tested": list(stats.contexts_tested),
                "target_types": list(stats.target_types),
                "severities_found": stats.severities_found,
            }

        return dataset

    def generate_training_export(self, output_path: str) -> None:
        """Export training data to JSON for use by ML pipeline."""
        X, y, feature_names = self.generate_feature_vectors()
        technique_data = self.generate_technique_dataset()

        export = {
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "num_samples": len(X),
                "num_features": len(feature_names) if feature_names else 0,
                "positive_samples": sum(y),
                "feature_names": feature_names,
            },
            "feature_vectors": X,
            "labels": y,
            "technique_statistics": technique_data,
            "engagement_metrics": {
                eng_id: asdict(metrics) for eng_id, metrics in
                self.telemetry.engagement_metrics.items()
            }
        }

        # Convert datetime objects to strings
        export["engagement_metrics"] = {
            k: {
                **v,
                "start_time": v["start_time"].isoformat() if isinstance(v["start_time"], datetime) else v["start_time"],
                "end_time": v["end_time"].isoformat() if isinstance(v.get("end_time"), datetime) else v.get("end_time"),
            }
            for k, v in export["engagement_metrics"].items()
        }

        with open(output_path, 'w') as f:
            json.dump(export, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# ENGAGEMENT QUALITY SCORER
# ─────────────────────────────────────────────────────────────────────────────

class EngagementQualityScorer:
    """
    Score the quality of engagement findings and overall engagement quality.
    High-quality data improves ML model training.
    """

    @staticmethod
    def score_finding_quality(finding: Finding) -> float:
        """
        Score individual finding quality (0.0-1.0).

        Considers: evidence depth, confirmation status, confidence, metadata completeness
        """
        score = 0.0

        # Base score from status
        if finding.status == FindingStatus.EXPLOITED:
            score = 1.0
        elif finding.status == FindingStatus.CONFIRMED:
            score = 0.8
        elif finding.status == FindingStatus.FALSE_POSITIVE:
            score = 0.0
        else:  # DISCOVERED
            score = 0.4

        # Boost for good evidence
        if finding.evidence:
            evidence_boost = min(0.15, len(finding.evidence) / 1000.0)
            score += evidence_boost

        # Boost for metadata
        if finding.cwe:
            score += 0.05
        if finding.cvss_score:
            score += 0.05

        # Apply confidence multiplier
        score *= finding.confidence

        # Normalize to 0-1
        return min(1.0, max(0.0, score))

    @staticmethod
    def score_engagement_quality(metrics: EngagementMetrics,
                                 telemetry: EngagementTelemetry) -> float:
        """
        Score overall engagement quality (0.0-1.0).

        Considers: confirmation rate, exploitation rate, finding depth,
        technique diversity, time efficiency
        """
        if metrics.total_findings == 0:
            return 0.0

        score = 0.0

        # Confirmation rate (0-0.25)
        confirmation_rate = metrics.confirmation_rate / 100.0
        score += min(0.25, confirmation_rate)

        # Exploitation rate (0-0.25)
        exploitation_rate = metrics.exploitation_rate / 100.0
        score += min(0.25, exploitation_rate)

        # Finding depth (0-0.2)
        avg_severity = metrics.average_finding_severity / 5.0
        score += min(0.2, avg_severity)

        # Technique diversity (0-0.15)
        tech_diversity = min(1.0, len(metrics.techniques_used) / 10.0)
        score += tech_diversity * 0.15

        # Time efficiency (0-0.15)
        # Better score if more findings in less time
        if metrics.duration_hours > 0:
            findings_per_hour = metrics.total_findings / metrics.duration_hours
            efficiency = min(1.0, findings_per_hour / 5.0)  # 5 findings/hour = max
            score += efficiency * 0.15

        # Quality of findings
        finding_quality_scores = []
        for finding in telemetry.findings.values():
            quality = EngagementQualityScorer.score_finding_quality(finding)
            finding_quality_scores.append(quality)

        if finding_quality_scores:
            avg_quality = sum(finding_quality_scores) / len(finding_quality_scores)
            score += min(0.25, avg_quality)

        return min(1.0, max(0.0, score))


# ─────────────────────────────────────────────────────────────────────────────
# CLI INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def cmd_telemetry(args, console: Console) -> None:
    """CLI command: hakuza telemetry [subcommand]"""

    telemetry = EngagementTelemetry()

    if getattr(args, 'subcommand', None) == 'import':
        _cmd_telemetry_import(args, console, telemetry)
    elif getattr(args, 'subcommand', None) == 'stats':
        _cmd_telemetry_stats(args, console, telemetry)
    elif getattr(args, 'subcommand', None) == 'export':
        _cmd_telemetry_export(args, console, telemetry)
    elif getattr(args, 'subcommand', None) == 'quality':
        _cmd_telemetry_quality(args, console, telemetry)
    else:
        console.print("[yellow]Usage: hakuza telemetry [import|stats|export|quality][/yellow]")


def _cmd_telemetry_import(args, console: Console, telemetry: EngagementTelemetry) -> None:
    """Import engagement data from file."""
    if not hasattr(args, 'file') or not args.file:
        console.print("[red]Error: Please specify a file to import[/red]")
        return

    filepath = args.file
    if not Path(filepath).exists():
        console.print(f"[red]Error: File not found: {filepath}[/red]")
        return

    console.print(f"\n[cyan]Importing from: {filepath}[/cyan]")

    importer = EngagementImporter(telemetry)

    # Detect format
    file_ext = Path(filepath).suffix.lower()
    format_arg = getattr(args, 'format', None) or 'auto'

    if format_arg == 'auto':
        if file_ext == '.xml':
            format_arg = 'burp'
        elif file_ext == '.json':
            format_arg = 'nuclei'
        elif file_ext == '.csv':
            format_arg = 'nessus'

    num_imported = 0
    errors = []

    with Progress() as progress:
        task = progress.add_task("[cyan]Importing...", total=None)

        if format_arg == 'burp':
            num_imported, errors = importer.import_burp_xml(filepath)
        elif format_arg == 'nuclei':
            num_imported, errors = importer.import_nuclei_json(filepath)
        elif format_arg == 'nessus':
            num_imported, errors = importer.import_nessus_csv(filepath)
        else:
            console.print(f"[red]Unknown format: {format_arg}[/red]")
            return

    console.print(f"\n[green]✓ Imported {num_imported} findings[/green]")

    if errors:
        console.print(f"\n[yellow]Warnings ({len(errors)}):[/yellow]")
        for err in errors[:5]:  # Show first 5
            console.print(f"  [dim]{err}[/dim]")
        if len(errors) > 5:
            console.print(f"  [dim]... and {len(errors) - 5} more[/dim]")


def _cmd_telemetry_stats(args, console: Console, telemetry: EngagementTelemetry) -> None:
    """Display telemetry statistics."""
    stats = telemetry.get_all_technique_stats()

    if not stats:
        console.print("[yellow]No technique statistics available[/yellow]")
        return

    # Sort by effectiveness
    sorted_stats = sorted(
        stats.items(),
        key=lambda x: x[1].effectiveness_score,
        reverse=True
    )

    table = Table(title="Technique Effectiveness Statistics")
    table.add_column("Technique", style="cyan")
    table.add_column("Runs", justify="right")
    table.add_column("Success %", justify="right", style="green")
    table.add_column("FP Rate %", justify="right", style="yellow")
    table.add_column("Effectiveness", justify="right", style="magenta")
    table.add_column("Avg Time (s)", justify="right")

    for tech_id, stat in sorted_stats[:20]:  # Top 20
        table.add_row(
            stat.technique_name,
            str(stat.total_runs),
            f"{stat.success_rate:.1f}%",
            f"{stat.false_positive_rate:.1f}%",
            f"{stat.effectiveness_score:.1f}",
            f"{stat.avg_time_to_success_seconds:.0f}"
        )

    console.print(table)


def _cmd_telemetry_export(args, console: Console, telemetry: EngagementTelemetry) -> None:
    """Export training data."""
    output = getattr(args, 'output', None) or "telemetry_training_data.json"

    console.print(f"[cyan]Generating ML training data...[/cyan]")

    generator = MLTrainingDataGenerator(telemetry)

    with Progress() as progress:
        task = progress.add_task("[cyan]Exporting...", total=100)

        generator.generate_training_export(output)
        progress.update(task, completed=100)

    console.print(f"[green]✓ Exported to: {output}[/green]")

    # Show summary
    X, y, feature_names = generator.generate_feature_vectors()
    console.print(f"\n[dim]Summary:[/dim]")
    console.print(f"  Samples: {len(X)}")
    console.print(f"  Features: {len(feature_names) if feature_names else 0}")
    console.print(f"  Positive samples: {sum(y)}")


def _cmd_telemetry_quality(args, console: Console, telemetry: EngagementTelemetry) -> None:
    """Score engagement quality."""
    scorer = EngagementQualityScorer()

    console.print("\n[cyan]Engagement Quality Assessment[/cyan]\n")

    # Score each engagement
    for eng_id, metrics in telemetry.engagement_metrics.items():
        quality_score = scorer.score_engagement_quality(metrics, telemetry)

        quality_label = "Excellent" if quality_score >= 0.8 else \
                       "Good" if quality_score >= 0.6 else \
                       "Fair" if quality_score >= 0.4 else "Poor"

        console.print(f"[bold]{metrics.engagement_name}[/bold]")
        console.print(f"  Quality Score: {quality_score:.2f} ({quality_label})")
        console.print(f"  Findings: {metrics.total_findings}")
        console.print(f"  Confirmation Rate: {metrics.confirmation_rate:.1f}%")
        console.print(f"  Exploitation Rate: {metrics.exploitation_rate:.1f}%")
        console.print(f"  Duration: {metrics.duration_hours:.1f} hours")
        console.print()


def register_argparse(subparsers) -> None:
    """Register telemetry subcommands with argparse."""
    p_telemetry = subparsers.add_parser(
        "telemetry",
        help="Engagement telemetry & ML training data pipeline"
    )

    p_telemetry_sub = p_telemetry.add_subparsers(dest="subcommand")

    # telemetry import
    p_import = p_telemetry_sub.add_parser(
        "import",
        help="Import engagement data from Burp/Nuclei/Nessus"
    )
    p_import.add_argument("file", help="File to import")
    p_import.add_argument(
        "--format",
        choices=["auto", "burp", "nuclei", "nessus"],
        default="auto",
        help="Format of input file"
    )

    # telemetry stats
    p_telemetry_sub.add_parser(
        "stats",
        help="Show technique statistics"
    )

    # telemetry export
    p_export = p_telemetry_sub.add_parser(
        "export",
        help="Export ML training data"
    )
    p_export.add_argument(
        "--output",
        default="telemetry_training_data.json",
        help="Output file for training data"
    )

    # telemetry quality
    p_telemetry_sub.add_parser(
        "quality",
        help="Score engagement quality"
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HAKUZA Engagement Telemetry")
    parser.add_argument("--db", default=str(Path.home() / ".hakuza" / "hakuza.db"),
                       help="Path to hakuza.db")

    args = parser.parse_args()

    console = Console()
    telemetry = EngagementTelemetry(args.db)

    console.print("[bold cyan]HAKUZA Engagement Telemetry[/bold cyan]\n")
    console.print("Module loaded. Use: from mod_engagement_telemetry import EngagementTelemetry")
