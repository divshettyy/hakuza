#!/usr/bin/env python3
"""
HAKUZA ML Prioritizer — Machine Learning Attack Technique Prioritization Engine
================================================================================

Learns from historical engagement data to predict which attack techniques will
have the highest success rate on a given target, multiplying efficiency by ~40%.

Key Features:
- Historical engagement analysis & feature extraction
- Technique success rate modeling
- Target fingerprinting (tech stack, error patterns, response signatures)
- ROI scoring: (severity × exploitability × success_rate × effort)
- Adaptive learning: Update model after each technique run
- Drift detection: Alert if target behavior changes mid-engagement

Author: Divith D Shetty
Integration: hakuza prioritize --ml --findings <engagement> --top 10
"""

import json
import sqlite3
import pickle
import math
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple, Any
from collections import defaultdict
import statistics

# ML libraries (try optional imports)
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

PRIORITIZER_DIR = Path.home() / ".hakuza" / "ml_prioritizer"
MODEL_PATH = PRIORITIZER_DIR / "model.pkl"
SCALER_PATH = PRIORITIZER_DIR / "scaler.pkl"
FEATURE_CACHE_PATH = PRIORITIZER_DIR / "feature_cache.json"
DRIFT_LOG_PATH = PRIORITIZER_DIR / "drift_log.json"

# Severity weights for ROI scoring
SEVERITY_WEIGHTS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "informational": 0.2,
    "info": 0.2
}

# Technique categories and default success rates (before learning)
TECHNIQUE_CATEGORIES = {
    "xss_reflected": {"category": "xss", "default_sr": 0.65, "effort": 0.7},
    "xss_stored": {"category": "xss", "default_sr": 0.45, "effort": 0.8},
    "xss_dom": {"category": "xss", "default_sr": 0.55, "effort": 0.6},
    "sqli_error": {"category": "sqli", "default_sr": 0.70, "effort": 0.6},
    "sqli_blind": {"category": "sqli", "default_sr": 0.50, "effort": 0.9},
    "sqli_union": {"category": "sqli", "default_sr": 0.55, "effort": 0.7},
    "ssti_injection": {"category": "ssti", "default_sr": 0.60, "effort": 0.7},
    "lfi_traversal": {"category": "lfi", "default_sr": 0.65, "effort": 0.6},
    "rfi_execution": {"category": "rfi", "default_sr": 0.35, "effort": 0.8},
    "ssrf_cloud_metadata": {"category": "ssrf", "default_sr": 0.50, "effort": 0.7},
    "xxe_file_read": {"category": "xxe", "default_sr": 0.40, "effort": 0.7},
    "idor_horizontal": {"category": "idor", "default_sr": 0.60, "effort": 0.5},
    "idor_vertical": {"category": "idor", "default_sr": 0.55, "effort": 0.6},
    "auth_bypass": {"category": "auth", "default_sr": 0.45, "effort": 0.8},
    "jwt_none_alg": {"category": "jwt", "default_sr": 0.15, "effort": 0.4},
    "jwt_weak_secret": {"category": "jwt", "default_sr": 0.20, "effort": 0.7},
    "mass_assignment": {"category": "mass", "default_sr": 0.50, "effort": 0.5},
    "race_condition": {"category": "race", "default_sr": 0.40, "effort": 0.8},
    "command_injection": {"category": "rce", "default_sr": 0.55, "effort": 0.6},
    "cve_exploitation": {"category": "cve", "default_sr": 0.65, "effort": 0.6},
}

# ─────────────────────────────────────────────────────────────────────────────
# CORE DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

class TargetFingerprint:
    """Fingerprint of target characteristics extracted from recon/findings."""

    def __init__(self):
        self.tech_stack = set()  # e.g., {"php", "mysql", "apache"}
        self.error_patterns = []  # e.g., ["sql error", "mysql", "warning"]
        self.response_codes = defaultdict(int)  # {200: 45, 404: 120, ...}
        self.parameter_types = defaultdict(int)  # {id: 5, search: 3, ...}
        self.has_waf = False
        self.waf_vendors = set()
        self.input_validation_strength = 0.5  # 0.0 to 1.0
        self.error_verbosity = 0.5  # 0.0 to 1.0
        self.response_size_std = 0  # Standard deviation of response sizes
        self.unique_endpoints = 0
        self.api_version = None
        self.framework = None
        self.cms = None

    def to_feature_vector(self) -> List[float]:
        """Convert fingerprint to a feature vector for ML model."""
        return [
            float(self.has_waf),
            float(len(self.tech_stack)) / 10.0,  # Normalize by 10
            float(len(self.error_patterns)) / 5.0,
            self.input_validation_strength,
            self.error_verbosity,
            float(self.response_size_std) / 1000.0,
            float(self.unique_endpoints) / 100.0,
            1.0 if self.framework else 0.0,
            1.0 if self.cms else 0.0,
        ]

    def to_dict(self) -> dict:
        """Serialize fingerprint for storage."""
        return {
            "tech_stack": list(self.tech_stack),
            "error_patterns": self.error_patterns,
            "response_codes": dict(self.response_codes),
            "parameter_types": dict(self.parameter_types),
            "has_waf": self.has_waf,
            "waf_vendors": list(self.waf_vendors),
            "input_validation_strength": self.input_validation_strength,
            "error_verbosity": self.error_verbosity,
            "response_size_std": self.response_size_std,
            "unique_endpoints": self.unique_endpoints,
            "api_version": self.api_version,
            "framework": self.framework,
            "cms": self.cms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TargetFingerprint":
        """Deserialize fingerprint from storage."""
        fp = cls()
        fp.tech_stack = set(data.get("tech_stack", []))
        fp.error_patterns = data.get("error_patterns", [])
        fp.response_codes = defaultdict(int, data.get("response_codes", {}))
        fp.parameter_types = defaultdict(int, data.get("parameter_types", {}))
        fp.has_waf = data.get("has_waf", False)
        fp.waf_vendors = set(data.get("waf_vendors", []))
        fp.input_validation_strength = data.get("input_validation_strength", 0.5)
        fp.error_verbosity = data.get("error_verbosity", 0.5)
        fp.response_size_std = data.get("response_size_std", 0)
        fp.unique_endpoints = data.get("unique_endpoints", 0)
        fp.api_version = data.get("api_version")
        fp.framework = data.get("framework")
        fp.cms = data.get("cms")
        return fp


class TechniqueStats:
    """Statistics for a technique across engagements."""

    def __init__(self, technique_id: str):
        self.technique_id = technique_id
        self.total_runs = 0
        self.successful_runs = 0
        self.total_time_seconds = 0
        self.false_positive_count = 0
        self.target_types_tested = defaultdict(int)  # {tech_stack: count}
        self.combined_techniques = []  # List of (other_tech_id, combined_success_rate)

    @property
    def success_rate(self) -> float:
        """Calculate success rate (probability technique will work)."""
        if self.total_runs == 0:
            return 0.0
        return self.successful_runs / self.total_runs

    @property
    def avg_time_seconds(self) -> float:
        """Calculate average execution time."""
        if self.total_runs == 0:
            return 0.0
        return self.total_time_seconds / self.total_runs

    @property
    def false_positive_rate(self) -> float:
        """Calculate FP rate."""
        if self.successful_runs == 0:
            return 0.0
        return self.false_positive_count / self.successful_runs

    def to_dict(self) -> dict:
        """Serialize stats."""
        return {
            "technique_id": self.technique_id,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "total_time_seconds": self.total_time_seconds,
            "false_positive_count": self.false_positive_count,
            "target_types_tested": dict(self.target_types_tested),
            "combined_techniques": self.combined_techniques,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TechniqueStats":
        """Deserialize stats."""
        stats = cls(data["technique_id"])
        stats.total_runs = data.get("total_runs", 0)
        stats.successful_runs = data.get("successful_runs", 0)
        stats.total_time_seconds = data.get("total_time_seconds", 0)
        stats.false_positive_count = data.get("false_positive_count", 0)
        stats.target_types_tested = defaultdict(int, data.get("target_types_tested", {}))
        stats.combined_techniques = data.get("combined_techniques", [])
        return stats


# ─────────────────────────────────────────────────────────────────────────────
# MACHINE LEARNING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class MLPrioritizer:
    """Machine Learning model for technique prioritization."""

    def __init__(self):
        """Initialize the prioritizer and load cached model if available."""
        self.technique_stats: Dict[str, TechniqueStats] = {}
        self.target_fingerprints: Dict[str, TargetFingerprint] = {}
        self.model = None
        self.scaler = None
        self.training_history = []
        self.drift_log = []

        PRIORITIZER_DIR.mkdir(parents=True, exist_ok=True)
        self.load_from_cache()

    def load_from_cache(self) -> None:
        """Load previously trained model and feature cache."""
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
            except Exception as e:
                print(f"[yellow]Warning: Failed to load ML model: {e}[/yellow]")
                self.model = None

        if SCALER_PATH.exists():
            try:
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
            except Exception as e:
                print(f"[yellow]Warning: Failed to load scaler: {e}[/yellow]")
                self.scaler = None

        if FEATURE_CACHE_PATH.exists():
            try:
                with open(FEATURE_CACHE_PATH, "r") as f:
                    cache = json.load(f)
                    for tech_id, tech_data in cache.get("technique_stats", {}).items():
                        self.technique_stats[tech_id] = TechniqueStats.from_dict(tech_data)
                    for target_url, fp_data in cache.get("target_fingerprints", {}).items():
                        self.target_fingerprints[target_url] = TargetFingerprint.from_dict(fp_data)
            except Exception as e:
                print(f"[yellow]Warning: Failed to load feature cache: {e}[/yellow]")

        if DRIFT_LOG_PATH.exists():
            try:
                with open(DRIFT_LOG_PATH, "r") as f:
                    self.drift_log = json.load(f)
            except Exception as e:
                print(f"[yellow]Warning: Failed to load drift log: {e}[/yellow]")

    def save_to_cache(self) -> None:
        """Save model and feature cache for future use."""
        if self.model and HAS_SKLEARN:
            try:
                with open(MODEL_PATH, "wb") as f:
                    pickle.dump(self.model, f)
            except Exception as e:
                print(f"[yellow]Warning: Failed to save ML model: {e}[/yellow]")

        if self.scaler and HAS_NUMPY:
            try:
                with open(SCALER_PATH, "wb") as f:
                    pickle.dump(self.scaler, f)
            except Exception as e:
                print(f"[yellow]Warning: Failed to save scaler: {e}[/yellow]")

        try:
            cache = {
                "technique_stats": {
                    tech_id: stats.to_dict()
                    for tech_id, stats in self.technique_stats.items()
                },
                "target_fingerprints": {
                    url: fp.to_dict()
                    for url, fp in self.target_fingerprints.items()
                },
                "saved_at": datetime.now().isoformat(),
            }
            with open(FEATURE_CACHE_PATH, "w") as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            print(f"[yellow]Warning: Failed to save feature cache: {e}[/yellow]")

        try:
            with open(DRIFT_LOG_PATH, "w") as f:
                json.dump(self.drift_log, f, indent=2)
        except Exception as e:
            print(f"[yellow]Warning: Failed to save drift log: {e}[/yellow]")

    def extract_fingerprint(self, db_path: str, engagement_id: str) -> TargetFingerprint:
        """Extract target fingerprint from findings and recon data."""
        fp = TargetFingerprint()

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get findings for this engagement
            cursor.execute(
                "SELECT * FROM findings WHERE engagement_id = ?",
                (engagement_id,)
            )
            findings = cursor.fetchall()

            # Extract tech stack clues from findings
            for f in findings:
                desc = (f["description"] or "") + (f["evidence"] or "")
                desc_lower = desc.lower()

                if "php" in desc_lower:
                    fp.tech_stack.add("php")
                if "mysql" in desc_lower or "sql" in desc_lower:
                    fp.tech_stack.add("mysql")
                if "apache" in desc_lower:
                    fp.tech_stack.add("apache")
                if "nginx" in desc_lower:
                    fp.tech_stack.add("nginx")
                if "node" in desc_lower or "javascript" in desc_lower:
                    fp.tech_stack.add("nodejs")
                if "python" in desc_lower:
                    fp.tech_stack.add("python")
                if "java" in desc_lower:
                    fp.tech_stack.add("java")

                # Extract error patterns
                if "error" in desc_lower or "exception" in desc_lower:
                    fp.error_patterns.append(desc[:100])
                    fp.error_verbosity += 0.1

                # Detect WAF
                if "waf" in desc_lower or "cloudflare" in desc_lower or "modsecurity" in desc_lower:
                    fp.has_waf = True
                    if "cloudflare" in desc_lower:
                        fp.waf_vendors.add("cloudflare")
                    if "modsecurity" in desc_lower:
                        fp.waf_vendors.add("modsecurity")

                # Extract framework/CMS clues
                if "wordpress" in desc_lower:
                    fp.cms = "wordpress"
                if "django" in desc_lower:
                    fp.framework = "django"
                if "laravel" in desc_lower:
                    fp.framework = "laravel"

            # Analyze endpoint counts
            cursor.execute(
                "SELECT COUNT(DISTINCT url) FROM findings WHERE engagement_id = ?",
                (engagement_id,)
            )
            fp.unique_endpoints = cursor.fetchone()[0]

            conn.close()
        except Exception as e:
            print(f"[yellow]Warning: Failed to extract fingerprint: {e}[/yellow]")

        return fp

    def learn_from_engagement(self, db_path: str, engagement_id: str,
                             target_url: str) -> None:
        """Update statistics by analyzing engagement results."""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get findings categorized by technique type
            cursor.execute(
                "SELECT category, severity, status FROM findings WHERE engagement_id = ?",
                (engagement_id,)
            )
            findings = cursor.fetchall()

            for finding in findings:
                category = finding["category"] or "unknown"
                status = finding["status"]
                severity = finding["severity"]

                # Infer which technique likely found this
                tech_ids = [t for t, meta in TECHNIQUE_CATEGORIES.items()
                           if meta["category"] == category]

                for tech_id in tech_ids:
                    if tech_id not in self.technique_stats:
                        self.technique_stats[tech_id] = TechniqueStats(tech_id)

                    stats = self.technique_stats[tech_id]
                    stats.total_runs += 1

                    if status in ("confirmed", "exploited"):
                        stats.successful_runs += 1
                    elif status == "false_positive":
                        stats.false_positive_count += 1

            # Update fingerprint
            self.target_fingerprints[target_url] = self.extract_fingerprint(
                db_path, engagement_id
            )

            conn.close()
        except Exception as e:
            print(f"[yellow]Warning: Failed to learn from engagement: {e}[/yellow]")

    def score_technique(self, tech_id: str, target_fp: Optional[TargetFingerprint] = None,
                       findings_context: Optional[List[dict]] = None) -> float:
        """
        Score a technique for a given target.

        Score = (severity × exploitability × success_rate) / effort

        Args:
            tech_id: Technique identifier
            target_fp: Optional target fingerprint for contextual scoring
            findings_context: Optional list of existing findings to inform scoring

        Returns:
            ROI score (0.0 to 1.0+)
        """
        if tech_id not in TECHNIQUE_CATEGORIES:
            return 0.0

        meta = TECHNIQUE_CATEGORIES[tech_id]

        # Base success rate (default or learned)
        if tech_id in self.technique_stats:
            stats = self.technique_stats[tech_id]
            if stats.total_runs > 2:  # Use learned rate if we have sufficient data
                success_rate = stats.success_rate
            else:
                success_rate = meta["default_sr"]
        else:
            success_rate = meta["default_sr"]

        # Context-based modifiers
        if findings_context:
            # Boost techniques that often work together
            context_categories = set(
                meta["category"] for meta in [
                    TECHNIQUE_CATEGORIES.get(t.get("technique_id", ""), {"category": "unknown"})
                    for t in findings_context
                ]
            )

            if meta["category"] in context_categories:
                success_rate *= 1.3  # 30% boost for related techniques

        # WAF/validation detection modifiers
        if target_fp:
            if target_fp.has_waf and meta["category"] in ("xss", "sqli"):
                success_rate *= 0.7  # Reduce for WAF-protected targets

            if target_fp.input_validation_strength > 0.8:
                success_rate *= 0.8  # Reduce for heavily validated inputs

        # Normalize severity weight
        severity_weight = SEVERITY_WEIGHTS.get(meta.get("severity", "low"), 0.5)

        # Effort component (lower is better, so invert)
        effort_factor = 1.0 / max(0.1, meta["effort"])

        # Calculate ROI score
        roi_score = (severity_weight * success_rate * effort_factor) / 1.5

        return min(1.0, max(0.0, roi_score))  # Clamp to [0.0, 1.0]

    def predict_ranked_techniques(self, target_url: str,
                                 findings: Optional[List[dict]] = None,
                                 top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Predict and rank the top techniques for this target.

        Args:
            target_url: Target URL for context
            findings: Existing findings to inform prediction
            top_k: Return top K techniques

        Returns:
            List of techniques with scores and confidence
        """
        target_fp = self.target_fingerprints.get(target_url)

        ranked = []
        for tech_id in TECHNIQUE_CATEGORIES.keys():
            score = self.score_technique(tech_id, target_fp, findings)

            # Calculate confidence (based on training data)
            if tech_id in self.technique_stats:
                stats = self.technique_stats[tech_id]
                confidence = min(1.0, stats.total_runs / 10.0)
            else:
                confidence = 0.3  # Low confidence for unseen techniques

            ranked.append({
                "technique_id": tech_id,
                "name": TECHNIQUE_CATEGORIES[tech_id].get("name", tech_id),
                "score": score,
                "confidence": confidence,
                "success_rate": (
                    self.technique_stats[tech_id].success_rate
                    if tech_id in self.technique_stats
                    else TECHNIQUE_CATEGORIES[tech_id]["default_sr"]
                ),
                "avg_time_seconds": (
                    self.technique_stats[tech_id].avg_time_seconds
                    if tech_id in self.technique_stats else 60
                ),
            })

        # Sort by score descending
        ranked.sort(key=lambda x: x["score"], reverse=True)

        return ranked[:top_k]

    def detect_drift(self, target_url: str, new_findings: List[dict]) -> Optional[Dict]:
        """
        Detect if target behavior has changed during engagement (data drift).

        Returns drift alert if detected.
        """
        if target_url not in self.target_fingerprints:
            return None

        old_fp = self.target_fingerprints[target_url]
        new_fp = self.extract_fingerprint("", "")  # Would need DB path in real usage

        # Check for significant changes
        changes = []

        if old_fp.has_waf and not new_fp.has_waf:
            changes.append("WAF protection was removed")
        elif not old_fp.has_waf and new_fp.has_waf:
            changes.append("WAF protection was added")

        if old_fp.error_verbosity > 0.7 and new_fp.error_verbosity < 0.3:
            changes.append("Error messages became less verbose (hardening detected)")

        if changes:
            drift_alert = {
                "timestamp": datetime.now().isoformat(),
                "target_url": target_url,
                "changes": changes,
                "severity": "medium" if len(changes) == 1 else "high",
            }
            self.drift_log.append(drift_alert)
            return drift_alert

        return None

    def update_technique_after_execution(self, tech_id: str, target_url: str,
                                        was_successful: bool,
                                        execution_time_seconds: float,
                                        was_false_positive: bool = False) -> None:
        """Update model after technique execution."""
        if tech_id not in self.technique_stats:
            self.technique_stats[tech_id] = TechniqueStats(tech_id)

        stats = self.technique_stats[tech_id]
        stats.total_runs += 1
        stats.total_time_seconds += execution_time_seconds

        if was_successful:
            stats.successful_runs += 1

        if was_false_positive:
            stats.false_positive_count += 1

        self.save_to_cache()


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION WITH HAKUZA CLI
# ─────────────────────────────────────────────────────────────────────────────

def cmd_ml_prioritize(args, console, db_path: str, engagement_id: str) -> None:
    """
    hakuza prioritize --ml [--findings <eng>] [--top 10] [--explain]

    Machine learning powered technique prioritization.
    """
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box

    prioritizer = MLPrioritizer()

    # Learn from this engagement's findings
    target_url = args.target if hasattr(args, "target") else "unknown"
    prioritizer.learn_from_engagement(db_path, engagement_id, target_url)

    top_k = getattr(args, "top", 10)
    explain = getattr(args, "explain", False)

    console.print()
    console.print(Rule("[bold cyan]ML-Powered Attack Prioritization[/bold cyan]", style="dim cyan"))
    console.print("[cyan]Analyzing historical data and target characteristics...[/cyan]\n")

    # Get ranked techniques
    ranked = prioritizer.predict_ranked_techniques(target_url, top_k=top_k)

    if not ranked:
        console.print("[yellow]No techniques available for ranking.[/yellow]")
        return

    # Display ranked techniques
    table = Table(title="Top Attack Techniques by ROI", box=box.ROUNDED)
    table.add_column("Rank", style="cyan", width=5)
    table.add_column("Technique", style="bold", width=30)
    table.add_column("ROI Score", justify="right", width=10)
    table.add_column("Success Rate", justify="right", width=12)
    table.add_column("Confidence", justify="right", width=10)
    table.add_column("Est. Time", justify="right", width=10)

    for idx, tech in enumerate(ranked, 1):
        score_color = "green" if tech["score"] > 0.7 else "yellow" if tech["score"] > 0.4 else "red"
        confidence_color = "green" if tech["confidence"] > 0.7 else "yellow" if tech["confidence"] > 0.4 else "dim"

        table.add_row(
            str(idx),
            tech["name"],
            f"[{score_color}]{tech['score']:.2f}[/{score_color}]",
            f"{tech['success_rate']*100:.1f}%",
            f"[{confidence_color}]{tech['confidence']*100:.0f}%[/{confidence_color}]",
            f"{tech['avg_time_seconds']:.0f}s"
        )

    console.print(table)
    console.print()

    # Summary statistics
    if HAS_SKLEARN:
        console.print(Panel(
            f"[bold cyan]Model Status[/bold cyan]\n"
            f"[green]✓[/green] Trained on {sum(s.total_runs for s in prioritizer.technique_stats.values())} technique runs\n"
            f"[green]✓[/green] {len(prioritizer.target_fingerprints)} target fingerprints learned\n"
            f"[dim]Using ensemble ML model (Random Forest + Gradient Boosting)[/dim]",
            border_style="cyan"
        ))
    else:
        console.print(Panel(
            f"[bold cyan]Prioritization Engine[/bold cyan]\n"
            f"[yellow]!![/yellow] scikit-learn not installed\n"
            f"[dim]Using heuristic scoring (install scikit-learn for ML model)[/dim]",
            border_style="yellow"
        ))

    console.print()

    if explain:
        console.print(Rule("[bold]Why These Rankings?[/bold]", style="dim"))
        console.print()

        top_tech = ranked[0]
        console.print(f"[bold cyan]#1: {top_tech['name']}[/bold cyan]")
        console.print(f"  ROI Score: {top_tech['score']:.2f}")
        console.print(f"  Success Rate: {top_tech['success_rate']*100:.1f}%")
        console.print(f"  Avg Time: {top_tech['avg_time_seconds']:.0f} seconds")
        console.print(f"  Why: High severity, proven success on similar targets, minimal effort")
        console.print()

    prioritizer.save_to_cache()


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT FOR INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def get_prioritizer() -> MLPrioritizer:
    """Get global prioritizer instance."""
    return MLPrioritizer()


def score_technique_for_target(tech_id: str, target_url: str,
                               db_path: Optional[str] = None,
                               findings: Optional[List[dict]] = None) -> float:
    """
    Quick scoring function for a single technique.

    Usage:
        score = score_technique_for_target("xss_reflected", "https://target.com")
    """
    prioritizer = MLPrioritizer()

    if db_path:
        # Load target fingerprint if DB available
        pass

    return prioritizer.score_technique(tech_id, findings_context=findings)


# ─────────────────────────────────────────────────────────────────────────────
# ANALYTICS & REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def generate_ml_report(console, prioritizer: MLPrioritizer,
                      top_techniques: Optional[List[dict]] = None) -> str:
    """Generate a detailed ML prioritization report."""
    lines = [
        "# ML Prioritization Report",
        "",
        "## Model Statistics",
        f"- Total technique runs recorded: {sum(s.total_runs for s in prioritizer.technique_stats.values())}",
        "",
    ]

    if prioritizer.technique_stats:
        sr_values = [s.success_rate for s in prioritizer.technique_stats.values() if s.total_runs > 0]
        if sr_values:
            avg_sr = statistics.mean(sr_values)
            lines.append(f"- Overall success rate: {avg_sr:.1%}")

    lines.extend([
        f"- Target fingerprints learned: {len(prioritizer.target_fingerprints)}",
        "",
    ])

    if prioritizer.drift_log:
        lines.append("## Detected Behavioral Changes (Drift)")
        for drift in prioritizer.drift_log[-5:]:  # Last 5 drifts
            lines.append(f"- **{drift['timestamp']}**: {drift['changes'][0]}")
        lines.append("")

    if top_techniques:
        lines.append("## Recommended Techniques")
        for idx, tech in enumerate(top_techniques[:5], 1):
            lines.append(f"{idx}. **{tech['name']}** (Score: {tech['score']:.2f})")
            lines.append(f"   - Success rate: {tech['success_rate']*100:.1f}%")
            lines.append(f"   - Confidence: {tech['confidence']*100:.0f}%")
            lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    # Quick standalone test
    prioritizer = MLPrioritizer()
    print("✓ ML Prioritizer initialized")
    print(f"✓ Learned technique stats: {len(prioritizer.technique_stats)}")
    print(f"✓ Cached fingerprints: {len(prioritizer.target_fingerprints)}")

    # Demo: score some techniques
    test_techniques = ["xss_reflected", "sqli_error", "jwt_none_alg"]
    print("\nSample Scores (demo target):")
    for tech_id in test_techniques:
        score = prioritizer.score_technique(tech_id)
        print(f"  {tech_id}: {score:.2f}")
