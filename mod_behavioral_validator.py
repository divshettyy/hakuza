#!/usr/bin/env python3
"""
mod_behavioral_validator.py — HAKUZA Behavioral Validation & Impact Quantification

Monitors APPLICATION BEHAVIOR CHANGES during exploitation to confirm PoC success,
measure impact (data exfiltrated, auth bypassed, execution confirmed), and automatically
quantify exploitability.

Key components:
  1. BehaviorMonitor — track HTTP responses, state changes, side effects
  2. BaselineCapture — capture pre-exploit app state (HTTP baseline, DB state, etc.)
  3. DeltaAnalyzer — compare before/after, identify impact
  4. SuccessConfirmer — did the exploit actually work? proof?
  5. ImpactQuantifier — how much data/access/capability did we gain?
  6. FalsePositiveEliminator — distinguish real success from false alarms
  7. AutomaticReporting — generate impact evidence

Integration:
  - Manual validation: hakuza validate --poc <script> --target <url>
  - Measure impact: hakuza validate --poc <script> --target <url> --measure impact
  - Deep analysis: hakuza validate --poc <script> --target <url> --measure full

Features:
  - Eliminates false positives through multi-vector analysis
  - Quantifies data exposure and privilege escalation impact
  - Confirms exploitation via RCE, auth bypass, data exposure vectors
  - Automatic CVSS scoring
  - Chain exploitation impact (multi-step attacks)
  - Timing-based blind exploitation detection
  - Error-based and inference-based success confirmation

Author  : HAKUZA Team
Purpose : Eliminate false positives, turn PoCs into quantified findings
Target  : 1100+ LOC with comprehensive edge case handling
"""

import os
import json
import re
import sys
import time
import subprocess
import tempfile
import hashlib
import shlex
import difflib
import mimetypes
import statistics
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Set
from dataclasses import dataclass, asdict, field

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HTTPSnapshot:
    """HTTP response snapshot for before/after comparison."""
    timestamp: str
    method: str
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    body_hash: str
    response_time_ms: float
    content_length: int

    def to_dict(self) -> dict:
        return asdict(self)

    def is_error_response(self) -> bool:
        """Check if response is an error (4xx or 5xx)."""
        return self.status_code >= 400

    def is_redirect(self) -> bool:
        """Check if response is a redirect."""
        return 300 <= self.status_code < 400

    def is_success(self) -> bool:
        """Check if response is successful (2xx)."""
        return 200 <= self.status_code < 300


@dataclass
class BehaviorDelta:
    """Difference between baseline and post-exploit state."""
    changed_status_codes: Dict[str, int] = field(default_factory=dict)
    body_differences: List[Tuple[str, str, str]] = field(default_factory=list)  # url, before, after
    new_endpoints_accessible: List[str] = field(default_factory=list)
    auth_state_changes: Dict[str, str] = field(default_factory=dict)  # endpoint -> auth_level
    data_exposure: Dict[str, int] = field(default_factory=dict)  # field -> count
    performance_degradation: Dict[str, float] = field(default_factory=dict)  # endpoint -> ms_increase
    timing_anomalies: List[str] = field(default_factory=list)  # responses with suspicious timing
    error_patterns: List[str] = field(default_factory=list)  # new errors / stack traces

    def has_changes(self) -> bool:
        return bool(
            self.changed_status_codes or
            self.body_differences or
            self.new_endpoints_accessible or
            self.auth_state_changes or
            self.data_exposure or
            self.performance_degradation or
            self.timing_anomalies or
            self.error_patterns
        )


@dataclass
class ExploitationResult:
    """Result of exploitation attempt with confidence metrics."""
    exploit_executed: bool
    success_confirmed: bool
    confidence_score: float  # 0.0-1.0
    evidence: List[str]
    impact_type: str  # "rce", "data_exposure", "auth_bypass", "privilege_escalation", etc.
    impact_severity: str  # "critical", "high", "medium", "low"
    data_exfiltrated: Dict[str, Any] = field(default_factory=dict)
    access_gained: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.0  # 0.0-1.0 (lower is better)
    false_positive_indicators: List[str] = field(default_factory=list)
    poc_output: str = ""
    http_changes: Optional[BehaviorDelta] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.http_changes:
            d['http_changes'] = asdict(self.http_changes)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# BaselineCapture — Pre-exploit state snapshot
# ─────────────────────────────────────────────────────────────────────────────

class BaselineCapture:
    """Captures application state before exploit execution."""

    def __init__(self, target_url: str, session=None, timeout: int = 10):
        self.target_url = target_url
        self.session = session or self._build_session()
        self.timeout = timeout
        self.baseline_snapshots: Dict[str, HTTPSnapshot] = {}
        self.baseline_timestamp = datetime.now().isoformat()

    def _build_session(self):
        """Build resilient requests session with retries."""
        if not HAS_REQUESTS:
            return None
        sess = requests.Session()
        retry = Retry(connect=2, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    def capture_endpoint(self, path: str = "", method: str = "GET",
                        data: dict = None, headers: dict = None) -> Optional[HTTPSnapshot]:
        """Capture single endpoint state."""
        if not HAS_REQUESTS or not self.session:
            return None

        url = self.target_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            start = time.time()
            if method.upper() == "GET":
                resp = self.session.get(url, timeout=self.timeout, headers=headers or {})
            elif method.upper() == "POST":
                resp = self.session.post(url, json=data or {}, timeout=self.timeout, headers=headers or {})
            else:
                return None
            elapsed_ms = (time.time() - start) * 1000

            body = resp.text
            body_hash = hashlib.sha256(body.encode()).hexdigest()

            snapshot = HTTPSnapshot(
                timestamp=datetime.now().isoformat(),
                method=method,
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body[:10000],  # truncate large bodies
                body_hash=body_hash,
                response_time_ms=elapsed_ms,
                content_length=len(body),
            )
            self.baseline_snapshots[url] = snapshot
            return snapshot
        except Exception as e:
            return None

    def capture_common_endpoints(self, endpoints: List[str] = None) -> Dict[str, HTTPSnapshot]:
        """Capture state of common endpoints."""
        if endpoints is None:
            endpoints = ["/", "/index.html", "/api/", "/api/health", "/admin"]

        for ep in endpoints:
            self.capture_endpoint(ep)

        return self.baseline_snapshots


# ─────────────────────────────────────────────────────────────────────────────
# BehaviorMonitor — Track responses and state changes
# ─────────────────────────────────────────────────────────────────────────────

class BehaviorMonitor:
    """Monitors application behavior during and after PoC execution."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.post_exploit_snapshots: Dict[str, HTTPSnapshot] = {}
        self.execution_events: List[Dict[str, Any]] = []
        self.session = self._build_session()

    def _build_session(self):
        if not HAS_REQUESTS:
            return None
        sess = requests.Session()
        retry = Retry(connect=2, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    def capture_post_exploit_state(self, path: str = "", method: str = "GET",
                                   data: dict = None, timeout: int = 10) -> Optional[HTTPSnapshot]:
        """Capture application state after exploit."""
        if not HAS_REQUESTS or not self.session:
            return None

        url = self.target_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            start = time.time()
            if method.upper() == "GET":
                resp = self.session.get(url, timeout=timeout)
            elif method.upper() == "POST":
                resp = self.session.post(url, json=data or {}, timeout=timeout)
            else:
                return None
            elapsed_ms = (time.time() - start) * 1000

            body = resp.text
            body_hash = hashlib.sha256(body.encode()).hexdigest()

            snapshot = HTTPSnapshot(
                timestamp=datetime.now().isoformat(),
                method=method,
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body[:10000],
                body_hash=body_hash,
                response_time_ms=elapsed_ms,
                content_length=len(body),
            )
            self.post_exploit_snapshots[url] = snapshot
            return snapshot
        except Exception as e:
            self.execution_events.append({
                "timestamp": datetime.now().isoformat(),
                "type": "error",
                "message": str(e),
            })
            return None

    def record_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Record an event during exploitation."""
        self.execution_events.append({
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            **details,
        })


# ─────────────────────────────────────────────────────────────────────────────
# DeltaAnalyzer — Compare before/after state
# ─────────────────────────────────────────────────────────────────────────────

class DeltaAnalyzer:
    """Analyzes differences between baseline and post-exploit state."""

    @staticmethod
    def analyze_http_changes(baseline: Dict[str, HTTPSnapshot],
                            post_exploit: Dict[str, HTTPSnapshot]) -> BehaviorDelta:
        """Compare HTTP responses before and after exploitation."""
        delta = BehaviorDelta()

        # Detect status code changes
        for url, baseline_snap in baseline.items():
            if url in post_exploit:
                post_snap = post_exploit[url]
                if baseline_snap.status_code != post_snap.status_code:
                    delta.changed_status_codes[url] = {
                        "before": baseline_snap.status_code,
                        "after": post_snap.status_code,
                    }

        # Detect body differences
        for url, baseline_snap in baseline.items():
            if url in post_exploit:
                post_snap = post_exploit[url]
                if baseline_snap.body_hash != post_snap.body_hash:
                    delta.body_differences.append((url, baseline_snap.body, post_snap.body))

        # Detect new accessible endpoints
        for url in post_exploit:
            if url not in baseline:
                snap = post_exploit[url]
                if snap.status_code < 400:
                    delta.new_endpoints_accessible.append(url)

        # Detect performance changes
        for url, baseline_snap in baseline.items():
            if url in post_exploit:
                post_snap = post_exploit[url]
                delta_time = post_snap.response_time_ms - baseline_snap.response_time_ms
                if delta_time > 1000:  # >1s increase
                    delta.performance_degradation[url] = delta_time

        return delta

    @staticmethod
    def extract_data_exposure(body_before: str, body_after: str) -> Dict[str, int]:
        """Detect and quantify data exposure in responses."""
        exposure = {}

        # Look for common sensitive patterns
        patterns = {
            "api_keys": r"(?i)(api[_-]?key|apikey|secret)['\"]?\s*[:=]\s*['\"]?([a-z0-9_-]{20,})",
            "credentials": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^'\"\s]+)",
            "email_addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone_numbers": r"\+?1?\d{9,15}",
            "credit_cards": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "ip_addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "json_objects": r"\{[^}]*(?:['\"][^'\"]*['\"][^}]*)*\}",
        }

        for pattern_name, pattern in patterns.items():
            before_matches = len(re.findall(pattern, body_before or ""))
            after_matches = len(re.findall(pattern, body_after or ""))
            if after_matches > before_matches:
                exposure[pattern_name] = after_matches - before_matches

        return exposure

    @staticmethod
    def detect_timing_anomalies(snapshots: List[HTTPSnapshot],
                               threshold_ms: float = 3000) -> List[str]:
        """Detect suspiciously slow responses (possible blind exploitation indicators)."""
        anomalies = []
        if not snapshots:
            return anomalies

        avg_time = sum(s.response_time_ms for s in snapshots) / len(snapshots)
        for snap in snapshots:
            if snap.response_time_ms > threshold_ms:
                anomalies.append(
                    f"{snap.url} took {snap.response_time_ms}ms (avg: {avg_time}ms)"
                )

        return anomalies


# ─────────────────────────────────────────────────────────────────────────────
# SuccessConfirmer — Proof of exploitation
# ─────────────────────────────────────────────────────────────────────────────

class SuccessConfirmer:
    """Determines whether an exploit actually succeeded with multi-vector confirmation."""

    @staticmethod
    def confirm_rce(poc_output: str, target_indicators: List[str] = None) -> Tuple[bool, float]:
        """Confirm RCE by looking for command output or execution indicators."""
        if not poc_output:
            return False, 0.0

        confidence = 0.0
        matches_found = 0
        strong_matches = 0

        # Look for command execution indicators
        # Organized by strength (strong indicators are high-confidence RCE signals)
        strong_indicators = [
            r"uid=\d+", r"gid=\d+",  # id command output (strong indicators)
            r"root\s+root",  # Directory listing with root user
        ]
        standard_indicators = [
            r"groups=",  # id command groups
            r"Linux", r"Windows",  # os indicators
            r"[\\/](bin|sbin|windows|system32)", r"cmd\.exe",  # path indicators
            r"total \d+", r"drwx", r"-rw",  # ls/dir output
            r"bash:|sh:|cmd\.exe:|powershell",  # shell prompt
            r"root@|administrator@",  # user@host prompt
            r"processes|netstat|LISTEN",  # process info
        ]

        # Check strong indicators first
        for indicator in strong_indicators:
            if re.search(indicator, poc_output, re.IGNORECASE):
                confidence += 0.25  # Stronger weight
                matches_found += 1
                strong_matches += 1

        # Then check standard indicators
        for indicator in standard_indicators:
            if re.search(indicator, poc_output, re.IGNORECASE):
                confidence += 0.15
                matches_found += 1

        # Successful execution if:
        # - 2+ strong matches (uid + gid), OR
        # - 3+ total matches, OR
        # - confidence >= 0.4
        success = (strong_matches >= 2) or (matches_found >= 3) or (confidence >= 0.4)
        return success, min(confidence, 1.0)

    @staticmethod
    def confirm_data_exposure(http_delta: BehaviorDelta,
                             exposure_threshold: int = 5) -> Tuple[bool, float]:
        """Confirm data exposure by detecting new sensitive data in responses."""
        if not http_delta.data_exposure:
            return False, 0.0

        total_exposure = sum(http_delta.data_exposure.values())

        # Weight by sensitivity
        weighted_score = 0.0
        weights = {
            "credentials": 3.0,
            "api_keys": 2.5,
            "credit_cards": 2.0,
            "email_addresses": 1.0,
            "phone_numbers": 0.8,
            "ip_addresses": 0.5,
        }

        for category, count in http_delta.data_exposure.items():
            weight = weights.get(category, 1.0)
            weighted_score += count * weight

        confidence = min(weighted_score / exposure_threshold, 1.0)
        success = weighted_score >= exposure_threshold

        return success, confidence

    @staticmethod
    def confirm_auth_bypass(http_delta: BehaviorDelta,
                           baseline_allowed: bool = False) -> Tuple[bool, float]:
        """Confirm auth bypass by detecting status 200 where 401/403 was expected."""
        if not http_delta.changed_status_codes:
            return False, 0.0

        bypass_found = False
        confidence = 0.0
        bypasses = []

        for url, changes in http_delta.changed_status_codes.items():
            before = changes.get("before", 0)
            after = changes.get("after", 0)

            # 401/403 -> 200/2xx = successful bypass
            if before in (401, 403) and 200 <= after < 300:
                bypass_found = True
                confidence = 0.95
                bypasses.append(url)

            # 403 -> 200 with body change
            elif before == 403 and after == 200:
                if any(diff[0] == url for diff in http_delta.body_differences):
                    bypass_found = True
                    confidence = 0.90

        # Multiple bypasses = higher confidence
        if len(bypasses) > 1:
            confidence = min(confidence * 1.1, 1.0)

        return bypass_found, confidence

    @staticmethod
    def confirm_timing_attack(http_delta: BehaviorDelta,
                            anomaly_threshold_ms: float = 2000) -> Tuple[bool, float]:
        """Confirm exploitation via timing anomalies (blind SQLi, etc)."""
        if not http_delta.timing_anomalies:
            return False, 0.0

        anomaly_count = len(http_delta.timing_anomalies)
        confidence = min(anomaly_count * 0.25, 1.0)

        # Timing attacks need at least 2 anomalies for confidence
        success = anomaly_count >= 2
        return success, confidence

    @staticmethod
    def confirm_error_based(poc_output: str, http_delta: BehaviorDelta) -> Tuple[bool, float]:
        """Confirm via error-based indicators (stack traces, DB errors, etc)."""
        if not poc_output and not http_delta.error_patterns:
            return False, 0.0

        confidence = 0.0

        # Look for DB error patterns
        db_patterns = [
            r"SQL", r"MySQL", r"PostgreSQL", r"Oracle", r"MSSQL",
            r"syntax error", r"unexpected token", r"invalid column",
            r"Traceback", r"Exception", r"Error in query",
        ]

        error_count = 0
        for pattern in db_patterns:
            if re.search(pattern, poc_output or "", re.IGNORECASE):
                error_count += 1

        # HTTP errors in response
        error_count += len(http_delta.error_patterns)

        confidence = min(error_count * 0.2, 1.0)
        success = error_count >= 2

        return success, confidence

    @staticmethod
    def confirm_from_indicators(poc_output: str, http_delta: BehaviorDelta,
                               custom_indicators: List[str] = None) -> Tuple[bool, float]:
        """Universal confirmation using custom indicators."""
        if not custom_indicators:
            return False, 0.0

        confidence = 0.0
        matches = 0

        for indicator in custom_indicators:
            if re.search(indicator, poc_output or "", re.IGNORECASE):
                confidence += 1.0 / len(custom_indicators)
                matches += 1

        # Also boost confidence if HTTP delta shows changes
        if http_delta.has_changes():
            confidence += 0.2

        # Multiple custom indicators matching = higher confidence
        if matches >= len(custom_indicators) * 0.5:
            confidence = min(confidence * 1.1, 1.0)

        success = confidence > 0.5 or matches >= len(custom_indicators) * 0.5
        return success, min(confidence, 1.0)


# ─────────────────────────────────────────────────────────────────────────────
# ImpactQuantifier — Measure exploitation impact
# ─────────────────────────────────────────────────────────────────────────────

class ImpactQuantifier:
    """Quantifies the impact of successful exploitation."""

    @staticmethod
    def quantify_data_exposure(data_exposure: Dict[str, int]) -> Dict[str, Any]:
        """Estimate data exposure impact."""
        result = {
            "total_items": sum(data_exposure.values()),
            "categories": data_exposure,
            "estimated_records": 0,
            "severity_estimate": "low",
        }

        # Estimate based on pattern type
        for category, count in data_exposure.items():
            if category == "email_addresses":
                result["estimated_records"] += count
            elif category == "credentials":
                result["estimated_records"] += count * 10  # assume each password unlocks ~10 systems
            elif category == "api_keys":
                result["estimated_records"] += count * 100
            elif category == "credit_cards":
                result["estimated_records"] += count * 50

        # Severity estimation
        if result["estimated_records"] > 1000:
            result["severity_estimate"] = "critical"
        elif result["estimated_records"] > 100:
            result["severity_estimate"] = "high"
        elif result["estimated_records"] > 10:
            result["severity_estimate"] = "medium"

        return result

    @staticmethod
    def quantify_privilege_escalation(access_gained: List[str]) -> Dict[str, Any]:
        """Estimate privilege escalation impact."""
        result = {
            "access_level_before": "user",
            "access_level_after": "user",
            "privilege_increase": 0,
        }

        # Check for highest privilege level first: root > system > admin > sudo
        has_root = any("root" in a.lower() for a in access_gained)
        has_system = any("system" in a.lower() for a in access_gained)
        has_admin = any("admin" in a.lower() for a in access_gained)
        has_sudo = any("sudo" in a.lower() for a in access_gained)

        if has_root:
            result["access_level_after"] = "root"
            result["privilege_increase"] = 3
        elif has_system:
            result["access_level_after"] = "system"
            result["privilege_increase"] = 3
        elif has_admin:
            result["access_level_after"] = "admin"
            result["privilege_increase"] = 2
        elif has_sudo:
            result["privilege_increase"] = 1

        return result

    @staticmethod
    def estimate_cvss_impact(impact_type: str, http_delta: BehaviorDelta,
                            data_exposure: Dict[str, int]) -> Tuple[float, str]:
        """Estimate CVSS 3.1 score based on impact metrics."""
        score = 0.0

        # Base scores by impact type (CVSS 3.1 reference)
        base_scores = {
            "rce": 9.8,           # Network, Low AV
            "data_exposure": 7.5, # Network, High C, High I
            "auth_bypass": 8.1,   # Network, High C+I
            "privilege_escalation": 8.8,  # High + system-level access
            "information_disclosure": 5.3,  # Low/Medium impact
            "xxe": 8.6,           # Can lead to RCE or data exposure
            "ssrf": 6.1,          # Medium impact, internal access
            "idor": 6.5,          # Horizontal privilege escalation
            "csrf": 4.3,          # Depends on context
            "xss": 6.1,           # Reflected/Stored XSS
            "sqli": 8.6,          # Can lead to RCE
            "lfi": 5.3,           # File disclosure
        }

        score = base_scores.get(impact_type, 5.0)

        # CVSS Confidentiality Impact adjustment
        if http_delta.data_exposure:
            total_exposed = sum(data_exposure.values()) if data_exposure else 0
            if total_exposed > 100:
                score = min(9.8, score + 1.0)
            elif total_exposed > 10:
                score = min(9.8, score + 0.5)

        # CVSS Availability Impact adjustment
        if http_delta.performance_degradation:
            perf_issues = len(http_delta.performance_degradation)
            if perf_issues > 5:
                score = min(9.8, score + 0.7)
            elif perf_issues > 1:
                score = min(9.8, score + 0.3)

        # CVSS Integrity Impact adjustment
        if http_delta.body_differences:
            body_diff_count = len(http_delta.body_differences)
            if body_diff_count > 5:
                score = min(9.8, score + 0.6)

        # New accessible endpoints indicate scope change
        if http_delta.new_endpoints_accessible:
            new_endpoint_count = len(http_delta.new_endpoints_accessible)
            if new_endpoint_count > 10:
                score = min(9.8, score + 0.8)
            elif new_endpoint_count > 3:
                score = min(9.8, score + 0.4)

        # Auth state changes = scope increase
        if http_delta.auth_state_changes:
            score = min(9.8, score + 0.5)

        # Cap adjustments
        score = min(9.8, max(0.1, score))

        # Severity mapping (CVSS 3.1 standard)
        if score >= 9.0:
            severity = "critical"
        elif score >= 7.0:
            severity = "high"
        elif score >= 4.0:
            severity = "medium"
        elif score >= 0.1:
            severity = "low"
        else:
            severity = "none"

        return round(score, 1), severity

    @staticmethod
    def quantify_chain_impact(impacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Quantify impact of chained exploitations."""
        if not impacts:
            return {"total_impact_score": 0, "chain_length": 0, "estimated_severity": "none"}

        # Each additional step in exploitation chain increases severity
        chain_multiplier = 1.0 + (len(impacts) * 0.15)

        total_score = 0.0
        max_severity = "low"
        severities = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

        for impact in impacts:
            if isinstance(impact, dict):
                score = impact.get("cvss_score", 5.0)
                total_score += score
                severity = impact.get("severity", "low")
                if severities.get(severity, 0) > severities.get(max_severity, 0):
                    max_severity = severity

        # Chain impact score
        chain_score = total_score * chain_multiplier

        return {
            "total_impact_score": round(chain_score, 1),
            "chain_length": len(impacts),
            "estimated_severity": max_severity,
            "chain_multiplier": chain_multiplier,
        }


# ─────────────────────────────────────────────────────────────────────────────
# FalsePositiveEliminator — Distinguish real success from false alarms
# ─────────────────────────────────────────────────────────────────────────────

class FalsePositiveEliminator:
    """Detects and eliminates false positive findings with multi-vector analysis."""

    @staticmethod
    def check_false_positives(http_delta: BehaviorDelta, poc_output: str,
                             baseline_anomalies: Dict[str, Any] = None) -> Tuple[float, List[str]]:
        """Compute false positive risk and return indicators."""
        risk = 0.0
        indicators = []

        # Check PoC output quality
        if not poc_output or len(poc_output) < 5:
            risk += 0.25
            indicators.append("PoC output suspiciously short or empty")
        elif len(poc_output) < 20 and poc_output.count("\n") < 2:
            risk += 0.15
            indicators.append("PoC output minimal, may be incomplete execution")

        # Check for error-only output
        if poc_output:
            error_keywords = ["error", "failed", "exception", "traceback", "not found"]
            success_keywords = ["success", "executed", "confirmed", "accessed", "retrieved"]

            error_count = sum(1 for kw in error_keywords if kw in poc_output.lower())
            success_count = sum(1 for kw in success_keywords if kw in poc_output.lower())

            if error_count > success_count and error_count >= 2:
                risk += 0.2
                indicators.append("PoC output contains multiple errors without success indicators")

        # Check HTTP changes quality
        if not http_delta.has_changes():
            risk += 0.35
            indicators.append("No HTTP-level behavior changes detected")

        # Timing-only indicators (possible false positive from network latency)
        timing_only = (
            http_delta.timing_anomalies and
            not http_delta.body_differences and
            not http_delta.data_exposure and
            not http_delta.auth_state_changes
        )
        if timing_only:
            risk += 0.25
            indicators.append("Only timing changes detected, no content/auth/data changes (may be network noise)")

        # Status code changes could be normal (redirects, 404s)
        if http_delta.changed_status_codes and not http_delta.body_differences:
            redirect_codes = {301, 302, 303, 304, 307, 308}
            redirect_only = all(
                c.get("after", 0) in redirect_codes or c.get("after") in (404, 410)
                for c in http_delta.changed_status_codes.values()
            )
            if redirect_only:
                risk += 0.45
                indicators.append("Status code changes appear to be redirects/404s, not exploitation impact")

        # Data exposure only in error pages (not actual breach)
        if http_delta.data_exposure and http_delta.body_differences:
            for url, before, after in http_delta.body_differences:
                if "/error" in url or "/404" in url or "error" in after.lower():
                    # Check if data is only in error context
                    if len(after) < 1000 and re.search(r"error|not found|exception", after, re.IGNORECASE):
                        risk += 0.15
                        indicators.append(f"Data exposure appears to be in error page ({url}), not real breach")

        # Check for response body legitimacy
        if http_delta.body_differences:
            suspicious_bodies = 0
            for url, before, after in http_delta.body_differences:
                # Empty responses
                if not after or len(after) < 2:
                    suspicious_bodies += 1
                # Response is just a status message
                elif after.lower() in ("ok", "error", "fail", "success"):
                    suspicious_bodies += 1
                # Response contains only whitespace
                elif not after.strip():
                    suspicious_bodies += 1

            if suspicious_bodies == len(http_delta.body_differences):
                risk += 0.2
                indicators.append("All body changes are minimal/empty responses, may indicate transient behavior")

        # Check for consistent changes across multiple endpoints
        if http_delta.changed_status_codes:
            status_changes = [c.get("after") for c in http_delta.changed_status_codes.values()]
            # If ALL endpoints show same status change, might be application-wide issue, not targeted exploit
            if status_changes and len(set(status_changes)) == 1 and len(status_changes) > 3:
                risk += 0.2
                indicators.append("Identical status changes across multiple endpoints (app-wide behavior, not targeted)")

        # Auth state changes without corresponding HTTP changes can be suspicious
        if http_delta.auth_state_changes and not http_delta.changed_status_codes:
            risk += 0.15
            indicators.append("Auth state changed but no HTTP status changes observed (inconsistent)")

        # Performance degradation without other changes
        perf_only = (
            http_delta.performance_degradation and
            not http_delta.body_differences and
            not http_delta.data_exposure and
            not http_delta.auth_state_changes and
            not http_delta.changed_status_codes
        )
        if perf_only:
            risk += 0.25
            indicators.append("Only performance degradation detected, no functional changes")

        return min(risk, 1.0), indicators[:5]  # Return top 5 indicators

    @staticmethod
    def validate_poc_output_format(poc_output: str, expected_format: str = None) -> Tuple[bool, str]:
        """Validate PoC output matches expected format."""
        if not poc_output:
            return False, "Empty output"

        # Check for common patterns
        if re.search(r"usage:|help:|options:", poc_output, re.IGNORECASE):
            return False, "Output appears to be help text, not execution result"

        if re.search(r"^command not found|^sh: \d+: ", poc_output):
            return False, "Command not found or shell error"

        if expected_format == "json":
            try:
                json.loads(poc_output)
                return True, "Valid JSON output"
            except:
                return False, "Expected JSON but output is not valid JSON"

        if expected_format == "rce":
            if re.search(r"uid=|gid=|root|admin", poc_output, re.IGNORECASE):
                return True, "Contains RCE indicators"
            return False, "Missing RCE indicators"

        return True, "Output validation passed (generic format)"


# ─────────────────────────────────────────────────────────────────────────────
# AutomaticReporting — Generate impact evidence report
# ─────────────────────────────────────────────────────────────────────────────

class AutomaticReporting:
    """Generates structured impact reports from validation results."""

    @staticmethod
    def generate_finding_evidence(result: ExploitationResult) -> str:
        """Generate evidence markdown for finding submission."""
        evidence_lines = [
            "## Exploitation Evidence",
            "",
            f"**Status:** {'Confirmed' if result.success_confirmed else 'Unconfirmed'}",
            f"**Confidence:** {result.confidence_score * 100:.1f}%",
            f"**False Positive Risk:** {result.false_positive_risk * 100:.1f}%",
            "",
        ]

        if result.impact_type:
            evidence_lines.extend([
                "### Impact Type",
                f"- Type: `{result.impact_type}`",
                f"- Severity: `{result.impact_severity}`",
                "",
            ])

        if result.evidence:
            evidence_lines.extend([
                "### Direct Evidence",
                "",
            ])
            for i, item in enumerate(result.evidence, 1):
                evidence_lines.append(f"{i}. {item}")
            evidence_lines.append("")

        if result.data_exfiltrated:
            evidence_lines.extend([
                "### Data Exposure",
                "",
            ])
            for key, value in result.data_exfiltrated.items():
                evidence_lines.append(f"- **{key}:** {value}")
            evidence_lines.append("")

        if result.access_gained:
            evidence_lines.extend([
                "### Access Gained",
                "",
            ])
            for access in result.access_gained:
                evidence_lines.append(f"- {access}")
            evidence_lines.append("")

        if result.false_positive_indicators:
            evidence_lines.extend([
                "### False Positive Considerations",
                "",
            ])
            for indicator in result.false_positive_indicators:
                evidence_lines.append(f"- {indicator}")
            evidence_lines.append("")

        if result.http_changes:
            evidence_lines.extend([
                "### HTTP-Level Changes",
                "",
                "#### Status Code Changes",
            ])
            if result.http_changes.changed_status_codes:
                for url, changes in result.http_changes.changed_status_codes.items():
                    evidence_lines.append(
                        f"- `{url}`: {changes.get('before')} → {changes.get('after')}"
                    )
            else:
                evidence_lines.append("- None detected")

            evidence_lines.extend([
                "",
                "#### New Accessible Endpoints",
            ])
            if result.http_changes.new_endpoints_accessible:
                for url in result.http_changes.new_endpoints_accessible:
                    evidence_lines.append(f"- `{url}`")
            else:
                evidence_lines.append("- None detected")

        return "\n".join(evidence_lines)

    @staticmethod
    def generate_json_report(result: ExploitationResult) -> str:
        """Generate JSON report for tool integration."""
        return json.dumps(result.to_dict(), indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator — Main validation flow
# ─────────────────────────────────────────────────────────────────────────────

class BehavioralValidator:
    """Orchestrates the complete validation workflow."""

    def __init__(self, target_url: str, console=None):
        self.target_url = target_url
        self.console = console
        self.baseline = None
        self.monitor = None

    def _print(self, msg: str, style: str = ""):
        """Print with optional rich styling."""
        if self.console and HAS_RICH:
            self.console.print(msg, style=style)
        else:
            print(msg)

    def validate_poc(self, poc_script: str, measure: str = "basic",
                    custom_indicators: List[str] = None) -> ExploitationResult:
        """Run complete validation workflow with multi-vector confirmation."""
        self._print(f"\n[bold cyan]Starting PoC Validation[/bold cyan] → {self.target_url}")

        # Phase 1: Baseline capture
        self._print("[yellow]Phase 1:[/yellow] Capturing baseline...")
        self.baseline = BaselineCapture(self.target_url)
        baseline_snapshots = self.baseline.capture_common_endpoints()
        self._print(f"  ✓ Captured {len(baseline_snapshots)} baseline snapshots")

        # Phase 2: Execute PoC
        self._print("[yellow]Phase 2:[/yellow] Executing PoC...")
        poc_output, execution_success = self._execute_poc(poc_script)
        self._print(f"  ✓ PoC execution: {'successful' if execution_success else 'failed'}")

        # Validate PoC output format
        valid_output, output_msg = FalsePositiveEliminator.validate_poc_output_format(poc_output)
        self._print(f"  ✓ PoC output validation: {output_msg}")

        # Phase 3: Post-exploit monitoring
        self._print("[yellow]Phase 3:[/yellow] Monitoring post-exploit state...")
        self.monitor = BehaviorMonitor(self.target_url)
        time.sleep(0.5)  # Give app time to settle
        post_exploit_snapshots = {}
        for url in baseline_snapshots.keys():
            path = url.replace(self.target_url, "")
            snap = self.monitor.capture_post_exploit_state(path)
            if snap:
                post_exploit_snapshots[url] = snap
        self._print(f"  ✓ Captured {len(post_exploit_snapshots)} post-exploit snapshots")

        # Phase 4: Delta analysis
        self._print("[yellow]Phase 4:[/yellow] Analyzing behavior changes...")
        http_delta = DeltaAnalyzer.analyze_http_changes(baseline_snapshots, post_exploit_snapshots)
        data_exposure = DeltaAnalyzer.extract_data_exposure(
            "\n".join(s.body for s in baseline_snapshots.values()),
            "\n".join(s.body for s in post_exploit_snapshots.values()),
        )
        http_delta.data_exposure = data_exposure

        # Detect timing anomalies
        timing_anomalies = DeltaAnalyzer.detect_timing_anomalies(list(post_exploit_snapshots.values()))
        http_delta.timing_anomalies = timing_anomalies

        self._print(f"  ✓ Detected {len(http_delta.changed_status_codes)} status changes")
        self._print(f"  ✓ Detected {sum(data_exposure.values())} exposed data items")
        if timing_anomalies:
            self._print(f"  ✓ Detected {len(timing_anomalies)} timing anomalies")

        # Phase 5: Multi-vector success confirmation
        self._print("[yellow]Phase 5:[/yellow] Multi-vector success confirmation...")
        success, confidence, impact_type = self._confirm_success_multipath(
            poc_output, http_delta, custom_indicators, poc_script
        )
        self._print(f"  ✓ Exploitation confidence: {confidence * 100:.1f}%")
        self._print(f"  ✓ Primary impact vector: {impact_type}")

        # Phase 6: Impact measurement (if requested)
        impact_severity = "low"
        access_gained = []

        if measure in ("impact", "full"):
            self._print("[yellow]Phase 6:[/yellow] Quantifying impact...")
            if data_exposure:
                impact_data = ImpactQuantifier.quantify_data_exposure(data_exposure)
                self._print(f"  ✓ Estimated {impact_data['estimated_records']} records exposed")
                self._print(f"  ✓ Severity estimate: {impact_data['severity_estimate']}")

            if success and impact_type == "privilege_escalation":
                privesc_data = ImpactQuantifier.quantify_privilege_escalation(access_gained)
                self._print(f"  ✓ Privilege escalation: {privesc_data['access_level_before']} → {privesc_data['access_level_after']}")

            cvss_score, impact_severity = ImpactQuantifier.estimate_cvss_impact(
                impact_type, http_delta, data_exposure
            )
            self._print(f"  ✓ Estimated CVSS 3.1: {cvss_score} ({impact_severity})")

        # Phase 7: False positive checking with validation
        self._print("[yellow]Phase 7:[/yellow] False positive detection...")
        fp_risk, fp_indicators = FalsePositiveEliminator.check_false_positives(
            http_delta, poc_output
        )
        self._print(f"  ✓ False positive risk: {fp_risk * 100:.1f}%")
        for indicator in fp_indicators[:3]:
            self._print(f"    ⚠ {indicator}")

        # Phase 8: Final verdict
        self._print("[yellow]Phase 8:[/yellow] Final exploitation verdict...")
        final_success = success and fp_risk < 0.5
        verdict = "CONFIRMED" if final_success else "LIKELY FALSE POSITIVE" if fp_risk > 0.7 else "UNCONFIRMED"
        self._print(f"  ✓ Final verdict: {verdict}")

        # Compile result
        result = ExploitationResult(
            exploit_executed=execution_success,
            success_confirmed=final_success,
            confidence_score=confidence * (1 - fp_risk),  # Adjust for FP risk
            evidence=self._extract_evidence(poc_output, http_delta),
            impact_type=impact_type,
            impact_severity=impact_severity,
            data_exfiltrated={"exposed_patterns": data_exposure} if data_exposure else {},
            access_gained=access_gained,
            false_positive_risk=fp_risk,
            false_positive_indicators=fp_indicators,
            poc_output=poc_output[:2000],  # truncate
            http_changes=http_delta,
        )

        return result

    def _execute_poc(self, poc_script: str) -> Tuple[str, bool]:
        """Execute PoC script and capture output."""
        try:
            # Try to execute as Python
            if poc_script.strip().startswith("#!/") or poc_script.strip().startswith("python"):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                    f.write(poc_script)
                    f.flush()
                    result = subprocess.run(
                        [sys.executable, f.name],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    os.unlink(f.name)
                    return result.stdout + result.stderr, result.returncode == 0

            # Try as bash
            elif poc_script.strip().startswith("#!") and "bash" in poc_script.split("\n")[0]:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                    f.write(poc_script)
                    f.flush()
                    result = subprocess.run(
                        ["bash", f.name],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    os.unlink(f.name)
                    return result.stdout + result.stderr, result.returncode == 0

            # Try as curl command
            elif "curl" in poc_script:
                result = subprocess.run(
                    poc_script,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                return result.stdout + result.stderr, result.returncode == 0

            else:
                # Fallback: try to run as shell command
                result = subprocess.run(
                    poc_script,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                return result.stdout + result.stderr, result.returncode == 0

        except subprocess.TimeoutExpired:
            return "PoC execution timeout after 30s", False
        except Exception as e:
            return str(e), False

    def _confirm_success_multipath(self, poc_output: str, http_delta: BehaviorDelta,
                                   custom_indicators: List[str] = None,
                                   poc_script: str = "") -> Tuple[bool, float, str]:
        """Multi-vector success confirmation with impact type detection."""
        vectors = {}  # impact_type -> (success, confidence)

        # Custom indicators vector
        if custom_indicators:
            success, conf = SuccessConfirmer.confirm_from_indicators(poc_output, http_delta, custom_indicators)
            if success:
                vectors["custom"] = (True, conf)

        # RCE vector
        rce_success, rce_conf = SuccessConfirmer.confirm_rce(poc_output)
        if rce_success:
            vectors["rce"] = (True, rce_conf)

        # Auth bypass vector
        auth_success, auth_conf = SuccessConfirmer.confirm_auth_bypass(http_delta)
        if auth_success:
            vectors["auth_bypass"] = (True, auth_conf)

        # Data exposure vector
        data_success, data_conf = SuccessConfirmer.confirm_data_exposure(http_delta)
        if data_success:
            vectors["data_exposure"] = (True, data_conf)

        # Timing attack vector (blind SQLi, etc.)
        timing_success, timing_conf = SuccessConfirmer.confirm_timing_attack(http_delta)
        if timing_success:
            vectors["timing_attack"] = (True, timing_conf)

        # Error-based vector
        error_success, error_conf = SuccessConfirmer.confirm_error_based(poc_output, http_delta)
        if error_success:
            vectors["error_based"] = (True, error_conf)

        # Determine primary impact type and success
        if vectors:
            # Get best confidence
            best_vector = max(vectors.items(), key=lambda x: x[1][1])
            impact_type = best_vector[0]
            confidence = best_vector[1][1]

            # Check for multiple confirming vectors
            confirming_vectors = sum(1 for _, (success, _) in vectors.items() if success)
            if confirming_vectors > 1:
                confidence = min(confidence * 1.1, 1.0)

            return True, confidence, impact_type
        else:
            # Fallback: any changes + successful execution
            if http_delta.has_changes() and poc_output:
                return True, 0.5, "unknown"
            return False, 0.0, "unknown"

    def _confirm_success(self, poc_output: str, http_delta: BehaviorDelta,
                        custom_indicators: List[str] = None) -> Tuple[bool, float]:
        """Determine if exploitation was successful (legacy method)."""
        success, confidence, _ = self._confirm_success_multipath(poc_output, http_delta, custom_indicators)
        return success, confidence

    def _extract_evidence(self, poc_output: str, http_delta: BehaviorDelta) -> List[str]:
        """Extract key evidence items."""
        evidence = []

        if poc_output:
            # Truncate for display
            truncated = poc_output[:200]
            evidence.append(f"PoC execution output: {truncated}...")

        if http_delta.changed_status_codes:
            evidence.append(f"Detected {len(http_delta.changed_status_codes)} HTTP status changes")

        if http_delta.new_endpoints_accessible:
            evidence.append(f"Found {len(http_delta.new_endpoints_accessible)} newly accessible endpoints")

        if http_delta.data_exposure:
            evidence.append(f"Data exposure detected: {sum(http_delta.data_exposure.values())} items")

        return evidence


# ─────────────────────────────────────────────────────────────────────────────
# CLI Integration
# ─────────────────────────────────────────────────────────────────────────────

def cmd_validate(args, console=None):
    """
    hakuza validate --poc <script.py> --target <url> [--measure basic|impact|full]

    Validate PoC against target and measure exploitation impact.
    """
    poc_file = getattr(args, "poc", None)
    target = getattr(args, "target", None)
    measure = getattr(args, "measure", "basic") or "basic"
    indicators = getattr(args, "indicators", None) or None

    if not poc_file or not target:
        if console and HAS_RICH:
            console.print("[red]Error:[/red] --poc and --target are required")
        else:
            print("Error: --poc and --target are required")
        return

    # Read PoC file
    try:
        with open(poc_file, "r") as f:
            poc_script = f.read()
    except FileNotFoundError:
        if console and HAS_RICH:
            console.print(f"[red]Error:[/red] PoC file not found: {poc_file}")
        else:
            print(f"Error: PoC file not found: {poc_file}")
        return

    # Parse custom indicators if provided
    custom_indicators = None
    if indicators:
        custom_indicators = indicators.split(",")

    # Run validation
    validator = BehavioralValidator(target, console=console)
    result = validator.validate_poc(poc_script, measure=measure, custom_indicators=custom_indicators)

    # Output results
    if console and HAS_RICH:
        _print_result_table(console, result)
    else:
        print(json.dumps(result.to_dict(), indent=2))

    # Save report
    report_path = Path(poc_file).stem + "_validation_report.json"
    with open(report_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)

    if console and HAS_RICH:
        console.print(f"\n[green]✓[/green] Report saved to {report_path}")
    else:
        print(f"\nReport saved to {report_path}")


def _print_result_table(console, result: ExploitationResult):
    """Print validation result as rich table."""
    from rich.panel import Panel

    # Summary panel
    summary_text = (
        f"[bold]Execution:[/bold] {'✓' if result.exploit_executed else '✗'}\n"
        f"[bold]Success:[/bold] {'✓' if result.success_confirmed else '✗'}\n"
        f"[bold]Confidence:[/bold] {result.confidence_score * 100:.1f}%\n"
        f"[bold]Impact:[/bold] {result.impact_type.upper()} ({result.impact_severity})\n"
        f"[bold]False Positive Risk:[/bold] {result.false_positive_risk * 100:.1f}%"
    )
    console.print(Panel(summary_text, title="[bold cyan]Validation Summary[/bold cyan]"))

    # Evidence table
    if result.evidence:
        table = Table(title="Evidence", box=box.ROUNDED)
        table.add_column("Item", style="cyan")
        for item in result.evidence:
            table.add_row(item)
        console.print(table)

    # Data exposure
    if result.data_exfiltrated:
        table = Table(title="Data Exposure", box=box.ROUNDED)
        table.add_column("Category", style="yellow")
        table.add_column("Count", style="red")
        for key, value in result.data_exfiltrated.items():
            if isinstance(value, dict):
                for subkey, subval in value.items():
                    table.add_row(subkey, str(subval))
        console.print(table)

    # False positive indicators
    if result.false_positive_indicators:
        table = Table(title="False Positive Indicators", box=box.ROUNDED)
        table.add_column("Indicator", style="yellow")
        for indicator in result.false_positive_indicators:
            table.add_row(indicator)
        console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HAKUZA Behavioral Validator")
    parser.add_argument("--poc", required=True, help="Path to PoC script")
    parser.add_argument("--target", required=True, help="Target URL (http://...)")
    parser.add_argument("--measure", choices=["basic", "impact", "full"], default="basic",
                       help="Measurement level")
    parser.add_argument("--indicators", help="Comma-separated custom success indicators")

    args = parser.parse_args()

    try:
        console = Console() if HAS_RICH else None
        cmd_validate(args, console)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
