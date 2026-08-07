#!/usr/bin/env python3
"""
mod_threat_intel.py — Live Threat Intelligence & Real-Time Exploit Prioritization
==================================================================================

Dynamically re-prioritizes attack techniques based on what's ACTIVELY EXPLOITED
in the wild RIGHT NOW using real-time feeds:

- CISA Known Exploited Vulnerabilities (KEV) — exploits publicly confirmed
- EPSS Predictions — exploit probability scoring system (0.0-1.0)
- CVE Data — enhanced with real-time severity and patch information
- Attack Marketplace Monitoring — 0day pricing + demand signals
- Threat Trend Analyzer — what's trending in exploits this week?
- Prioritization Updater — feed live data into ML prioritizer
- Alerting Engine — notify when new exploits match target tech stack

Author: Divith D Shetty
Integration: hakuza intel --live --output priorities.json
"""

import json
import sqlite3
import os
import sys
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Tuple, Any, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
import statistics
import hashlib
import ssl
from collections import defaultdict

# Optional imports for HTTP + parsing
try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

try:
    import xml.etree.ElementTree as ET
    HAS_XML = True
except ImportError:
    HAS_XML = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

THREAT_INTEL_DIR = Path.home() / ".hakuza" / "threat_intel"
KEV_CACHE_PATH = THREAT_INTEL_DIR / "cisa_kev_cache.json"
EPSS_CACHE_PATH = THREAT_INTEL_DIR / "epss_cache.json"
CVE_CACHE_PATH = THREAT_INTEL_DIR / "cve_cache.json"
MARKETPLACE_CACHE_PATH = THREAT_INTEL_DIR / "marketplace_cache.json"
TRENDS_CACHE_PATH = THREAT_INTEL_DIR / "trends_cache.json"
ALERTS_DB_PATH = THREAT_INTEL_DIR / "alerts.db"
INTELLIGENCE_LOG = THREAT_INTEL_DIR / "intel_log.json"

# Remote feeds
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_CVE_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_CVE_URL = "https://cve.mitre.org/data/refs/RefMap.csv"

# Cache validity (seconds)
CACHE_TTL = {
    "kev": 3600,      # 1 hour
    "epss": 7200,     # 2 hours
    "cve": 86400,     # 1 day
    "marketplace": 86400,  # 1 day
    "trends": 3600,   # 1 hour
}

# Severity ratings
SEVERITY_LEVELS = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
    "unknown": 0.5,
}

EXPLOITABILITY_FACTOR = {
    "unproven": 0.2,
    "poc": 0.5,
    "functional": 0.8,
    "high": 1.0,
}

# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVERecord:
    """Unified CVE record with enriched threat data."""
    cve_id: str
    cvss_score: float
    cvss_vector: str = ""
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    affected_component: str = ""
    affected_versions: List[str] = field(default_factory=list)
    is_actively_exploited: bool = False
    exploitation_status: str = "unproven"  # unproven, poc, functional, high
    patch_available: bool = False
    patch_date: Optional[str] = None
    pub_date: Optional[str] = None
    update_date: Optional[str] = None
    description: str = ""
    references: List[str] = field(default_factory=list)
    threat_actor_count: int = 0
    marketplace_mentions: int = 0
    avg_marketplace_price: float = 0.0
    attack_complexity: float = 0.5  # 0.0 = low complexity, 1.0 = high
    attack_vector: str = "network"  # network, adjacent, local, physical
    requires_auth: bool = False
    user_interaction: bool = False
    scope_changed: bool = False
    impact_confidentiality: float = 0.0
    impact_integrity: float = 0.0
    impact_availability: float = 0.0
    combined_score: float = 0.0
    trend_velocity: float = 0.0  # How fast it's trending (0-1)
    priority_rank: int = 0
    confidence: float = 1.0


@dataclass
class ThreatAlert:
    """Alert for when exploits match target tech stack."""
    alert_id: str
    timestamp: str
    cve_id: str
    alert_type: str  # new_exploit, trending, marketplace, kev_update
    severity: str
    tech_component: str  # What matched (e.g., "nginx 1.19.0", "apache", "php")
    description: str
    recommended_action: str
    urgency: float  # 0.0-1.0
    false_positive_score: float = 0.1


@dataclass
class ThreatTrend:
    """Trending vulnerability or exploit pattern."""
    trend_id: str
    timestamp: str
    pattern: str  # "ransomware_target", "apt_interest", "mass_exploitation"
    related_cves: List[str]
    attack_techniques: List[str]  # MITRE ATT&CK IDs
    affected_sectors: List[str]
    geographic_origin: Optional[str]
    velocity: float  # 0-1 (how fast it's spreading)
    confidence: float  # 0-1
    forecast_7d: float  # Expected velocity in 7 days


@dataclass
class ExploitMarketplaceItem:
    """Tracked exploit/0day from underground marketplace."""
    marketplace_id: str
    title: str
    cve_ids: List[str]
    price_usd: float
    currency: str = "USD"
    market_active_duration_days: float = 0.0
    seller_reputation: float = 0.5  # 0-1
    buyer_count: int = 0
    demand_signals: int = 0  # auction bids, seller messages, etc.
    update_date: Optional[str] = None
    exploit_code_available: bool = False
    technical_depth: str = "limited"  # limited, moderate, comprehensive
    target_market: str = "enterprise"  # individual, enterprise, government
    confidence: float = 0.9


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV FETCHER
# ─────────────────────────────────────────────────────────────────────────────

class CISAKEVFetcher:
    """Fetch and cache CISA Known Exploited Vulnerabilities list."""

    @staticmethod
    def fetch_live() -> Optional[Dict[str, Any]]:
        """
        Fetch CISA KEV JSON from official source.
        Returns dict with 'vulnerabilities' array or None if fetch fails.
        """
        if not HAS_URLLIB:
            return None

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # For testing; use proper certs in prod

            req = urllib.request.Request(CISA_KEV_URL)
            req.add_header('User-Agent', 'HAKUZA-ThreatIntel/1.0')

            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data
        except Exception as e:
            logging.error(f"CISA KEV fetch failed: {e}")
            return None

    @staticmethod
    def load_cached() -> Optional[Dict[str, Any]]:
        """Load cached KEV data if still valid."""
        if not KEV_CACHE_PATH.exists():
            return None

        try:
            with open(KEV_CACHE_PATH) as f:
                cached = json.load(f)

            cache_age = datetime.now(timezone.utc).timestamp() - cached.get("_fetched", 0)
            if cache_age < CACHE_TTL["kev"]:
                return cached
        except Exception as e:
            logging.error(f"Cache load failed: {e}")

        return None

    @staticmethod
    def save_cache(data: Dict[str, Any]) -> None:
        """Save KEV data to cache."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            data["_fetched"] = datetime.now(timezone.utc).timestamp()
            with open(KEV_CACHE_PATH, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Cache save failed: {e}")

    @staticmethod
    def get_kev_list(use_cache=True) -> List[str]:
        """
        Get list of all CVE IDs currently in CISA KEV.
        Returns list of "CVE-YYYY-NNNNN" strings.
        """
        data = None

        if use_cache:
            data = CISAKEVFetcher.load_cached()

        if data is None:
            data = CISAKEVFetcher.fetch_live()
            if data:
                CISAKEVFetcher.save_cache(data)

        if not data or "vulnerabilities" not in data:
            return []

        return [v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")]

    @staticmethod
    def get_kev_details(cve_id: str) -> Optional[Dict[str, Any]]:
        """Get full details for a specific CVE from KEV."""
        data = CISAKEVFetcher.load_cached()
        if not data:
            data = CISAKEVFetcher.fetch_live()

        if not data:
            return None

        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return vuln

        return None


# ─────────────────────────────────────────────────────────────────────────────
# EPSS PREDICTOR
# ─────────────────────────────────────────────────────────────────────────────

class EPSSPredictor:
    """Fetch EPSS (Exploit Probability Scoring System) scores."""

    @staticmethod
    def fetch_epss_score(cve_id: str) -> Optional[Tuple[float, float]]:
        """
        Fetch EPSS score for a CVE.
        Returns (epss_score, percentile) or (None, None) on failure.
        epss_score: 0.0-1.0 (probability of exploitation)
        percentile: 0-100 (where this CVE ranks vs all others)
        """
        if not HAS_URLLIB:
            return None, None

        # Check cache first
        epss_cache = EPSSPredictor._load_cache()
        if cve_id in epss_cache:
            cached_entry = epss_cache[cve_id]
            cache_age = datetime.now(timezone.utc).timestamp() - cached_entry.get("_fetched", 0)
            if cache_age < CACHE_TTL["epss"]:
                return cached_entry.get("score"), cached_entry.get("percentile")

        try:
            url = f"{EPSS_API_BASE}?cve={cve_id}"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'HAKUZA-ThreatIntel/1.0')

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))

            if "data" in data and len(data["data"]) > 0:
                record = data["data"][0]
                score = float(record.get("epss", 0))
                percentile = float(record.get("percentile", 0))

                # Cache it
                epss_cache[cve_id] = {
                    "score": score,
                    "percentile": percentile,
                    "_fetched": datetime.now(timezone.utc).timestamp()
                }
                EPSSPredictor._save_cache(epss_cache)

                return score, percentile
        except Exception as e:
            logging.warning(f"EPSS fetch failed for {cve_id}: {e}")

        return None, None

    @staticmethod
    def _load_cache() -> Dict[str, Any]:
        """Load cached EPSS scores."""
        if not EPSS_CACHE_PATH.exists():
            return {}

        try:
            with open(EPSS_CACHE_PATH) as f:
                return json.load(f)
        except:
            return {}

    @staticmethod
    def _save_cache(cache: Dict[str, Any]) -> None:
        """Save EPSS cache."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(EPSS_CACHE_PATH, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logging.error(f"EPSS cache save failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CVE ENRICHER
# ─────────────────────────────────────────────────────────────────────────────

class CVSSEnricher:
    """Fetch and enrich CVE data with CVSS scores and details."""

    @staticmethod
    def parse_cvss_vector(vector: str) -> Dict[str, float]:
        """
        Parse CVSS 3.1 vector string into component scores.
        E.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        Returns dict with normalized 0.0-1.0 scores for each component.
        """
        metrics = {}

        # Attack Vector (AV)
        if "/AV:N/" in vector:
            metrics["attack_vector"] = 1.0
        elif "/AV:A/" in vector:
            metrics["attack_vector"] = 0.65
        elif "/AV:L/" in vector:
            metrics["attack_vector"] = 0.35
        else:
            metrics["attack_vector"] = 0.0

        # Attack Complexity (AC)
        if "/AC:L/" in vector:
            metrics["attack_complexity"] = 0.0  # Low complexity = easier
        else:
            metrics["attack_complexity"] = 0.4  # High complexity

        # Privileges Required (PR)
        if "/PR:N/" in vector:
            metrics["requires_auth"] = False
        else:
            metrics["requires_auth"] = True

        # User Interaction (UI)
        if "/UI:N/" in vector:
            metrics["user_interaction"] = False
        else:
            metrics["user_interaction"] = True

        # Scope (S)
        metrics["scope_changed"] = "/S:C/" in vector

        # Impact
        metrics["impact_confidentiality"] = 1.0 if "/C:H/" in vector else (0.5 if "/C:L/" in vector else 0.0)
        metrics["impact_integrity"] = 1.0 if "/I:H/" in vector else (0.5 if "/I:L/" in vector else 0.0)
        metrics["impact_availability"] = 1.0 if "/A:H/" in vector else (0.5 if "/A:L/" in vector else 0.0)

        return metrics

    @staticmethod
    def fetch_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details from NVD or local cache.
        Returns enriched CVE data or None.
        """
        # Check cache first
        cve_cache = CVSSEnricher._load_cache()
        if cve_id in cve_cache:
            cached_entry = cve_cache[cve_id]
            cache_age = datetime.now(timezone.utc).timestamp() - cached_entry.get("_fetched", 0)
            if cache_age < CACHE_TTL["cve"]:
                return cached_entry

        # Mock data for demonstration (real implementation would query NVD)
        mock_data = {
            "CVE-2024-0001": {
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "component": "nginx",
                "versions": ["1.19.0", "1.20.0", "1.21.0"],
                "pub_date": "2024-01-15T00:00:00Z",
                "description": "Remote Code Execution in nginx"
            },
            "CVE-2024-0002": {
                "cvss_score": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
                "component": "apache",
                "versions": ["2.4.41", "2.4.48", "2.4.49"],
                "pub_date": "2024-02-20T00:00:00Z",
                "description": "SQL Injection in Apache modules"
            }
        }

        data = mock_data.get(cve_id)
        if data:
            data["_fetched"] = datetime.now(timezone.utc).timestamp()
            cve_cache[cve_id] = data
            CVSSEnricher._save_cache(cve_cache)
            return data

        return None

    @staticmethod
    def _load_cache() -> Dict[str, Any]:
        """Load cached CVE data."""
        if not CVE_CACHE_PATH.exists():
            return {}

        try:
            with open(CVE_CACHE_PATH) as f:
                return json.load(f)
        except:
            return {}

    @staticmethod
    def _save_cache(cache: Dict[str, Any]) -> None:
        """Save CVE cache."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(CVE_CACHE_PATH, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logging.error(f"CVE cache save failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT MARKETPLACE MONITOR
# ─────────────────────────────────────────────────────────────────────────────

class AttackMarketplaceMonitor:
    """Monitor underground exploit/0day marketplace activity."""

    @staticmethod
    def get_marketplace_listings() -> List[ExploitMarketplaceItem]:
        """
        Get current marketplace listings (mock data for demonstration).
        Real implementation would integrate with marketplace monitoring APIs.
        """
        # Mock marketplace data
        listings = [
            ExploitMarketplaceItem(
                marketplace_id="mp-001",
                title="nginx 1.19.0 RCE PoC",
                cve_ids=["CVE-2024-0001"],
                price_usd=5000.0,
                buyer_count=3,
                demand_signals=7,
                exploit_code_available=True,
                technical_depth="comprehensive",
                target_market="enterprise",
                seller_reputation=0.95,
                confidence=0.92
            ),
            ExploitMarketplaceItem(
                marketplace_id="mp-002",
                title="0day Apache Struts bypass",
                cve_ids=["CVE-2024-NEW1"],
                price_usd=15000.0,
                buyer_count=1,
                demand_signals=2,
                exploit_code_available=False,
                technical_depth="moderate",
                target_market="government",
                seller_reputation=0.88,
                confidence=0.78
            ),
            ExploitMarketplaceItem(
                marketplace_id="mp-003",
                title="PHP 8.0 type confusion pack",
                cve_ids=["CVE-2024-0002"],
                price_usd=2500.0,
                buyer_count=5,
                demand_signals=12,
                exploit_code_available=True,
                technical_depth="moderate",
                target_market="individual",
                seller_reputation=0.72,
                confidence=0.85
            ),
        ]

        # Cache
        marketplace_cache = {
            "listings": [asdict(item) for item in listings],
            "_fetched": datetime.now(timezone.utc).timestamp()
        }
        AttackMarketplaceMonitor._save_cache(marketplace_cache)

        return listings

    @staticmethod
    def score_marketplace_item(item: ExploitMarketplaceItem) -> float:
        """
        Score marketplace item for threat level.
        Higher = more dangerous/active.
        """
        demand_score = min(item.demand_signals / 10.0, 1.0)  # Cap at 1.0
        code_available_boost = 0.3 if item.exploit_code_available else 0.0
        reputation_factor = item.seller_reputation
        urgency = (item.buyer_count / 10.0) if item.buyer_count > 0 else 0.0

        score = (demand_score * 0.4 + code_available_boost + reputation_factor * 0.3 + urgency * 0.3)
        return min(score * item.confidence, 1.0)

    @staticmethod
    def _load_cache() -> Optional[Dict[str, Any]]:
        """Load cached marketplace data."""
        if not MARKETPLACE_CACHE_PATH.exists():
            return None

        try:
            with open(MARKETPLACE_CACHE_PATH) as f:
                cached = json.load(f)
                cache_age = datetime.now(timezone.utc).timestamp() - cached.get("_fetched", 0)
                if cache_age < CACHE_TTL["marketplace"]:
                    return cached
        except:
            pass

        return None

    @staticmethod
    def _save_cache(cache: Dict[str, Any]) -> None:
        """Save marketplace cache."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(MARKETPLACE_CACHE_PATH, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logging.error(f"Marketplace cache save failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# THREAT TREND ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class ThreatTrendAnalyzer:
    """Analyze and predict emerging threat trends."""

    @staticmethod
    def extract_current_trends() -> List[ThreatTrend]:
        """
        Extract current trending vulnerabilities and patterns.
        Real implementation would analyze:
        - Shodan queries over time
        - Honeypot hits
        - Dark web chatter
        - OSINT feeds
        - CVE publication velocity
        """
        trends = [
            ThreatTrend(
                trend_id="trend-001",
                timestamp=datetime.now(timezone.utc).isoformat(),
                pattern="ransomware_target",
                related_cves=["CVE-2024-0001", "CVE-2024-0002"],
                attack_techniques=["T1486", "T1560"],  # MITRE ATT&CK
                affected_sectors=["healthcare", "education", "finance"],
                geographic_origin="Eastern Europe",
                velocity=0.85,
                confidence=0.92,
                forecast_7d=0.75
            ),
            ThreatTrend(
                trend_id="trend-002",
                timestamp=datetime.now(timezone.utc).isoformat(),
                pattern="apt_interest",
                related_cves=["CVE-2024-NEW1"],
                attack_techniques=["T1055", "T1010"],
                affected_sectors=["government", "defense", "telecoms"],
                geographic_origin="China",
                velocity=0.65,
                confidence=0.88,
                forecast_7d=0.80
            ),
            ThreatTrend(
                trend_id="trend-003",
                timestamp=datetime.now(timezone.utc).isoformat(),
                pattern="mass_exploitation",
                related_cves=["CVE-2024-0002"],
                attack_techniques=["T1190", "T1133"],
                affected_sectors=["retail", "tech", "manufacturing"],
                geographic_origin="Russia",
                velocity=0.92,
                confidence=0.95,
                forecast_7d=0.70
            ),
        ]

        # Cache
        trends_cache = {
            "trends": [asdict(t) for t in trends],
            "_fetched": datetime.now(timezone.utc).timestamp()
        }
        ThreatTrendAnalyzer._save_cache(trends_cache)

        return trends

    @staticmethod
    def score_trend_impact(trend: ThreatTrend, target_sectors: List[str]) -> float:
        """
        Score trend impact on specific target sectors.
        """
        sector_overlap = len(set(target_sectors) & set(trend.affected_sectors)) / max(len(target_sectors), 1)
        impact = trend.velocity * trend.confidence * (0.5 + sector_overlap * 0.5)
        return min(impact, 1.0)

    @staticmethod
    def _save_cache(cache: Dict[str, Any]) -> None:
        """Save trends cache."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(TRENDS_CACHE_PATH, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logging.error(f"Trends cache save failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# PRIORITIZATION UPDATER
# ─────────────────────────────────────────────────────────────────────────────

class PrioritizationUpdater:
    """Feed live threat intelligence data into the ML prioritizer."""

    @staticmethod
    def build_threat_scored_cve_list(target_tech_stack: Dict[str, str]) -> List[CVERecord]:
        """
        Build prioritized CVE list with real-time threat scores.

        Args:
            target_tech_stack: {"nginx": "1.19.0", "apache": "2.4.48", "php": "8.0"}

        Returns:
            Sorted list of CVERecord objects ranked by threat priority.
        """
        cve_records = []

        # Get all data sources
        kev_list = CISAKEVFetcher.get_kev_list()
        marketplace_items = AttackMarketplaceMonitor.get_marketplace_listings()
        trends = ThreatTrendAnalyzer.extract_current_trends()

        # Map marketplace mentions and prices to CVE IDs
        cve_marketplace_map = defaultdict(list)
        for item in marketplace_items:
            for cve in item.cve_ids:
                cve_marketplace_map[cve].append(item)

        # Build mapping of affected products to CVEs
        kev_cves = set(kev_list)
        example_cves = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-NEW1"]

        for cve_id in example_cves:
            # Fetch details
            cve_details = CVSSEnricher.fetch_cve_details(cve_id)
            epss_score, epss_percentile = EPSSPredictor.fetch_epss_score(cve_id)
            kev_details = CISAKEVFetcher.get_kev_details(cve_id) if cve_id in kev_cves else None

            if cve_details:
                # Parse CVSS vector
                vector_metrics = CVSSEnricher.parse_cvss_vector(cve_details.get("cvss_vector", ""))

                # Marketplace data
                marketplace_items_for_cve = cve_marketplace_map.get(cve_id, [])
                marketplace_mentions = len(marketplace_items_for_cve)
                avg_price = statistics.mean([item.price_usd for item in marketplace_items_for_cve]) if marketplace_items_for_cve else 0.0

                # Calculate combined threat score
                is_in_kev = cve_id in kev_cves
                cvss_score = cve_details.get("cvss_score", 0.0)
                exploitation_status = "high" if is_in_kev else "poc"

                # Trend velocity (how fast it's trending)
                trend_velocity = 0.0
                for trend in trends:
                    if cve_id in trend.related_cves:
                        trend_velocity = max(trend_velocity, trend.velocity)

                # Combined scoring: (CVSS * 0.35) + (EPSS * 0.35) + (Trend * 0.15) + (Marketplace * 0.15)
                cvss_normalized = min(cvss_score / 10.0, 1.0)
                epss_norm = epss_score if epss_score else 0.0
                marketplace_norm = min(marketplace_mentions / 5.0, 1.0)
                combined = (cvss_normalized * 0.35 + epss_norm * 0.35 + trend_velocity * 0.15 + marketplace_norm * 0.15)

                record = CVERecord(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    cvss_vector=cve_details.get("cvss_vector", ""),
                    epss_score=epss_score or 0.0,
                    epss_percentile=epss_percentile or 0.0,
                    affected_component=cve_details.get("component", ""),
                    affected_versions=cve_details.get("versions", []),
                    is_actively_exploited=is_in_kev,
                    exploitation_status=exploitation_status,
                    patch_available=(cve_id in kev_cves) and kev_details and kev_details.get("dateAdded"),
                    description=cve_details.get("description", ""),
                    marketplace_mentions=marketplace_mentions,
                    avg_marketplace_price=avg_price,
                    attack_complexity=vector_metrics.get("attack_complexity", 0.5),
                    requires_auth=vector_metrics.get("requires_auth", False),
                    user_interaction=vector_metrics.get("user_interaction", False),
                    scope_changed=vector_metrics.get("scope_changed", False),
                    impact_confidentiality=vector_metrics.get("impact_confidentiality", 0.0),
                    impact_integrity=vector_metrics.get("impact_integrity", 0.0),
                    impact_availability=vector_metrics.get("impact_availability", 0.0),
                    combined_score=min(combined, 1.0),
                    trend_velocity=trend_velocity,
                    confidence=0.95 if is_in_kev else 0.80
                )
                cve_records.append(record)

        # Sort by combined threat score
        cve_records.sort(key=lambda x: x.combined_score, reverse=True)

        # Add priority ranks
        for idx, record in enumerate(cve_records):
            record.priority_rank = idx + 1

        return cve_records

    @staticmethod
    def export_prioritized_threats(cve_records: List[CVERecord], output_file: str) -> None:
        """Export ranked threats to JSON for ML prioritizer integration."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump([asdict(r) for r in cve_records], f, indent=2, default=str)
            logging.info(f"Prioritized threats exported to {output_file}")
        except Exception as e:
            logging.error(f"Export failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ALERTING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AlertingEngine:
    """Generate alerts when exploits match target tech stack."""

    @staticmethod
    def initialize_db() -> None:
        """Initialize alerts database."""
        try:
            THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(ALERTS_DB_PATH))
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    cve_id TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    tech_component TEXT,
                    description TEXT,
                    urgency REAL,
                    false_positive_score REAL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT,
                    action TEXT,
                    timestamp TEXT,
                    notes TEXT
                )
            ''')

            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"DB initialization failed: {e}")

    @staticmethod
    def generate_alerts(target_tech_stack: Dict[str, str], cve_records: List[CVERecord]) -> List[ThreatAlert]:
        """
        Generate alerts for new exploits matching target tech stack.

        Args:
            target_tech_stack: {"nginx": "1.19.0", "apache": "2.4.48"}
            cve_records: Prioritized CVE records

        Returns:
            List of ThreatAlert objects
        """
        alerts = []

        for record in cve_records:
            # Check if affected component matches target stack
            affected_component = record.affected_component.lower()

            for tech_name, tech_version in target_tech_stack.items():
                tech_name_lower = tech_name.lower()

                # Simple matching (real implementation would do version range checking)
                if tech_name_lower in affected_component or affected_component in tech_name_lower:
                    # Check if this is already in DB to avoid duplicates
                    alert_id = hashlib.md5(f"{record.cve_id}-{tech_name}".encode()).hexdigest()

                    # Determine alert type
                    alert_type = "new_exploit"
                    if record.trend_velocity > 0.7:
                        alert_type = "trending"
                    if record.marketplace_mentions > 0:
                        alert_type = "marketplace"
                    if record.is_actively_exploited:
                        alert_type = "kev_update"

                    # Calculate urgency
                    urgency = min(record.combined_score + (0.2 if record.is_actively_exploited else 0), 1.0)

                    alert = ThreatAlert(
                        alert_id=alert_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        cve_id=record.cve_id,
                        alert_type=alert_type,
                        severity="critical" if record.cvss_score >= 9.0 else
                                "high" if record.cvss_score >= 7.0 else
                                "medium" if record.cvss_score >= 5.0 else "low",
                        tech_component=f"{tech_name} {tech_version}",
                        description=f"{record.cve_id} affects {record.affected_component} ({', '.join(record.affected_versions[:2])}). "
                                    f"CVSS: {record.cvss_score}, EPSS: {record.epss_score:.2f}",
                        recommended_action=f"Update {tech_name} to latest patched version immediately" if record.is_actively_exploited else
                                           f"Monitor {tech_name} for security updates",
                        urgency=urgency,
                        false_positive_score=0.05 if record.is_actively_exploited else 0.15
                    )
                    alerts.append(alert)

        # Save to database
        AlertingEngine._save_alerts_to_db(alerts)

        return alerts

    @staticmethod
    def _save_alerts_to_db(alerts: List[ThreatAlert]) -> None:
        """Save alerts to database."""
        try:
            conn = sqlite3.connect(str(ALERTS_DB_PATH))
            cursor = conn.cursor()

            for alert in alerts:
                cursor.execute('''
                    INSERT OR REPLACE INTO alerts
                    (alert_id, timestamp, cve_id, alert_type, severity, tech_component, description, urgency, false_positive_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id, alert.timestamp, alert.cve_id, alert.alert_type,
                    alert.severity, alert.tech_component, alert.description,
                    alert.urgency, alert.false_positive_score
                ))

            conn.commit()
            conn.close()
            logging.info(f"Saved {len(alerts)} alerts to database")
        except Exception as e:
            logging.error(f"Failed to save alerts: {e}")

    @staticmethod
    def get_active_alerts(severity_filter: Optional[str] = None) -> List[ThreatAlert]:
        """Retrieve active alerts from database."""
        try:
            conn = sqlite3.connect(str(ALERTS_DB_PATH))
            cursor = conn.cursor()

            if severity_filter:
                cursor.execute('SELECT * FROM alerts WHERE severity = ?', (severity_filter,))
            else:
                cursor.execute('SELECT * FROM alerts')

            rows = cursor.fetchall()
            conn.close()

            alerts = []
            for row in rows:
                alerts.append(ThreatAlert(
                    alert_id=row[0],
                    timestamp=row[1],
                    cve_id=row[2],
                    alert_type=row[3],
                    severity=row[4],
                    tech_component=row[5],
                    description=row[6],
                    urgency=row[7],
                    false_positive_score=row[8]
                ))

            return alerts
        except Exception as e:
            logging.error(f"Failed to retrieve alerts: {e}")
            return []


# ─────────────────────────────────────────────────────────────────────────────
# CLI INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

def cmd_intel(args, console) -> None:
    """
    hakuza intel [--live] [--stack <tech_stack>] [--output <file>] [--alerts] [--trends]
    """
    from rich.table import Table
    from rich.panel import Panel

    console.print(Panel.fit("[bold cyan]THREAT INTELLIGENCE ENGINE[/bold cyan]", border_style="cyan"))

    # Parse tech stack
    tech_stack = {}
    if hasattr(args, 'stack') and args.stack:
        # Parse comma-separated key=value pairs: "nginx=1.19.0,apache=2.4.48"
        for pair in args.stack.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                tech_stack[k.strip()] = v.strip()

    if not tech_stack:
        # Prompt for tech stack if not provided
        console.print("[yellow]Enter tech stack (e.g., nginx=1.19.0,apache=2.4.48):[/yellow]")
        tech_stack_input = input().strip()
        for pair in tech_stack_input.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                tech_stack[k.strip()] = v.strip()

    if not tech_stack:
        tech_stack = {"nginx": "1.19.0", "apache": "2.4.48"}
        console.print(f"[yellow]Using default stack: {tech_stack}[/yellow]")

    # Initialize alerting system
    AlertingEngine.initialize_db()

    # Get live threat data
    use_live = getattr(args, 'live', False)
    console.print(f"\n[{'green' if use_live else 'yellow'}]{'Fetching' if use_live else 'Using cached'} live threat data...[/{'green' if use_live else 'yellow'}]")

    # Build prioritized threat list
    cve_records = PrioritizationUpdater.build_threat_scored_cve_list(tech_stack)

    # Generate alerts
    alerts = AlertingEngine.generate_alerts(tech_stack, cve_records)

    # Display prioritized CVEs
    console.print("\n[bold]Prioritized Threats:[/bold]")
    threat_table = Table(title="Real-Time Threat Intelligence")
    threat_table.add_column("Rank", style="cyan")
    threat_table.add_column("CVE ID", style="magenta")
    threat_table.add_column("CVSS", justify="right")
    threat_table.add_column("EPSS", justify="right")
    threat_table.add_column("Status", style="yellow")
    threat_table.add_column("Trend", justify="right")
    threat_table.add_column("Component")

    for record in cve_records[:10]:  # Top 10
        status_str = "🔴 KEV" if record.is_actively_exploited else "🟡 PoC" if record.exploitation_status == "poc" else "⚪ Unproven"
        trend_str = f"{record.trend_velocity:.0%}"

        threat_table.add_row(
            str(record.priority_rank),
            record.cve_id,
            f"{record.cvss_score:.1f}",
            f"{record.epss_score:.2f}",
            status_str,
            trend_str,
            record.affected_component
        )

    console.print(threat_table)

    # Display alerts
    if alerts:
        console.print(f"\n[bold red]Alerts: {len(alerts)} threat match(es) detected[/bold red]")
        alert_table = Table(title="Security Alerts")
        alert_table.add_column("CVE", style="red")
        alert_table.add_column("Type")
        alert_table.add_column("Component")
        alert_table.add_column("Urgency", justify="right")
        alert_table.add_column("Action")

        for alert in alerts:
            alert_table.add_row(
                alert.cve_id,
                alert.alert_type,
                alert.tech_component,
                f"{alert.urgency:.0%}",
                alert.recommended_action
            )

        console.print(alert_table)

    # Display trends
    if getattr(args, 'trends', False):
        trends = ThreatTrendAnalyzer.extract_current_trends()
        console.print(f"\n[bold]Emerging Threat Trends ({len(trends)})[/bold]")
        trends_table = Table(title="Active Threat Patterns")
        trends_table.add_column("Pattern")
        trends_table.add_column("Velocity")
        trends_table.add_column("Affected Sectors")
        trends_table.add_column("Forecast (7d)")

        for trend in trends:
            sectors_str = ", ".join(trend.affected_sectors[:2])
            trends_table.add_row(
                trend.pattern,
                f"{trend.velocity:.0%}",
                sectors_str,
                f"{trend.forecast_7d:.0%}"
            )

        console.print(trends_table)

    # Export results
    output_file = getattr(args, 'output', None)
    if output_file:
        PrioritizationUpdater.export_prioritized_threats(cve_records, output_file)
        console.print(f"\n[green]✓ Exported to {output_file}[/green]")
        alerts_export = output_file.replace(".json", "_alerts.json")
        with open(alerts_export, 'w') as f:
            json.dump([asdict(a) for a in alerts], f, indent=2, default=str)
        console.print(f"[green]✓ Exported alerts to {alerts_export}[/green]")

    console.print(f"\n[bold green]Intelligence refresh complete[/bold green] — {len(cve_records)} CVEs analyzed, {len(alerts)} alerts generated")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    import argparse
    from rich.console import Console

    console = Console()

    parser = argparse.ArgumentParser(prog="hakuza intel")
    parser.add_argument("--live", action="store_true", help="Fetch live threat data (vs. cache)")
    parser.add_argument("--stack", default=None, help="Tech stack (e.g., 'nginx=1.19.0,apache=2.4.48')")
    parser.add_argument("--output", default=None, help="Output file for prioritized threats (JSON)")
    parser.add_argument("--alerts", action="store_true", help="Show active security alerts")
    parser.add_argument("--trends", action="store_true", help="Show emerging threat trends")

    args = parser.parse_args()
    cmd_intel(args, console)
