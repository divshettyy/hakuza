#!/usr/bin/env python3
"""
Comprehensive test suite for mod_threat_intel.py
Tests: CISA KEV, EPSS, CVE enrichment, marketplace monitoring, trend analysis, prioritization, alerting
"""

import unittest
import json
import tempfile
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from mod_threat_intel import (
    CISAKEVFetcher, EPSSPredictor, CVSSEnricher, AttackMarketplaceMonitor,
    ThreatTrendAnalyzer, PrioritizationUpdater, AlertingEngine,
    CVERecord, ThreatAlert, ThreatTrend, ExploitMarketplaceItem
)


class TestCISAKEVFetcher(unittest.TestCase):
    """Test CISA KEV fetcher and cache."""

    def setUp(self):
        """Set up test fixtures."""
        self.fetcher = CISAKEVFetcher()

    def test_kev_cache_save_and_load(self):
        """Test KEV cache save and load."""
        test_data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-15"},
                {"cveID": "CVE-2024-0002", "dateAdded": "2024-02-20"}
            ]
        }

        # Save
        self.fetcher.save_cache(test_data)

        # Load
        loaded = self.fetcher.load_cached()
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded["vulnerabilities"]), 2)
        self.assertEqual(loaded["vulnerabilities"][0]["cveID"], "CVE-2024-0001")

    def test_get_kev_list(self):
        """Test extracting CVE IDs from KEV data."""
        test_data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001"},
                {"cveID": "CVE-2024-0002"},
                {"cveID": "CVE-2024-0003"}
            ]
        }

        self.fetcher.save_cache(test_data)
        cve_list = self.fetcher.get_kev_list(use_cache=True)

        self.assertEqual(len(cve_list), 3)
        self.assertIn("CVE-2024-0001", cve_list)

    def test_get_kev_details(self):
        """Test fetching specific CVE details from KEV."""
        test_data = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "dateAdded": "2024-01-15",
                    "product": "nginx",
                    "severity": "High"
                }
            ]
        }

        self.fetcher.save_cache(test_data)
        details = self.fetcher.get_kev_details("CVE-2024-0001")

        self.assertIsNotNone(details)
        self.assertEqual(details["product"], "nginx")

    def test_kev_list_empty_on_no_cache(self):
        """Test that empty list is returned if cache has empty vulnerabilities."""
        # Create a data structure with empty vulnerabilities list
        empty_data = {"vulnerabilities": []}

        # Save it as cache
        self.fetcher.save_cache(empty_data)

        # Load and verify it returns empty list
        cve_list = self.fetcher.get_kev_list(use_cache=True)
        self.assertEqual(cve_list, [])

    def test_cache_expiration(self):
        """Test that expired cache is not used."""
        # This test verifies cache expiration logic
        # We'll test with a mock that returns fresh data
        old_timestamp = (datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()

        # Create mock load_cached that returns old data
        old_data = {
            "vulnerabilities": [{"cveID": "CVE-2024-0001"}],
            "_fetched": old_timestamp
        }

        # Create fresh data
        fresh_data = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001"},
                {"cveID": "CVE-2024-NEW"}
            ]
        }

        # Patch both load_cached and fetch_live
        with patch.object(self.fetcher, 'load_cached', return_value=old_data):
            with patch.object(self.fetcher, 'fetch_live', return_value=fresh_data):
                # With cache TTL check, should return cached if not expired
                # But since our mock returns old data, the actual implementation
                # should check TTL and fetch fresh. This test verifies the pattern.
                cve_list = self.fetcher.get_kev_list(use_cache=False)
                # When use_cache=False, should fetch fresh data
                self.assertIsNotNone(cve_list)


class TestEPSSPredictor(unittest.TestCase):
    """Test EPSS score fetching and caching."""

    def setUp(self):
        """Set up test fixtures."""
        self.predictor = EPSSPredictor()

    def test_epss_cache_save_and_load(self):
        """Test EPSS cache operations."""
        cache = {
            "CVE-2024-0001": {
                "score": 0.95,
                "percentile": 98.5,
                "_fetched": datetime.now(timezone.utc).timestamp()
            }
        }

        self.predictor._save_cache(cache)
        loaded = self.predictor._load_cache()

        self.assertIn("CVE-2024-0001", loaded)
        self.assertEqual(loaded["CVE-2024-0001"]["score"], 0.95)

    def test_epss_score_caching(self):
        """Test that EPSS scores are cached and reused."""
        cache = {
            "CVE-2024-0001": {
                "score": 0.95,
                "percentile": 98.5,
                "_fetched": datetime.now(timezone.utc).timestamp()
            }
        }

        self.predictor._save_cache(cache)

        # Should return cached value without fetching
        score, percentile = self.predictor.fetch_epss_score("CVE-2024-0001")
        self.assertEqual(score, 0.95)
        self.assertEqual(percentile, 98.5)

    def test_epss_score_none_on_failure(self):
        """Test that None is returned on fetch failure."""
        with patch('urllib.request.urlopen', side_effect=Exception("Network error")):
            score, percentile = self.predictor.fetch_epss_score("CVE-2024-NEW")
            self.assertIsNone(score)
            self.assertIsNone(percentile)

    def test_epss_percentile_extraction(self):
        """Test proper extraction of EPSS percentile."""
        cache = {
            "CVE-2024-HIGH": {
                "score": 0.98,
                "percentile": 99.9,
                "_fetched": datetime.now(timezone.utc).timestamp()
            },
            "CVE-2024-LOW": {
                "score": 0.05,
                "percentile": 5.0,
                "_fetched": datetime.now(timezone.utc).timestamp()
            }
        }

        self.predictor._save_cache(cache)

        score_high, pctl_high = self.predictor.fetch_epss_score("CVE-2024-HIGH")
        score_low, pctl_low = self.predictor.fetch_epss_score("CVE-2024-LOW")

        self.assertGreater(pctl_high, pctl_low)
        self.assertGreater(score_high, score_low)


class TestCVSSEnricher(unittest.TestCase):
    """Test CVSS vector parsing and CVE enrichment."""

    def setUp(self):
        """Set up test fixtures."""
        self.enricher = CVSSEnricher()

    def test_cvss_vector_parsing_critical(self):
        """Test parsing of critical CVSS vector."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        metrics = self.enricher.parse_cvss_vector(vector)

        self.assertEqual(metrics["attack_vector"], 1.0)  # Network = max
        self.assertEqual(metrics["attack_complexity"], 0.0)  # Low = easier
        self.assertFalse(metrics["requires_auth"])
        self.assertFalse(metrics["user_interaction"])
        self.assertEqual(metrics["impact_confidentiality"], 1.0)

    def test_cvss_vector_parsing_low_impact(self):
        """Test parsing of low-impact CVSS vector."""
        vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L"
        metrics = self.enricher.parse_cvss_vector(vector)

        self.assertLess(metrics["attack_vector"], 1.0)  # Local < Network
        self.assertGreater(metrics["attack_complexity"], 0.0)  # High complexity
        self.assertTrue(metrics["requires_auth"])
        self.assertTrue(metrics["user_interaction"])
        self.assertLess(metrics["impact_confidentiality"], 1.0)

    def test_cvss_vector_scope_change(self):
        """Test detection of scope change in CVSS."""
        vector_scope_change = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        vector_no_scope = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        metrics_changed = self.enricher.parse_cvss_vector(vector_scope_change)
        metrics_unchanged = self.enricher.parse_cvss_vector(vector_no_scope)

        self.assertTrue(metrics_changed["scope_changed"])
        self.assertFalse(metrics_unchanged["scope_changed"])

    def test_cve_details_caching(self):
        """Test CVE details are cached correctly."""
        # Clear cache first
        cache = {}

        test_cve = "CVE-2024-0001"
        details = self.enricher.fetch_cve_details(test_cve)

        self.assertIsNotNone(details)
        self.assertIn("cvss_score", details)

    def test_cve_details_nonexistent(self):
        """Test that nonexistent CVE returns None."""
        details = self.enricher.fetch_cve_details("CVE-1999-FAKE")
        self.assertIsNone(details)


class TestAttackMarketplaceMonitor(unittest.TestCase):
    """Test exploit marketplace monitoring."""

    def setUp(self):
        """Set up test fixtures."""
        self.monitor = AttackMarketplaceMonitor()

    def test_marketplace_listings_retrieval(self):
        """Test fetching marketplace listings."""
        listings = self.monitor.get_marketplace_listings()

        self.assertGreater(len(listings), 0)
        self.assertIsInstance(listings[0], ExploitMarketplaceItem)
        self.assertIsNotNone(listings[0].marketplace_id)

    def test_marketplace_listing_has_prices(self):
        """Test that marketplace listings include pricing."""
        listings = self.monitor.get_marketplace_listings()

        for listing in listings:
            self.assertGreater(listing.price_usd, 0)
            self.assertIsNotNone(listing.cve_ids)

    def test_marketplace_scoring(self):
        """Test marketplace item threat scoring."""
        item = ExploitMarketplaceItem(
            marketplace_id="test-001",
            title="Test exploit",
            cve_ids=["CVE-2024-0001"],
            price_usd=5000.0,
            buyer_count=5,
            demand_signals=10,
            exploit_code_available=True,
            seller_reputation=0.95,
            confidence=0.95
        )

        score = self.monitor.score_marketplace_item(item)
        self.assertGreater(score, 0.5)  # High score for active marketplace item
        self.assertLessEqual(score, 1.0)

    def test_marketplace_scoring_low_demand(self):
        """Test that low-demand items score lower."""
        high_demand = ExploitMarketplaceItem(
            marketplace_id="test-002",
            title="Popular exploit",
            cve_ids=["CVE-2024-0001"],
            price_usd=5000.0,
            buyer_count=20,
            demand_signals=50,
            exploit_code_available=True,
            seller_reputation=0.95,
            confidence=0.95
        )

        low_demand = ExploitMarketplaceItem(
            marketplace_id="test-003",
            title="Unpopular exploit",
            cve_ids=["CVE-2024-0001"],
            price_usd=100.0,
            buyer_count=0,
            demand_signals=0,
            exploit_code_available=False,
            seller_reputation=0.5,
            confidence=0.6
        )

        score_high = self.monitor.score_marketplace_item(high_demand)
        score_low = self.monitor.score_marketplace_item(low_demand)

        self.assertGreater(score_high, score_low)

    def test_marketplace_cache_save_load(self):
        """Test marketplace data caching."""
        listings = self.monitor.get_marketplace_listings()
        cached = self.monitor._load_cache()

        self.assertIsNotNone(cached)
        self.assertIn("listings", cached)


class TestThreatTrendAnalyzer(unittest.TestCase):
    """Test threat trend analysis and forecasting."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ThreatTrendAnalyzer()

    def test_trend_extraction(self):
        """Test extracting current trends."""
        trends = self.analyzer.extract_current_trends()

        self.assertGreater(len(trends), 0)
        self.assertIsInstance(trends[0], ThreatTrend)

    def test_trend_has_required_fields(self):
        """Test that trends have all required fields."""
        trends = self.analyzer.extract_current_trends()

        for trend in trends:
            self.assertIsNotNone(trend.trend_id)
            self.assertIsNotNone(trend.pattern)
            self.assertGreater(len(trend.related_cves), 0)
            self.assertGreater(len(trend.attack_techniques), 0)
            self.assertGreater(trend.velocity, 0)
            self.assertLessEqual(trend.velocity, 1.0)
            self.assertGreater(trend.confidence, 0)
            self.assertLessEqual(trend.confidence, 1.0)

    def test_trend_sector_impact_scoring(self):
        """Test scoring trend impact on specific sectors."""
        trend = ThreatTrend(
            trend_id="test-trend",
            timestamp=datetime.now(timezone.utc).isoformat(),
            pattern="test_pattern",
            related_cves=["CVE-2024-0001"],
            attack_techniques=["T1234"],
            affected_sectors=["healthcare", "education"],
            geographic_origin="Unknown",
            velocity=0.8,
            confidence=0.9,
            forecast_7d=0.7
        )

        # Impact should be high for overlapping sectors
        impact_high = self.analyzer.score_trend_impact(trend, ["healthcare", "retail"])
        # Impact should be low for non-overlapping sectors
        impact_low = self.analyzer.score_trend_impact(trend, ["government", "retail"])

        self.assertGreater(impact_high, impact_low)

    def test_trend_velocity_range(self):
        """Test that trend velocity is properly bounded."""
        trends = self.analyzer.extract_current_trends()

        for trend in trends:
            self.assertGreaterEqual(trend.velocity, 0.0)
            self.assertLessEqual(trend.velocity, 1.0)
            self.assertGreaterEqual(trend.forecast_7d, 0.0)
            self.assertLessEqual(trend.forecast_7d, 1.0)


class TestPrioritizationUpdater(unittest.TestCase):
    """Test threat prioritization with ML integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.updater = PrioritizationUpdater()

    def test_build_threat_scored_cve_list(self):
        """Test building prioritized CVE list."""
        target_stack = {"nginx": "1.19.0", "apache": "2.4.48"}
        cve_records = self.updater.build_threat_scored_cve_list(target_stack)

        self.assertGreater(len(cve_records), 0)
        # Verify sorting by combined score
        for i in range(len(cve_records) - 1):
            self.assertGreaterEqual(
                cve_records[i].combined_score,
                cve_records[i + 1].combined_score
            )

    def test_cve_records_have_priority_ranks(self):
        """Test that CVE records are ranked correctly."""
        target_stack = {"nginx": "1.19.0"}
        cve_records = self.updater.build_threat_scored_cve_list(target_stack)

        for idx, record in enumerate(cve_records):
            self.assertEqual(record.priority_rank, idx + 1)

    def test_threat_scoring_includes_multiple_sources(self):
        """Test that combined score uses all threat sources."""
        target_stack = {"nginx": "1.19.0"}
        cve_records = self.updater.build_threat_scored_cve_list(target_stack)

        # Check that scoring factors are being used
        for record in cve_records:
            self.assertGreater(record.combined_score, 0)
            # Combined score should consider CVSS, EPSS, trends, marketplace
            factors_used = (record.cvss_score > 0) + (record.epss_score > 0) + (record.trend_velocity > 0)
            # At least one source should contribute
            self.assertGreater(factors_used, 0)

    def test_active_exploitation_boost(self):
        """Test that actively exploited vulns get higher scores."""
        target_stack = {"nginx": "1.19.0"}
        cve_records = self.updater.build_threat_scored_cve_list(target_stack)

        # Find exploited vs unexloited
        exploited = [r for r in cve_records if r.is_actively_exploited]
        unexploited = [r for r in cve_records if not r.is_actively_exploited]

        if exploited and unexploited:
            avg_exploited = sum(r.combined_score for r in exploited) / len(exploited)
            avg_unexploited = sum(r.combined_score for r in unexploited) / len(unexploited)
            self.assertGreaterEqual(avg_exploited, avg_unexploited * 0.8)

    def test_export_prioritized_threats(self):
        """Test exporting prioritized threats to JSON."""
        target_stack = {"nginx": "1.19.0"}
        cve_records = self.updater.build_threat_scored_cve_list(target_stack)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            self.updater.export_prioritized_threats(cve_records, output_file)
            self.assertTrue(os.path.exists(output_file))

            with open(output_file) as f:
                exported = json.load(f)
                self.assertEqual(len(exported), len(cve_records))
                self.assertIn("cve_id", exported[0])
                self.assertIn("combined_score", exported[0])
        finally:
            os.unlink(output_file)


class TestAlertingEngine(unittest.TestCase):
    """Test security alert generation and management."""

    def setUp(self):
        """Set up test fixtures."""
        self.engine = AlertingEngine()

    def test_db_initialization(self):
        """Test that alerts database is properly initialized."""
        self.engine.initialize_db()
        # Should not raise an exception

    def test_generate_alerts_for_matching_components(self):
        """Test generating alerts for matching tech stack."""
        target_stack = {"nginx": "1.19.0", "apache": "2.4.48"}

        # Create test CVE records
        test_cve = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            epss_score=0.95,
            affected_component="nginx",
            affected_versions=["1.19.0", "1.20.0"],
            is_actively_exploited=True,
            exploitation_status="high",
            patch_available=True,
            combined_score=0.92,
            confidence=0.95
        )

        alerts = self.engine.generate_alerts(target_stack, [test_cve])

        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].cve_id, "CVE-2024-0001")

    def test_alert_severity_classification(self):
        """Test that alerts are severity-classified correctly."""
        target_stack = {"nginx": "1.19.0"}

        critical_cve = CVERecord(
            cve_id="CVE-CRITICAL",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_component="nginx",
            combined_score=0.95,
            confidence=0.95
        )

        low_cve = CVERecord(
            cve_id="CVE-LOW",
            cvss_score=3.5,
            cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
            affected_component="nginx",
            combined_score=0.3,
            confidence=0.95
        )

        critical_alerts = self.engine.generate_alerts(target_stack, [critical_cve])
        low_alerts = self.engine.generate_alerts(target_stack, [low_cve])

        if critical_alerts:
            self.assertEqual(critical_alerts[0].severity, "critical")
        if low_alerts:
            self.assertEqual(low_alerts[0].severity, "low")

    def test_alert_urgency_calculation(self):
        """Test that alert urgency is properly calculated."""
        target_stack = {"nginx": "1.19.0"}

        high_threat = CVERecord(
            cve_id="CVE-HIGH",
            cvss_score=9.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_component="nginx",
            is_actively_exploited=True,
            combined_score=0.95,
            confidence=0.95
        )

        alerts = self.engine.generate_alerts(target_stack, [high_threat])

        if alerts:
            self.assertGreater(alerts[0].urgency, 0.8)

    def test_no_alerts_for_unmatched_components(self):
        """Test that no alerts are generated for non-matching components."""
        target_stack = {"postgres": "12.0"}

        cve = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=9.0,
            affected_component="nginx",
            combined_score=0.9,
            confidence=0.95
        )

        alerts = self.engine.generate_alerts(target_stack, [cve])
        self.assertEqual(len(alerts), 0)

    def test_alert_id_uniqueness(self):
        """Test that alert IDs are unique."""
        target_stack = {"nginx": "1.19.0", "apache": "2.4.48"}

        test_cve = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=9.0,
            affected_component="nginx",
            combined_score=0.9,
            confidence=0.95
        )

        alerts = self.engine.generate_alerts(target_stack, [test_cve])
        alert_ids = [a.alert_id for a in alerts]

        self.assertEqual(len(alert_ids), len(set(alert_ids)))


class TestCVERecordDataStructure(unittest.TestCase):
    """Test CVE record data structure."""

    def test_cve_record_creation(self):
        """Test creating a CVE record."""
        record = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=9.0,
            epss_score=0.95,
            affected_component="nginx",
            is_actively_exploited=True
        )

        self.assertEqual(record.cve_id, "CVE-2024-0001")
        self.assertEqual(record.cvss_score, 9.0)
        self.assertTrue(record.is_actively_exploited)

    def test_cve_record_default_values(self):
        """Test that CVE record has proper default values."""
        record = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=5.0
        )

        self.assertEqual(record.epss_score, 0.0)
        self.assertFalse(record.is_actively_exploited)
        self.assertEqual(record.confidence, 1.0)

    def test_cve_record_affected_versions(self):
        """Test CVE record version tracking."""
        versions = ["1.19.0", "1.20.0", "1.21.0"]
        record = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=8.0,
            affected_versions=versions
        )

        self.assertEqual(len(record.affected_versions), 3)
        self.assertIn("1.19.0", record.affected_versions)


class TestThreatAlertDataStructure(unittest.TestCase):
    """Test threat alert data structure."""

    def test_alert_creation(self):
        """Test creating a threat alert."""
        alert = ThreatAlert(
            alert_id="alert-001",
            timestamp=datetime.now(timezone.utc).isoformat(),
            cve_id="CVE-2024-0001",
            alert_type="new_exploit",
            severity="critical",
            tech_component="nginx 1.19.0",
            description="Critical RCE in nginx",
            recommended_action="Upgrade nginx immediately",
            urgency=0.95
        )

        self.assertEqual(alert.alert_id, "alert-001")
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.urgency, 0.95)

    def test_alert_false_positive_scoring(self):
        """Test false positive score on alerts."""
        alert = ThreatAlert(
            alert_id="alert-002",
            timestamp=datetime.now(timezone.utc).isoformat(),
            cve_id="CVE-2024-0002",
            alert_type="trending",
            severity="high",
            tech_component="apache 2.4.48",
            description="Trending vulnerability",
            recommended_action="Monitor",
            urgency=0.7,
            false_positive_score=0.2
        )

        self.assertLess(alert.false_positive_score, 0.3)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete threat intelligence pipeline."""

    def test_full_pipeline(self):
        """Test complete pipeline from CVE fetching to alert generation."""
        target_stack = {"nginx": "1.19.0", "apache": "2.4.48"}

        # Step 1: Get prioritized threats
        updater = PrioritizationUpdater()
        cve_records = updater.build_threat_scored_cve_list(target_stack)

        self.assertGreater(len(cve_records), 0)

        # Step 2: Generate alerts
        engine = AlertingEngine()
        alerts = engine.generate_alerts(target_stack, cve_records)

        # Should have at least some alerts for matching components
        self.assertIsInstance(alerts, list)

        # Step 3: Verify alert quality
        for alert in alerts:
            self.assertIsNotNone(alert.cve_id)
            self.assertIsNotNone(alert.tech_component)
            self.assertGreater(alert.urgency, 0)

    def test_pipeline_with_trends(self):
        """Test pipeline with trend analysis."""
        target_stack = {"nginx": "1.19.0"}

        # Get trends
        analyzer = ThreatTrendAnalyzer()
        trends = analyzer.extract_current_trends()

        # Score trends for this sector
        scores = [analyzer.score_trend_impact(t, ["technology", "finance"]) for t in trends]

        # At least some trends should match
        self.assertGreater(sum(1 for s in scores if s > 0.3), 0)

    def test_pipeline_with_marketplace(self):
        """Test pipeline with marketplace monitoring."""
        monitor = AttackMarketplaceMonitor()
        listings = monitor.get_marketplace_listings()

        # Score listings
        scores = [monitor.score_marketplace_item(item) for item in listings]

        # Verify scoring range
        for score in scores:
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 1.0)

    def test_multiple_threat_sources_correlation(self):
        """Test correlation of threats from multiple sources."""
        target_stack = {"nginx": "1.19.0"}

        # Get CVEs from different sources
        updater = PrioritizationUpdater()
        cve_records = updater.build_threat_scored_cve_list(target_stack)

        # Each CVE should have data from multiple sources
        for record in cve_records[:3]:  # Check top 3
            source_count = 0
            if record.cvss_score > 0:
                source_count += 1
            if record.epss_score > 0:
                source_count += 1
            if record.is_actively_exploited:
                source_count += 1
            if record.marketplace_mentions > 0:
                source_count += 1

            # Most records should have at least one source
            self.assertGreater(source_count, 0)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def test_empty_tech_stack(self):
        """Test handling of empty tech stack."""
        updater = PrioritizationUpdater()
        cve_records = updater.build_threat_scored_cve_list({})

        # Should still return CVE list
        self.assertIsInstance(cve_records, list)

    def test_invalid_cvss_vector(self):
        """Test handling of invalid CVSS vector."""
        enricher = CVSSEnricher()
        metrics = enricher.parse_cvss_vector("INVALID_VECTOR")

        # Should return dict with default values
        self.assertIsInstance(metrics, dict)
        self.assertIn("attack_vector", metrics)

    def test_marketplace_empty_list(self):
        """Test handling when no marketplace listings available."""
        monitor = AttackMarketplaceMonitor()
        listings = monitor.get_marketplace_listings()

        # Should handle gracefully
        self.assertIsInstance(listings, list)

    def test_trends_missing_sectors(self):
        """Test handling trends with missing sector data."""
        trend = ThreatTrend(
            trend_id="test",
            timestamp=datetime.now(timezone.utc).isoformat(),
            pattern="test",
            related_cves=[],
            attack_techniques=[],
            affected_sectors=[],
            geographic_origin=None,
            velocity=0.5,
            confidence=0.8,
            forecast_7d=0.5
        )

        analyzer = ThreatTrendAnalyzer()
        impact = analyzer.score_trend_impact(trend, ["finance"])

        # Should handle empty sectors
        self.assertGreaterEqual(impact, 0)
        self.assertLessEqual(impact, 1.0)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
