# ─────────────────────────────────────────
# Netrix — tests/test_scanner.py
# Purpose: Unit tests for the scanner module.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import unittest
from unittest.mock import MagicMock, patch

from app.scanner.nmap_engine import NmapEngine
from app.scanner.report_engine import ReportEngine


class TestNmapEngine(unittest.TestCase):
    """Test cases for the NmapEngine class."""

    @patch("app.scanner.nmap_engine.nmap.PortScanner")
    @patch("app.scanner.nmap_engine.get_settings")
    def test_scan_profiles_exist(self, mock_settings, mock_scanner):
        """Verify that all expected scan profiles are defined."""
        mock_settings.return_value = MagicMock(NMAP_PATH="/usr/bin/nmap")
        engine = NmapEngine()
        expected_profiles = ["quick", "standard", "deep", "vuln", "stealth"]
        for profile in expected_profiles:
            self.assertIn(profile, engine.SCAN_PROFILES)

    @patch("app.scanner.nmap_engine.nmap.PortScanner")
    @patch("app.scanner.nmap_engine.get_settings")
    def test_standard_profile_includes_version_detection(self, mock_settings, mock_scanner):
        """Verify that the standard profile includes service version detection."""
        mock_settings.return_value = MagicMock(NMAP_PATH="/usr/bin/nmap")
        engine = NmapEngine()
        self.assertIn("-sV", engine.SCAN_PROFILES["standard"])


class TestReportEngine(unittest.TestCase):
    """Test cases for the ReportEngine class."""

    def test_severity_counts(self):
        """Verify severity counting logic."""
        engine = ReportEngine()
        vulns = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        counts = engine._count_severities(vulns)
        self.assertEqual(counts["critical"], 2)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)
        self.assertEqual(counts["info"], 1)

    def test_aggregate_scan_data_structure(self):
        """Verify the structure of aggregated report data."""
        engine = ReportEngine()
        scan_results = {"hosts": [{"ip_address": "10.0.0.1", "ports": [{"port_number": 80}]}]}
        vulns = [{"severity": "high", "cve_id": "CVE-2021-1234"}]
        metadata = {"target": "10.0.0.1", "scan_type": "standard"}

        result = engine.aggregate_scan_data(scan_results, vulns, metadata)

        self.assertIn("metadata", result)
        self.assertIn("summary", result)
        self.assertIn("hosts", result)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(result["summary"]["total_hosts"], 1)
        self.assertEqual(result["summary"]["total_vulnerabilities"], 1)


if __name__ == "__main__":
    unittest.main()
