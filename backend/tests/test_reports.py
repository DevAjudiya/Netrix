# ─────────────────────────────────────────
# Netrix — tests/test_reports.py
# Purpose: Unit tests for the report generation module.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import unittest

from app.schemas.report import ReportCreate, ReportResponse


class TestReportSchemas(unittest.TestCase):
    """Test cases for report Pydantic schemas."""

    def test_report_create_defaults_to_pdf(self):
        """Verify that report format defaults to PDF."""
        report = ReportCreate(scan_id=1)
        self.assertEqual(report.report_format, "pdf")

    def test_report_create_accepts_all_formats(self):
        """Verify that all supported formats are accepted."""
        for fmt in ("pdf", "html", "json", "csv"):
            report = ReportCreate(scan_id=1, report_format=fmt)
            self.assertEqual(report.report_format, fmt)

    def test_report_create_requires_scan_id(self):
        """Verify that scan_id is required."""
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            ReportCreate()


if __name__ == "__main__":
    unittest.main()
