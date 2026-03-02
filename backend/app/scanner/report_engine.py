# ─────────────────────────────────────────
# Netrix — scanner/report_engine.py
# Purpose: Complete report generation engine supporting PDF, JSON,
#          CSV, and HTML formats with professional styling.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import csv
import io
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader

from app.config import get_settings

logger = logging.getLogger("netrix")


# ─────────────────────────────────────────
# ReportData Dataclass
# ─────────────────────────────────────────
@dataclass
class ReportData:
    """Structured container for all data needed to render a report."""

    # Scan identification
    scan_id: str = ""
    report_name: str = ""
    generated_at: str = ""
    generated_by: str = "Netrix Security Platform"
    target: str = ""
    scan_type: str = ""
    scan_duration: str = ""
    started_at: str = ""
    completed_at: str = ""
    nmap_command: str = ""

    # Summary counts
    total_hosts: int = 0
    hosts_up: int = 0
    hosts_down: int = 0
    total_open_ports: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    overall_risk_score: int = 0
    overall_severity: str = "info"

    # Detailed data
    hosts: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)

    # Executive summary
    executive_summary: str = ""
    recommendations: List[str] = field(default_factory=list)


# ─────────────────────────────────────────
# Severity colour constants
# ─────────────────────────────────────────
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#16A34A",
    "info": "#3B82F6",
}

SEVERITY_COLORS_RGB = {
    "critical": (0.86, 0.15, 0.15),
    "high": (0.92, 0.35, 0.05),
    "medium": (0.79, 0.54, 0.02),
    "low": (0.09, 0.64, 0.29),
    "info": (0.23, 0.51, 0.96),
}

HEADER_COLOR_HEX = "#1A2B4A"


# ─────────────────────────────────────────
# ReportEngine Class
# ─────────────────────────────────────────
class ReportEngine:
    """
    Multi-format report generator for Netrix scan results.

    Produces professional reports in PDF, JSON, CSV and HTML formats.
    PDF uses ReportLab. HTML uses Jinja2 templates. CSV uses pandas.
    """

    def __init__(self) -> None:
        """Initialise the report engine with settings and template env."""
        self.settings = get_settings()
        self.reports_dir = self.settings.REPORTS_DIR
        os.makedirs(self.reports_dir, exist_ok=True)

        # Jinja2 template directory
        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "templates",
        )
        os.makedirs(template_dir, exist_ok=True)
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )

        logger.info("[NETRIX] Report Engine initialized.")

    # ─────────────────────────────────────
    # Public API
    # ─────────────────────────────────────
    def generate_report(
        self,
        report_data: ReportData,
        fmt: str,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate a report in *fmt* format.

        Args:
            report_data: Complete scan data.
            fmt:         One of ``pdf``, ``json``, ``csv``, ``html``.
            output_path: Where to save the file (auto-generated if ``None``).

        Returns:
            str: Absolute path to the generated report file.

        Raises:
            ValueError: If *fmt* is not a supported format.
        """
        fmt = fmt.lower().strip()

        if output_path is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"netrix_report_{report_data.scan_id}_{timestamp}.{fmt}"
            output_path = os.path.join(self.reports_dir, filename)

        generators = {
            "pdf": self.generate_pdf_report,
            "json": self.generate_json_report,
            "csv": self.generate_csv_report,
            "html": self.generate_html_report,
        }

        generator = generators.get(fmt)
        if generator is None:
            raise ValueError(
                f"Unsupported report format '{fmt}'. "
                f"Supported: {', '.join(generators)}"
            )

        result = generator(report_data, output_path)
        logger.info("[NETRIX] Report generated: %s", result)
        return result

    # ─────────────────────────────────────
    # PDF Report
    # ─────────────────────────────────────
    def generate_pdf_report(
        self,
        report_data: ReportData,
        output_path: str,
    ) -> str:
        """
        Generate a professional multi-page PDF report using ReportLab.

        Page structure:
        1. Cover page with branding
        2. Executive summary with severity table
        3. Scan metadata details
        4+ Host details with ports and vulnerabilities
        Last: Recommendations
        """
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch, mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        PAGE_W, PAGE_H = A4
        styles = getSampleStyleSheet()

        header_color = rl_colors.HexColor(HEADER_COLOR_HEX)

        # ── Custom styles ──────────────────────────────
        cover_title = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontSize=36,
            leading=44,
            textColor=header_color,
            alignment=TA_CENTER,
            spaceAfter=10,
        )
        cover_subtitle = ParagraphStyle(
            "CoverSubtitle",
            parent=styles["Normal"],
            fontSize=16,
            leading=22,
            textColor=rl_colors.HexColor("#4B5563"),
            alignment=TA_CENTER,
            spaceAfter=6,
        )
        section_title = ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=24,
            textColor=header_color,
            spaceBefore=16,
            spaceAfter=10,
        )
        sub_heading = ParagraphStyle(
            "SubHeading",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=header_color,
            spaceBefore=12,
            spaceAfter=6,
        )
        body_text = ParagraphStyle(
            "BodyText",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            spaceAfter=4,
        )
        footer_style = ParagraphStyle(
            "Footer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=rl_colors.HexColor("#9CA3AF"),
            alignment=TA_CENTER,
        )

        # ── Helper — coloured severity label ──────────
        def sev_para(severity: str) -> Paragraph:
            """Return a coloured paragraph for a severity level."""
            col = SEVERITY_COLORS.get(severity.lower(), "#6B7280")
            return Paragraph(
                f'<font color="{col}"><b>{severity.upper()}</b></font>',
                body_text,
            )

        # ── Standard table style ──────────────────────
        def standard_table_style() -> TableStyle:
            return TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), header_color),
                ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.4, rl_colors.HexColor("#D1D5DB")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    rl_colors.HexColor("#F9FAFB"),
                    rl_colors.white,
                ]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])

        elements: list = []

        # ─── PAGE 1: COVER ────────────────────────────
        elements.append(Spacer(1, 80))
        elements.append(Paragraph("NETRIX", cover_title))
        elements.append(Spacer(1, 10))
        elements.append(
            Paragraph("Network Security Assessment Report", cover_subtitle)
        )
        elements.append(Spacer(1, 30))

        cover_info = [
            ("Target", report_data.target),
            ("Scan Type", report_data.scan_type.capitalize()),
            ("Generated", report_data.generated_at),
            ("Prepared by", report_data.generated_by),
        ]
        for label, value in cover_info:
            elements.append(
                Paragraph(
                    f'<b>{label}:</b>  {value}',
                    ParagraphStyle(
                        "CoverInfo", parent=body_text,
                        fontSize=12, alignment=TA_CENTER, spaceAfter=6,
                    ),
                )
            )

        elements.append(Spacer(1, 40))
        elements.append(
            Paragraph(
                '<font color="#DC2626"><b>CONFIDENTIAL</b></font> — '
                "This document contains sensitive security assessment data. "
                "Distribution is restricted to authorised personnel only.",
                ParagraphStyle(
                    "Confidential", parent=body_text,
                    fontSize=9, alignment=TA_CENTER,
                    textColor=rl_colors.HexColor("#6B7280"),
                ),
            )
        )
        elements.append(PageBreak())

        # ─── PAGE 2: EXECUTIVE SUMMARY ────────────────
        elements.append(Paragraph("Executive Summary", section_title))

        # Risk score
        risk_col = SEVERITY_COLORS.get(
            report_data.overall_severity.lower(), "#6B7280"
        )
        elements.append(
            Paragraph(
                f'Overall Risk Score: '
                f'<font color="{risk_col}" size="20"><b>'
                f'{report_data.overall_risk_score}/100</b></font>  '
                f'<font color="{risk_col}"><b>'
                f'[{report_data.overall_severity.upper()}]</b></font>',
                body_text,
            )
        )
        elements.append(Spacer(1, 10))

        # Executive summary paragraph
        if report_data.executive_summary:
            elements.append(Paragraph(report_data.executive_summary, body_text))
            elements.append(Spacer(1, 10))

        # Severity table
        elements.append(Paragraph("Vulnerability Breakdown", sub_heading))
        sev_table_data = [
            ["Severity", "Count"],
            ["Critical", str(report_data.critical_count)],
            ["High", str(report_data.high_count)],
            ["Medium", str(report_data.medium_count)],
            ["Low", str(report_data.low_count)],
            ["Info", str(report_data.info_count)],
            ["TOTAL", str(report_data.total_vulnerabilities)],
        ]
        sev_table = Table(sev_table_data, colWidths=[150, 80])
        sev_ts = standard_table_style()
        # Colour-code severity rows
        severity_row_colors = [
            (1, "#DC2626"), (2, "#EA580C"), (3, "#CA8A04"),
            (4, "#16A34A"), (5, "#3B82F6"),
        ]
        for row_idx, hex_col in severity_row_colors:
            sev_ts.add("TEXTCOLOR", (0, row_idx), (0, row_idx),
                        rl_colors.HexColor(hex_col))
        sev_ts.add("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold")
        sev_table.setStyle(sev_ts)
        elements.append(sev_table)
        elements.append(Spacer(1, 14))

        # Top critical findings
        critical_vulns = [
            v for v in report_data.vulnerabilities
            if v.get("severity", "").lower() == "critical"
        ][:3]
        if critical_vulns:
            elements.append(
                Paragraph("Top Critical Findings", sub_heading)
            )
            for cv in critical_vulns:
                cve = cv.get("cve_id", "N/A")
                title = cv.get("title", "Unknown")
                elements.append(
                    Paragraph(
                        f'<font color="#DC2626">●</font> '
                        f'<b>{cve}</b> — {title}',
                        body_text,
                    )
                )
            elements.append(Spacer(1, 8))

        elements.append(PageBreak())

        # ─── PAGE 3: SCAN DETAILS ─────────────────────
        elements.append(Paragraph("Scan Details", section_title))

        scan_meta = [
            ["Property", "Value"],
            ["Scan ID", report_data.scan_id],
            ["Target", report_data.target],
            ["Scan Type", report_data.scan_type.capitalize()],
            ["Duration", report_data.scan_duration or "N/A"],
            ["Started At", report_data.started_at or "N/A"],
            ["Completed At", report_data.completed_at or "N/A"],
            ["Nmap Command", report_data.nmap_command or "N/A"],
            ["Total Hosts", str(report_data.total_hosts)],
            ["Hosts Up", str(report_data.hosts_up)],
            ["Hosts Down", str(report_data.hosts_down)],
            ["Open Ports", str(report_data.total_open_ports)],
        ]
        meta_table = Table(scan_meta, colWidths=[130, 340])
        meta_table.setStyle(standard_table_style())
        elements.append(meta_table)
        elements.append(PageBreak())

        # ─── PAGES 4+: HOST DETAILS ───────────────────
        elements.append(Paragraph("Host Details", section_title))

        for host in report_data.hosts:
            ip = host.get("ip_address", host.get("ip", "N/A"))
            hostname = host.get("hostname", "N/A") or "N/A"
            os_name = host.get("os_name", host.get("os", "N/A")) or "N/A"
            risk = host.get("risk_score", 0)
            risk_lvl = host.get("risk_level", "info")

            risk_hex = SEVERITY_COLORS.get(risk_lvl, "#6B7280")
            elements.append(
                Paragraph(
                    f'<b>{ip}</b>  |  {hostname}  |  OS: {os_name}  |  '
                    f'Risk: <font color="{risk_hex}"><b>{risk}</b></font>',
                    sub_heading,
                )
            )

            # Ports table
            ports = host.get("ports", [])
            if ports:
                port_data = [["Port", "Protocol", "Service", "Product", "Version", "State"]]
                for p in ports:
                    port_data.append([
                        str(p.get("port_number", p.get("port", ""))),
                        p.get("protocol", "tcp"),
                        p.get("service_name", p.get("service", "N/A")) or "N/A",
                        p.get("product", "N/A") or "N/A",
                        p.get("version", "N/A") or "N/A",
                        p.get("state", "open"),
                    ])
                pt = Table(port_data, colWidths=[50, 55, 80, 90, 80, 50])
                pt.setStyle(standard_table_style())
                elements.append(pt)
                elements.append(Spacer(1, 6))

            # Per-host vulnerabilities
            host_vulns = [
                v for v in report_data.vulnerabilities
                if v.get("affected_host") == ip
                or v.get("host_ip") == ip
            ]
            if host_vulns:
                vuln_data = [["CVE ID", "Severity", "CVSS", "Title"]]
                for v in host_vulns:
                    vuln_data.append([
                        v.get("cve_id", "N/A") or "N/A",
                        v.get("severity", "info").capitalize(),
                        str(v.get("cvss_score", "N/A") or "N/A"),
                        (v.get("title", "") or "")[:60],
                    ])
                vt = Table(vuln_data, colWidths=[90, 65, 50, 260])
                vt_style = standard_table_style()
                # Colour severity cells
                for r_idx in range(1, len(vuln_data)):
                    sev_lower = vuln_data[r_idx][1].lower()
                    sev_hex = SEVERITY_COLORS.get(sev_lower, "#6B7280")
                    vt_style.add(
                        "TEXTCOLOR", (1, r_idx), (1, r_idx),
                        rl_colors.HexColor(sev_hex),
                    )
                vt.setStyle(vt_style)
                elements.append(vt)

            elements.append(Spacer(1, 14))

        elements.append(PageBreak())

        # ─── LAST PAGE: RECOMMENDATIONS ───────────────
        elements.append(Paragraph("Recommendations", section_title))

        if report_data.recommendations:
            for idx, rec in enumerate(report_data.recommendations, 1):
                elements.append(
                    Paragraph(f"<b>{idx}.</b>  {rec}", body_text)
                )
        else:
            elements.append(
                Paragraph("No specific recommendations generated.", body_text)
            )

        elements.append(Spacer(1, 16))
        elements.append(Paragraph("General Security Recommendations", sub_heading))
        general_recs = [
            "Keep all software and firmware updated to the latest stable versions.",
            "Close unnecessary ports and disable unused services on all hosts.",
            "Use strong, unique passwords and enable multi-factor authentication.",
            "Enable and properly configure host and network firewalls.",
            "Conduct regular security audits and penetration testing.",
            "Implement network segmentation to limit lateral movement.",
            "Deploy intrusion detection/prevention systems (IDS/IPS).",
            "Maintain up-to-date backups and test disaster recovery procedures.",
        ]
        for idx, rec in enumerate(general_recs, 1):
            elements.append(Paragraph(f"{idx}. {rec}", body_text))

        # ─── Build PDF with header/footer ─────────────
        def _header_footer(canvas_obj, doc_obj):
            """Draw header and footer on every page."""
            canvas_obj.saveState()
            # Header
            canvas_obj.setFont("Helvetica", 8)
            canvas_obj.setFillColor(rl_colors.HexColor("#9CA3AF"))
            canvas_obj.drawString(
                40, PAGE_H - 30,
                "NETRIX  |  CONFIDENTIAL",
            )
            canvas_obj.drawRightString(
                PAGE_W - 40, PAGE_H - 30,
                report_data.generated_at,
            )
            # Divider line
            canvas_obj.setStrokeColor(rl_colors.HexColor("#E5E7EB"))
            canvas_obj.setLineWidth(0.5)
            canvas_obj.line(40, PAGE_H - 35, PAGE_W - 40, PAGE_H - 35)
            # Footer
            canvas_obj.setFont("Helvetica", 8)
            canvas_obj.setFillColor(rl_colors.HexColor("#9CA3AF"))
            page_num = doc_obj.page
            canvas_obj.drawCentredString(
                PAGE_W / 2, 25,
                f"Page {page_num}  |  {report_data.generated_at}"
                f"  |  Netrix v{self.settings.APP_VERSION}",
            )
            canvas_obj.restoreState()

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=50,
            bottomMargin=45,
            leftMargin=40,
            rightMargin=40,
        )
        doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)

        logger.info("[NETRIX] PDF report generated: %s", output_path)
        return output_path

    # ─────────────────────────────────────
    # JSON Report
    # ─────────────────────────────────────
    def generate_json_report(
        self,
        report_data: ReportData,
        output_path: str,
    ) -> str:
        """Generate a structured JSON report."""
        report_dict = {
            "report_metadata": {
                "report_name": report_data.report_name,
                "generated_at": report_data.generated_at,
                "generated_by": report_data.generated_by,
                "netrix_version": self.settings.APP_VERSION,
            },
            "scan_info": {
                "scan_id": report_data.scan_id,
                "target": report_data.target,
                "scan_type": report_data.scan_type,
                "started_at": report_data.started_at,
                "completed_at": report_data.completed_at,
                "duration": report_data.scan_duration,
                "nmap_command": report_data.nmap_command,
            },
            "executive_summary": {
                "overall_risk_score": report_data.overall_risk_score,
                "overall_severity": report_data.overall_severity,
                "executive_text": report_data.executive_summary,
                "total_hosts": report_data.total_hosts,
                "hosts_up": report_data.hosts_up,
                "hosts_down": report_data.hosts_down,
                "total_open_ports": report_data.total_open_ports,
                "total_vulnerabilities": report_data.total_vulnerabilities,
                "critical_count": report_data.critical_count,
                "high_count": report_data.high_count,
                "medium_count": report_data.medium_count,
                "low_count": report_data.low_count,
                "info_count": report_data.info_count,
            },
            "hosts": report_data.hosts,
            "vulnerabilities": report_data.vulnerabilities,
            "recommendations": report_data.recommendations,
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report_dict, fh, indent=2, default=str, ensure_ascii=False)

        logger.info("[NETRIX] JSON report generated: %s", output_path)
        return output_path

    # ─────────────────────────────────────
    # CSV Report
    # ─────────────────────────────────────
    def generate_csv_report(
        self,
        report_data: ReportData,
        output_path: str,
    ) -> str:
        """
        Generate a CSV report with four clearly delimited sections:
        Scan Summary, Hosts, Vulnerabilities, and Open Ports.
        """
        import pandas as pd

        buf = io.StringIO()
        writer = csv.writer(buf)

        # ── Section 1: Scan Summary ───────────────────
        writer.writerow(["=== SCAN SUMMARY ==="])
        writer.writerow(["Property", "Value"])
        summary_rows = [
            ("Scan ID", report_data.scan_id),
            ("Target", report_data.target),
            ("Scan Type", report_data.scan_type),
            ("Duration", report_data.scan_duration),
            ("Started At", report_data.started_at),
            ("Completed At", report_data.completed_at),
            ("Total Hosts", report_data.total_hosts),
            ("Hosts Up", report_data.hosts_up),
            ("Hosts Down", report_data.hosts_down),
            ("Open Ports", report_data.total_open_ports),
            ("Total Vulnerabilities", report_data.total_vulnerabilities),
            ("Critical", report_data.critical_count),
            ("High", report_data.high_count),
            ("Medium", report_data.medium_count),
            ("Low", report_data.low_count),
            ("Info", report_data.info_count),
            ("Overall Risk Score", report_data.overall_risk_score),
            ("Generated At", report_data.generated_at),
            ("Generated By", report_data.generated_by),
        ]
        for prop, val in summary_rows:
            writer.writerow([prop, val])
        writer.writerow([])

        # ── Section 2: Hosts ──────────────────────────
        writer.writerow(["=== HOSTS ==="])
        host_headers = [
            "IP", "Hostname", "OS", "Status",
            "Open Ports", "Risk Score", "Risk Level",
        ]
        writer.writerow(host_headers)
        for host in report_data.hosts:
            open_port_count = len([
                p for p in host.get("ports", [])
                if p.get("state", "open") == "open"
            ])
            writer.writerow([
                host.get("ip_address", host.get("ip", "")),
                host.get("hostname", "") or "",
                host.get("os_name", host.get("os", "")) or "",
                host.get("status", "up"),
                open_port_count,
                host.get("risk_score", 0),
                host.get("risk_level", "info"),
            ])
        writer.writerow([])

        # ── Section 3: Vulnerabilities ────────────────
        writer.writerow(["=== VULNERABILITIES ==="])
        vuln_headers = [
            "CVE ID", "Severity", "CVSS Score", "Title",
            "Affected Host", "Affected Port", "Service", "Remediation",
        ]
        writer.writerow(vuln_headers)
        for vuln in report_data.vulnerabilities:
            writer.writerow([
                vuln.get("cve_id", ""),
                vuln.get("severity", "info"),
                vuln.get("cvss_score", ""),
                vuln.get("title", ""),
                vuln.get("affected_host", vuln.get("host_ip", "")),
                vuln.get("affected_port", vuln.get("port", "")),
                vuln.get("affected_service", vuln.get("service", "")),
                vuln.get("remediation", ""),
            ])
        writer.writerow([])

        # ── Section 4: Open Ports ─────────────────────
        writer.writerow(["=== OPEN PORTS ==="])
        port_headers = [
            "Host IP", "Port", "Protocol", "Service",
            "Product", "Version", "State",
        ]
        writer.writerow(port_headers)
        for host in report_data.hosts:
            ip = host.get("ip_address", host.get("ip", ""))
            for port in host.get("ports", []):
                writer.writerow([
                    ip,
                    port.get("port_number", port.get("port", "")),
                    port.get("protocol", "tcp"),
                    port.get("service_name", port.get("service", "")) or "",
                    port.get("product", "") or "",
                    port.get("version", "") or "",
                    port.get("state", "open"),
                ])

        with open(output_path, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(buf.getvalue())

        logger.info("[NETRIX] CSV report generated: %s", output_path)
        return output_path

    # ─────────────────────────────────────
    # HTML Report
    # ─────────────────────────────────────
    def generate_html_report(
        self,
        report_data: ReportData,
        output_path: str,
    ) -> str:
        """
        Generate a beautiful self-contained HTML report using Jinja2.

        Falls back to inline rendering if the template file is missing.
        """
        template_context = {
            "report": report_data,
            "severity_colors": SEVERITY_COLORS,
            "version": self.settings.APP_VERSION,
        }

        try:
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(**template_context)
        except Exception as template_error:
            logger.warning(
                "[NETRIX] Template rendering failed (%s), using inline fallback.",
                str(template_error),
            )
            html_content = self._generate_inline_html(report_data)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        logger.info("[NETRIX] HTML report generated: %s", output_path)
        return output_path

    # ─────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────
    def _generate_executive_summary(self, report_data: ReportData) -> str:
        """
        Auto-generate an executive summary paragraph from scan data.

        Returns:
            str: A human-readable executive summary.
        """
        parts = [
            f"The security assessment of {report_data.target} "
            f"conducted on {report_data.started_at or report_data.generated_at} "
            f"identified {report_data.total_hosts} active host(s) "
            f"with {report_data.total_open_ports} open port(s) "
            f"and {report_data.total_vulnerabilities} vulnerability(ies)."
        ]

        if report_data.critical_count > 0:
            parts.append(
                f"{report_data.critical_count} CRITICAL vulnerability(ies) "
                "require immediate attention and remediation."
            )

        if report_data.high_count > 0:
            parts.append(
                f"{report_data.high_count} HIGH severity issue(s) "
                "should be addressed within the next patching cycle."
            )

        if report_data.total_vulnerabilities == 0:
            parts.append(
                "No known vulnerabilities were detected. "
                "Continue routine security monitoring and patching."
            )

        risk = report_data.overall_risk_score
        if risk >= 80:
            parts.append(
                "The overall risk posture is CRITICAL. "
                "Immediate action is strongly recommended."
            )
        elif risk >= 60:
            parts.append(
                "The overall risk posture is HIGH. "
                "Prioritise remediation of the most severe findings."
            )
        elif risk >= 40:
            parts.append(
                "The overall risk posture is MODERATE. "
                "Address findings as part of regular maintenance."
            )
        else:
            parts.append(
                "The overall risk posture is LOW. "
                "Maintain current security practices and monitor for new threats."
            )

        return " ".join(parts)

    def _generate_recommendations(self, report_data: ReportData) -> List[str]:
        """
        Auto-generate prioritised recommendations from scan data.

        Returns:
            list[str]: Up to 10 actionable recommendations.
        """
        recs: List[str] = []

        # Critical vulnerability patches
        seen_cves = set()
        for v in report_data.vulnerabilities:
            if v.get("severity", "").lower() == "critical":
                cve = v.get("cve_id", "N/A")
                host = v.get("affected_host", v.get("host_ip", "unknown"))
                if cve not in seen_cves:
                    recs.append(
                        f"Immediately patch {cve} on {host} — "
                        f"{v.get('title', 'Critical vulnerability')}."
                    )
                    seen_cves.add(cve)

        # High severity
        for v in report_data.vulnerabilities:
            if v.get("severity", "").lower() == "high" and len(recs) < 10:
                cve = v.get("cve_id", "N/A")
                host = v.get("affected_host", v.get("host_ip", "unknown"))
                if cve not in seen_cves:
                    recs.append(
                        f"Remediate {cve} on {host} within the next patch cycle."
                    )
                    seen_cves.add(cve)

        # Service-level recommendations
        for host in report_data.hosts:
            ip = host.get("ip_address", host.get("ip", ""))
            for port in host.get("ports", []):
                svc = (port.get("service_name", port.get("service", "")) or "").lower()
                pnum = port.get("port_number", port.get("port", 0))

                if svc == "telnet" or pnum == 23:
                    recs.append(
                        f"Disable Telnet (port 23) on {ip} — use SSH instead."
                    )
                if svc == "ftp" or pnum == 21:
                    recs.append(
                        f"Review FTP service on {ip}:21 — "
                        "disable anonymous access and consider SFTP."
                    )

            # Too many open ports
            open_ports = [
                p for p in host.get("ports", [])
                if p.get("state", "open") == "open"
            ]
            if len(open_ports) > 15:
                recs.append(
                    f"Host {ip} has {len(open_ports)} open ports — "
                    "close unnecessary services to reduce attack surface."
                )

        # General fallbacks
        if len(recs) < 3:
            recs.extend([
                "Ensure all software is updated to the latest stable versions.",
                "Close unnecessary ports and disable unused services.",
                "Enable multi-factor authentication on all critical systems.",
            ])

        return recs[:10]

    def _get_severity_color(self, severity: str) -> Tuple[float, float, float]:
        """Return an RGB 0-1 tuple for the given severity level."""
        return SEVERITY_COLORS_RGB.get(severity.lower(), (0.42, 0.42, 0.42))

    def _generate_inline_html(self, report_data: ReportData) -> str:
        """Fallback inline HTML generator when Jinja2 template is unavailable."""
        rd = report_data

        host_rows = ""
        for h in rd.hosts:
            ip = h.get("ip_address", h.get("ip", "N/A"))
            hostname = h.get("hostname", "N/A") or "N/A"
            os_n = h.get("os_name", h.get("os", "N/A")) or "N/A"
            risk = h.get("risk_score", 0)
            rl = h.get("risk_level", "info")
            col = SEVERITY_COLORS.get(rl, "#6B7280")
            port_count = len(h.get("ports", []))
            host_rows += (
                f'<tr><td>{ip}</td><td>{hostname}</td><td>{os_n}</td>'
                f'<td>{port_count}</td>'
                f'<td style="color:{col};font-weight:bold">{risk}</td>'
                f'<td><span class="badge" style="background:{col}">'
                f'{rl.upper()}</span></td></tr>\n'
            )

        vuln_rows = ""
        for v in rd.vulnerabilities:
            sev = v.get("severity", "info")
            col = SEVERITY_COLORS.get(sev, "#6B7280")
            cve = v.get("cve_id", "N/A") or "N/A"
            cve_link = (
                f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" '
                f'target="_blank" style="color:#60A5FA">{cve}</a>'
                if cve != "N/A" else "N/A"
            )
            vuln_rows += (
                f'<tr><td>{cve_link}</td>'
                f'<td><span class="badge" style="background:{col}">'
                f'{sev.upper()}</span></td>'
                f'<td>{v.get("cvss_score", "N/A")}</td>'
                f'<td>{v.get("title", "N/A")}</td>'
                f'<td>{v.get("affected_host", v.get("host_ip", "N/A"))}</td></tr>\n'
            )

        rec_items = ""
        for idx, rec in enumerate(rd.recommendations, 1):
            rec_items += f"<li>{rec}</li>\n"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Netrix Report — {rd.target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0F172A;color:#E2E8F0;font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.navbar{{background:#1E293B;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid #3B82F6}}
.navbar h1{{color:#60A5FA;font-size:20px}}
.navbar span{{color:#94A3B8;font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:24px 0}}
.card{{background:#1E293B;border-radius:10px;padding:20px;text-align:center;border:1px solid #334155}}
.card .value{{font-size:32px;font-weight:700}}
.card .label{{font-size:13px;color:#94A3B8;margin-top:4px}}
.section{{background:#1E293B;border-radius:10px;padding:24px;margin:20px 0;border:1px solid #334155}}
.section h2{{color:#60A5FA;margin-bottom:16px;font-size:18px;border-bottom:1px solid #334155;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#0F172A;color:#94A3B8;text-align:left;padding:10px 12px;font-weight:600;text-transform:uppercase;font-size:11px}}
td{{padding:10px 12px;border-bottom:1px solid #1E293B}}
tr:hover{{background:#1E293B}}
.badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;color:#FFF}}
.bar-chart{{margin:16px 0}}
.bar-row{{display:flex;align-items:center;margin:6px 0}}
.bar-label{{width:80px;font-size:13px;font-weight:600}}
.bar-track{{flex:1;height:22px;background:#1E293B;border-radius:4px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;transition:width 0.5s}}
.bar-count{{width:40px;text-align:right;font-size:13px;margin-left:8px}}
a{{color:#60A5FA;text-decoration:none}}
a:hover{{text-decoration:underline}}
ol{{padding-left:20px}}
ol li{{margin:6px 0;font-size:14px}}
@media print{{body{{background:#fff;color:#1a1a1a}}th{{background:#f1f5f9}}}}
</style>
</head>
<body>
<div class="navbar">
  <h1>🛡️ NETRIX</h1>
  <span>{rd.report_name} — Generated {rd.generated_at}</span>
</div>
<div class="container">

<div class="cards">
  <div class="card">
    <div class="value" style="color:{SEVERITY_COLORS.get(rd.overall_severity.lower(),'#6B7280')}">{rd.overall_risk_score}</div>
    <div class="label">Risk Score</div>
  </div>
  <div class="card">
    <div class="value">{rd.total_hosts}</div>
    <div class="label">Total Hosts</div>
  </div>
  <div class="card">
    <div class="value">{rd.total_vulnerabilities}</div>
    <div class="label">Total Vulnerabilities</div>
  </div>
  <div class="card">
    <div class="value" style="color:#DC2626">{rd.critical_count}</div>
    <div class="label">Critical</div>
  </div>
</div>

<div class="section">
  <h2>Vulnerability Distribution</h2>
  <div class="bar-chart">
    <div class="bar-row"><span class="bar-label" style="color:#DC2626">Critical</span><div class="bar-track"><div class="bar-fill" style="width:{min(rd.critical_count*10,100)}%;background:#DC2626"></div></div><span class="bar-count">{rd.critical_count}</span></div>
    <div class="bar-row"><span class="bar-label" style="color:#EA580C">High</span><div class="bar-track"><div class="bar-fill" style="width:{min(rd.high_count*10,100)}%;background:#EA580C"></div></div><span class="bar-count">{rd.high_count}</span></div>
    <div class="bar-row"><span class="bar-label" style="color:#CA8A04">Medium</span><div class="bar-track"><div class="bar-fill" style="width:{min(rd.medium_count*10,100)}%;background:#CA8A04"></div></div><span class="bar-count">{rd.medium_count}</span></div>
    <div class="bar-row"><span class="bar-label" style="color:#16A34A">Low</span><div class="bar-track"><div class="bar-fill" style="width:{min(rd.low_count*10,100)}%;background:#16A34A"></div></div><span class="bar-count">{rd.low_count}</span></div>
    <div class="bar-row"><span class="bar-label" style="color:#3B82F6">Info</span><div class="bar-track"><div class="bar-fill" style="width:{min(rd.info_count*10,100)}%;background:#3B82F6"></div></div><span class="bar-count">{rd.info_count}</span></div>
  </div>
</div>

<div class="section">
  <h2>Discovered Hosts</h2>
  <table>
    <thead><tr><th>IP Address</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Risk Score</th><th>Risk Level</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table>
</div>

<div class="section">
  <h2>Vulnerabilities</h2>
  <table>
    <thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Affected Host</th></tr></thead>
    <tbody>{vuln_rows}</tbody>
  </table>
</div>

<div class="section">
  <h2>Recommendations</h2>
  <ol>{rec_items}</ol>
</div>

<div style="text-align:center;padding:24px;color:#64748B;font-size:12px">
  Generated by Netrix v{self.settings.APP_VERSION} — {rd.generated_at}<br>
  &copy; {datetime.now().year} Netrix Security Platform. CONFIDENTIAL.
</div>
</div>
</body>
</html>"""

    # ─────────────────────────────────────
    # Data Preparation
    # ─────────────────────────────────────
    def prepare_report_data(
        self,
        scan_summary: Any,
        vulnerability_matches: Any,
        generated_by: str = "Netrix System",
    ) -> ReportData:
        """
        Prepare a ``ReportData`` object from raw scan results and
        vulnerability matches.

        Works with dictionaries, ScanSummary dataclasses (with ``__dict__``
        or ``asdict``), or the Scan ORM model.

        Args:
            scan_summary:         Scan result data (dict or object).
            vulnerability_matches: List of vulnerability dicts/objects.
            generated_by:         Attribution string.

        Returns:
            ReportData: A fully populated report data container.
        """
        # Normalise scan_summary to dict
        if hasattr(scan_summary, "__dict__") and not isinstance(scan_summary, dict):
            summary = {
                k: v for k, v in scan_summary.__dict__.items()
                if not k.startswith("_")
            }
        elif isinstance(scan_summary, dict):
            summary = scan_summary
        else:
            summary = {}

        # Normalise vulnerability_matches to list of dicts
        vuln_list: List[Dict] = []
        if vulnerability_matches:
            for vm in vulnerability_matches:
                if isinstance(vm, dict):
                    vuln_list.append(vm)
                elif hasattr(vm, "__dict__"):
                    vuln_list.append({
                        k: v for k, v in vm.__dict__.items()
                        if not k.startswith("_")
                    })
                elif hasattr(vm, "to_dict"):
                    vuln_list.append(vm.to_dict())

        # Extract host data
        hosts_raw = summary.get("hosts", [])
        if not isinstance(hosts_raw, list):
            hosts_raw = []

        # Count severities
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vuln_list:
            sev = v.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            else:
                sev_counts["info"] += 1

        total_vulns = sum(sev_counts.values())

        # Count ports
        total_open_ports = 0
        for h in hosts_raw:
            ports = h.get("ports", [])
            total_open_ports += len([
                p for p in ports
                if p.get("state", "open") == "open"
            ])

        # Calculate risk score (weighted average 0-100)
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        risk_sum = sum(weights.get(s, 0) * c for s, c in sev_counts.items())
        max_possible = total_vulns * 10 if total_vulns > 0 else 1
        overall_risk = min(round((risk_sum / max_possible) * 100), 100)

        if overall_risk >= 80:
            overall_severity = "critical"
        elif overall_risk >= 60:
            overall_severity = "high"
        elif overall_risk >= 40:
            overall_severity = "medium"
        elif overall_risk >= 20:
            overall_severity = "low"
        else:
            overall_severity = "info"

        # Duration
        started = summary.get("started_at", "")
        completed = summary.get("completed_at", "")
        duration = summary.get("duration", summary.get("scan_duration", ""))
        if not duration and started and completed:
            try:
                duration = str(completed)
            except Exception:
                duration = "N/A"

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        rd = ReportData(
            scan_id=str(summary.get("scan_id", "")),
            report_name=f"Netrix Report — {summary.get('target', 'Unknown')}",
            generated_at=generated_at,
            generated_by=generated_by,
            target=str(summary.get("target", "")),
            scan_type=str(summary.get("scan_type", "full")),
            scan_duration=str(duration) if duration else "N/A",
            started_at=str(started) if started else "N/A",
            completed_at=str(completed) if completed else "N/A",
            nmap_command=str(summary.get("nmap_command", summary.get("scan_args", ""))),
            total_hosts=int(summary.get("total_hosts", len(hosts_raw))),
            hosts_up=int(summary.get("hosts_up", 0)),
            hosts_down=int(summary.get("hosts_down", 0)),
            total_open_ports=total_open_ports,
            total_vulnerabilities=total_vulns,
            critical_count=sev_counts["critical"],
            high_count=sev_counts["high"],
            medium_count=sev_counts["medium"],
            low_count=sev_counts["low"],
            info_count=sev_counts["info"],
            overall_risk_score=overall_risk,
            overall_severity=overall_severity,
            hosts=hosts_raw,
            vulnerabilities=vuln_list,
        )

        # Auto-generate executive summary and recommendations
        rd.executive_summary = self._generate_executive_summary(rd)
        rd.recommendations = self._generate_recommendations(rd)

        logger.info(
            "[NETRIX] ReportData prepared: %d hosts, %d vulns, risk=%d (%s)",
            rd.total_hosts, rd.total_vulnerabilities,
            rd.overall_risk_score, rd.overall_severity,
        )
        return rd
