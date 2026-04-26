#!/usr/bin/env python3
"""Generate a PDF of the Netrix project main source files."""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Preformatted, PageBreak,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfgen import canvas

# Main files to include in the PDF
MAIN_FILES = [
    # Root config
    ("docker-compose.yml", "Configuration"),
    ("frontend/nginx.conf", "Configuration"),
    # Backend core
    ("backend/app/main.py", "Backend - Core"),
    ("backend/app/config.py", "Backend - Core"),
    ("backend/app/dependencies.py", "Backend - Core"),
    # API routes
    ("backend/app/api/router.py", "Backend - API"),
    ("backend/app/api/v1/auth.py", "Backend - API"),
    ("backend/app/api/v1/scans.py", "Backend - API"),
    ("backend/app/api/v1/hosts.py", "Backend - API"),
    ("backend/app/api/v1/vulnerabilities.py", "Backend - API"),
    ("backend/app/api/v1/dashboard.py", "Backend - API"),
    ("backend/app/api/v1/reports.py", "Backend - API"),
    ("backend/app/api/v1/users.py", "Backend - API"),
    ("backend/app/api/v1/admin.py", "Backend - API"),
    # Models
    ("backend/app/models/user.py", "Backend - Models"),
    ("backend/app/models/scan.py", "Backend - Models"),
    ("backend/app/models/host.py", "Backend - Models"),
    ("backend/app/models/port.py", "Backend - Models"),
    ("backend/app/models/vulnerability.py", "Backend - Models"),
    ("backend/app/models/report.py", "Backend - Models"),
    ("backend/app/models/system_metric.py", "Backend - Models"),
    # Schemas
    ("backend/app/schemas/user.py", "Backend - Schemas"),
    ("backend/app/schemas/scan.py", "Backend - Schemas"),
    ("backend/app/schemas/host.py", "Backend - Schemas"),
    ("backend/app/schemas/vulnerability.py", "Backend - Schemas"),
    ("backend/app/schemas/report.py", "Backend - Schemas"),
    ("backend/app/schemas/admin.py", "Backend - Schemas"),
    # Core modules
    ("backend/app/core/security.py", "Backend - Core Modules"),
    ("backend/app/core/middleware.py", "Backend - Core Modules"),
    ("backend/app/core/exceptions.py", "Backend - Core Modules"),
    ("backend/app/core/validators.py", "Backend - Core Modules"),
    ("backend/app/core/metrics_task.py", "Backend - Core Modules"),
    # Database
    ("backend/app/database/session.py", "Backend - Database"),
    ("backend/app/database/init_db.py", "Backend - Database"),
    # Services
    ("backend/app/services/auth_service.py", "Backend - Services"),
    ("backend/app/services/scan_service.py", "Backend - Services"),
    ("backend/app/services/cve_service.py", "Backend - Services"),
    ("backend/app/services/report_service.py", "Backend - Services"),
    ("backend/app/services/health_service.py", "Backend - Services"),
    ("backend/app/services/audit_service.py", "Backend - Services"),
    # Scanner
    ("backend/app/scanner/scan_manager.py", "Backend - Scanner"),
    ("backend/app/scanner/nmap_engine.py", "Backend - Scanner"),
    ("backend/app/scanner/vuln_engine.py", "Backend - Scanner"),
    ("backend/app/scanner/report_engine.py", "Backend - Scanner"),
    ("backend/app/scanner/script_engine.py", "Backend - Scanner"),
    # Frontend
    ("frontend/src/main.jsx", "Frontend - Core"),
    ("frontend/src/App.jsx", "Frontend - Core"),
    ("frontend/src/services/api.js", "Frontend - Services"),
    ("frontend/src/store/index.js", "Frontend - State"),
    ("frontend/src/context/ThemeContext.jsx", "Frontend - Context"),
    ("frontend/src/context/ToastContext.jsx", "Frontend - Context"),
    # Frontend pages
    ("frontend/src/pages/Login.jsx", "Frontend - Pages"),
    ("frontend/src/pages/Register.jsx", "Frontend - Pages"),
    ("frontend/src/pages/Dashboard.jsx", "Frontend - Pages"),
    ("frontend/src/pages/NewScan.jsx", "Frontend - Pages"),
    ("frontend/src/pages/ScanResults.jsx", "Frontend - Pages"),
    ("frontend/src/pages/History.jsx", "Frontend - Pages"),
    ("frontend/src/pages/Vulnerabilities.jsx", "Frontend - Pages"),
    ("frontend/src/pages/Reports.jsx", "Frontend - Pages"),
    ("frontend/src/pages/Settings.jsx", "Frontend - Pages"),
    ("frontend/src/pages/AdminUsers.jsx", "Frontend - Admin"),
    ("frontend/src/pages/AdminScans.jsx", "Frontend - Admin"),
    ("frontend/src/pages/AdminLogs.jsx", "Frontend - Admin"),
    ("frontend/src/pages/AdminHealth.jsx", "Frontend - Admin"),
    ("frontend/src/pages/AdminCVE.jsx", "Frontend - Admin"),
    # Frontend components
    ("frontend/src/components/Layout.jsx", "Frontend - Components"),
    ("frontend/src/components/Navbar.jsx", "Frontend - Components"),
    ("frontend/src/components/Sidebar.jsx", "Frontend - Components"),
    ("frontend/src/components/ScanCard.jsx", "Frontend - Components"),
    ("frontend/src/components/VulnBadge.jsx", "Frontend - Components"),
    ("frontend/src/components/ProtectedRoute.jsx", "Frontend - Components"),
    ("frontend/src/components/AdminRoute.jsx", "Frontend - Components"),
    # CLI
    ("cli/netrix_cli.py", "CLI"),
    ("cli/api_client.py", "CLI"),
    ("cli/config.py", "CLI"),
    ("cli/commands/scan.py", "CLI - Commands"),
    ("cli/commands/auth.py", "CLI - Commands"),
    ("cli/commands/dashboard.py", "CLI - Commands"),
    ("cli/commands/vulns.py", "CLI - Commands"),
    ("cli/commands/report.py", "CLI - Commands"),
    ("cli/commands/history.py", "CLI - Commands"),
    ("cli/ui/panels.py", "CLI - UI"),
    ("cli/ui/tables.py", "CLI - UI"),
    ("cli/ui/banners.py", "CLI - UI"),
]

BASE_DIR = "/root/Netrix"
OUTPUT_PATH = "/root/Netrix/Netrix_Project_Code.pdf"


def add_page_number(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(colors.HexColor("#666666"))
    page_num = canvas_obj.getPageNumber()
    canvas_obj.drawRightString(A4[0] - 1.5 * cm, 0.8 * cm, f"Page {page_num}")
    canvas_obj.drawString(1.5 * cm, 0.8 * cm, "Netrix - Network Security Scanner")
    canvas_obj.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PATH,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=2 * cm,
        bottomMargin=1.8 * cm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=28,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=8,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontSize=13,
        textColor=colors.HexColor("#16213e"),
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    info_style = ParagraphStyle(
        "InfoStyle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#555555"),
        spaceAfter=2,
        alignment=TA_CENTER,
    )
    section_style = ParagraphStyle(
        "SectionStyle",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=colors.HexColor("#0f3460"),
        spaceBefore=14,
        spaceAfter=4,
        borderPad=4,
    )
    file_header_style = ParagraphStyle(
        "FileHeaderStyle",
        parent=styles["Heading2"],
        fontSize=10,
        textColor=colors.white,
        backColor=colors.HexColor("#16213e"),
        spaceBefore=10,
        spaceAfter=0,
        leftIndent=4,
        rightIndent=4,
        borderPad=5,
    )
    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Code"],
        fontSize=7,
        fontName="Courier",
        textColor=colors.HexColor("#1a1a1a"),
        backColor=colors.HexColor("#f8f8f8"),
        leftIndent=4,
        rightIndent=4,
        spaceBefore=0,
        spaceAfter=6,
        borderColor=colors.HexColor("#dddddd"),
        borderWidth=0.5,
        borderPad=5,
    )
    toc_item_style = ParagraphStyle(
        "TocItem",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=2,
        leftIndent=12,
    )
    toc_section_style = ParagraphStyle(
        "TocSection",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#0f3460"),
        spaceBefore=6,
        spaceAfter=2,
        fontName="Helvetica-Bold",
    )

    story = []

    # ── Cover Page ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("NETRIX", title_style))
    story.append(Paragraph("Network Security Scanner", subtitle_style))
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="80%", thickness=2, color=colors.HexColor("#0f3460"), spaceAfter=16))
    story.append(Paragraph("Project Source Code Documentation", info_style))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Date: April 23, 2026", info_style))
    story.append(Spacer(1, 2 * cm))

    # Project description table
    desc_data = [
        ["Project", "Netrix - Network Security Scanner"],
        ["Stack", "FastAPI (Python) · React (JSX) · PostgreSQL · Docker"],
        ["Features", "Port scanning, CVE matching, Vulnerability reports, CLI, Admin panel"],
        ["Author", "Student Project"],
    ]
    desc_table = Table(desc_data, colWidths=[4 * cm, 13 * cm])
    desc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#16213e")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f0f4ff")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1a1a2e")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.HexColor("#f0f4ff"), colors.HexColor("#e8eeff")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(desc_table)
    story.append(PageBreak())

    # ── Table of Contents ────────────────────────────────────────────────────
    story.append(Paragraph("Table of Contents", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceAfter=10))

    current_section = None
    for rel_path, section in MAIN_FILES:
        full_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(full_path):
            continue
        if section != current_section:
            story.append(Paragraph(section, toc_section_style))
            current_section = section
        story.append(Paragraph(f"• {rel_path}", toc_item_style))

    story.append(PageBreak())

    # ── Source Files ─────────────────────────────────────────────────────────
    current_section = None
    included = 0

    for rel_path, section in MAIN_FILES:
        full_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"  [SKIP] {rel_path}")
            continue

        # Section header
        if section != current_section:
            story.append(Paragraph(section, section_style))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460"), spaceAfter=6))
            current_section = section

        # File header bar
        story.append(Paragraph(f"  {rel_path}", file_header_style))

        # Read file content
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            content = f"[Error reading file: {e}]"

        # Truncate very large files to keep PDF under 10MB
        MAX_CHARS = 12000
        truncated = False
        if len(content) > MAX_CHARS:
            content = content[:MAX_CHARS]
            truncated = True

        # Escape for Preformatted (no XML escaping needed in Preformatted)
        story.append(Preformatted(content, code_style))

        if truncated:
            story.append(Paragraph(
                "<i>... [file truncated for length] ...</i>",
                ParagraphStyle("trunc", parent=styles["Normal"], fontSize=8,
                               textColor=colors.HexColor("#999999"), spaceAfter=6)
            ))

        included += 1
        print(f"  [OK]   {rel_path}")

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)

    size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
    print(f"\nDone! PDF saved to: {OUTPUT_PATH}")
    print(f"Files included: {included}")
    print(f"File size: {size_mb:.2f} MB")

    if size_mb > 10:
        print("WARNING: File exceeds 10 MB!")
    else:
        print("File size is within the 10 MB limit.")


if __name__ == "__main__":
    build_pdf()
