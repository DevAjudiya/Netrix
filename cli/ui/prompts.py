# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/ui/prompts.py
# Purpose: All InquirerPy interactive menus, wizards, and prompts.
# ─────────────────────────────────────────

from typing import List, Optional

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator


# ── Main Menu ─────────────────────────────────────────────────────────


def main_menu(logged_in: bool = False) -> str:
    """
    Interactive main menu.
    Shows Login/Register when logged out; Logout/Whoami when logged in.
    """
    choices = []

    if not logged_in:
        choices += [
            Choice("login",    "👤  Login"),
            Choice("register", "📝  Register"),
            Separator(),
        ]

    choices += [
        Choice("scan",      "🔍  New Scan"),
        Choice("dashboard", "📊  Dashboard"),
        Choice("vulns",     "🛡️   Vulnerabilities"),
        Choice("report",    "📄  Generate Report"),
        Choice("history",   "📜  Scan History"),
        Choice("config",    "⚙️   Settings"),
    ]

    if logged_in:
        choices += [
            Separator(),
            Choice("whoami", "👤  Account"),
            Choice("logout", "🚫  Logout"),
        ]

    choices += [
        Separator(),
        Choice("exit", "🚪  Exit"),
    ]

    default = "scan" if logged_in else "login"
    result = inquirer.select(
        message="What would you like to do?",
        choices=choices,
        default=default,
        vi_mode=False,
    ).execute()
    return result


# ── Scan Wizard ───────────────────────────────────────────────────────


def prompt_target() -> str:
    """Step 1: Ask for scan target with validation."""
    import re

    _IP_RE    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    _CIDR_RE  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
    _RANGE_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$")
    _DOMAIN_RE = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    def _validate(val: str) -> bool:
        val = val.strip()
        return bool(
            _IP_RE.match(val)
            or _CIDR_RE.match(val)
            or _RANGE_RE.match(val)
            or _DOMAIN_RE.match(val)
        )

    result = inquirer.text(
        message="Enter target (IP / CIDR / Domain):",
        validate=lambda val: _validate(val) or "Invalid format. Use: 192.168.1.1 | 192.168.1.0/24 | example.com",
        invalid_message="Invalid target format.",
        long_instruction=(
            "  Supported formats:\n"
            "    • Single IP  : 192.168.1.1\n"
            "    • CIDR Range : 192.168.1.0/24\n"
            "    • Domain     : example.com\n"
            "    • IP Range   : 192.168.1.1-50"
        ),
    ).execute()
    return result.strip()


def prompt_scan_type() -> str:
    """Step 2: Select scan type with descriptions."""
    result = inquirer.select(
        message="Select scan type:",
        choices=[
            Choice("quick",
                   "⚡ Quick Scan      — Top 100 ports • ~2 min • Fast recon"),
            Choice("stealth",
                   "🥷 Stealth Scan    — SYN scan • All ports • ~20 min • IDS evasion"),
            Choice("full",
                   "🔍 Full Scan       — All ports + OS + Scripts • ~30 min"),
            Choice("aggressive",
                   "💥 Aggressive Scan — Everything + Traceroute • ~45 min"),
            Choice("vulnerability",
                   "🛡️  Vuln Scan       — NSE vuln scripts + CVE detection • ~60 min"),
        ],
        default="quick",
    ).execute()
    return result


def prompt_output_formats() -> List[str]:
    """Step 3: Select optional report formats (multi-select)."""
    want_report = inquirer.confirm(
        message="Auto-generate report after scan?",
        default=False,
    ).execute()

    if not want_report:
        return []

    formats = inquirer.checkbox(
        message="Select format(s): (Space to select, Enter to confirm)",
        choices=[
            Choice("pdf",  "PDF  — Professional assessment report"),
            Choice("json", "JSON — Machine-readable structured data"),
            Choice("csv",  "CSV  — Spreadsheet compatible"),
            Choice("html", "HTML — Browser viewable report"),
        ],
        default=["pdf"],
        validate=lambda result: len(result) > 0 or "Select at least one format.",
    ).execute()
    return formats


def prompt_scan_confirm(target: str, scan_type: str, formats: List[str]) -> str:
    """Step 4: Confirm or edit scan configuration.

    Returns: 'start' | 'edit' | 'cancel'
    """
    result = inquirer.select(
        message=f"Ready to scan {target} ({scan_type})?",
        choices=[
            Choice("start",  "▶  Start Scan"),
            Choice("edit",   "✏️   Edit Configuration"),
            Choice("cancel", "✖  Cancel"),
        ],
        default="start",
    ).execute()
    return result


def prompt_post_scan(scan_id: str) -> str:
    """Post-scan 'What next?' menu. Returns action key."""
    result = inquirer.select(
        message="What would you like to do next?",
        choices=[
            Choice("results", "📋  View detailed results"),
            Choice("vulns",   "🛡️   View vulnerabilities"),
            Choice("report",  "📄  Generate report"),
            Choice("scan",    "🔍  Start another scan"),
            Choice("menu",    "🏠  Back to main menu"),
        ],
        default="results",
    ).execute()
    return result


# ── Auth prompts ──────────────────────────────────────────────────────


def prompt_login_credentials() -> dict:
    """Prompt for username and password."""
    username = inquirer.text(
        message="Username:",
        validate=lambda v: len(v.strip()) > 0 or "Username required",
    ).execute()

    password = inquirer.secret(
        message="Password:",
        validate=lambda v: len(v) > 0 or "Password required",
    ).execute()

    return {"username": username.strip(), "password": password}


def prompt_register_credentials() -> dict:
    """Prompt for new account details."""
    username = inquirer.text(
        message="Username:",
        validate=lambda v: len(v.strip()) >= 3 or "Username must be at least 3 characters",
    ).execute()

    email = inquirer.text(
        message="Email:",
        validate=lambda v: "@" in v and "." in v or "Enter a valid email address",
    ).execute()

    password = inquirer.secret(
        message="Password (8+ chars, 1 uppercase, 1 digit, 1 special):",
        validate=lambda v: len(v) >= 8 or "Password must be at least 8 characters",
    ).execute()

    confirm = inquirer.secret(
        message="Confirm password:",
        validate=lambda v: v == password or "Passwords do not match",
    ).execute()

    return {
        "username": username.strip(),
        "email": email.strip(),
        "password": password,
    }


# ── Report prompts ────────────────────────────────────────────────────


def prompt_select_scan(scans: list) -> Optional[int]:
    """Select a scan from a list. Returns numeric scan ID."""
    if not scans:
        return None

    choices = []
    for sc in scans:
        sid = sc.get("scan_id", sc.get("id", "?"))
        tgt = sc.get("target", "N/A")
        stype = sc.get("scan_type", "")
        status = sc.get("status", "")
        created = sc.get("created_at", "")
        if isinstance(created, str) and "T" in created:
            created = created.split("T")[0]
        label = f"{sid}  •  {tgt}  •  {stype}  •  {status}  •  {created}"
        choices.append(Choice(sc.get("id"), label))

    choices.append(Separator())
    choices.append(Choice(None, "← Cancel"))

    result = inquirer.select(
        message="Select scan:",
        choices=choices,
    ).execute()
    return result


def prompt_report_formats() -> List[str]:
    """Multi-select report formats."""
    return inquirer.checkbox(
        message="Select format(s):",
        choices=[
            Choice("pdf",  "PDF  — Professional assessment report"),
            Choice("json", "JSON — Machine-readable structured data"),
            Choice("csv",  "CSV  — Spreadsheet compatible"),
            Choice("html", "HTML — Browser viewable report"),
        ],
        default=["pdf"],
        validate=lambda r: len(r) > 0 or "Select at least one format.",
    ).execute()


# ── Vulnerability prompts ─────────────────────────────────────────────


def prompt_severity_filter() -> str:
    """Select severity filter for vulnerability browser."""
    return inquirer.select(
        message="Filter by severity:",
        choices=[
            Choice("all",      "All"),
            Choice("critical", "🔴 Critical"),
            Choice("high",     "🟠 High"),
            Choice("medium",   "🟡 Medium"),
            Choice("low",      "🔵 Low"),
        ],
        default="all",
    ).execute()


def prompt_select_vuln(vulns: list) -> Optional[str]:
    """Select a vulnerability from a list. Returns CVE ID."""
    if not vulns:
        return None

    choices = []
    for v in vulns:
        cve_id = v.get("cve_id", "N/A")
        cvss = v.get("cvss_score", "?")
        severity = v.get("severity", "")
        host = v.get("host_ip", v.get("ip_address", ""))
        label = f"{cve_id}  CVSS:{cvss}  {severity.upper()}  {host}"
        choices.append(Choice(cve_id, label))

    choices.append(Separator())
    choices.append(Choice(None, "← Back"))

    return inquirer.select(
        message="Select CVE for details:",
        choices=choices,
    ).execute()


# ── History prompts ───────────────────────────────────────────────────


def prompt_history_action() -> str:
    """Actions for a selected scan in history."""
    return inquirer.select(
        message="Action:",
        choices=[
            Choice("view",   "📋  View scan results"),
            Choice("report", "📄  Generate report"),
            Choice("delete", "🗑️   Delete scan"),
            Choice("back",   "🏠  Back"),
        ],
    ).execute()


def prompt_confirm_delete(item: str) -> bool:
    """Confirm deletion of a resource."""
    return inquirer.confirm(
        message=f"Are you sure you want to delete {item}? This cannot be undone.",
        default=False,
    ).execute()


# ── Config prompts ────────────────────────────────────────────────────


def prompt_config_action() -> str:
    """Interactive config menu."""
    return inquirer.select(
        message="Configuration — what would you like to change?",
        choices=[
            Choice("api_url",           "🌐  API URL"),
            Choice("default_scan_type", "⚡  Default scan type"),
            Choice("default_format",    "📄  Default report format"),
            Choice("output_dir",        "📁  Report output directory"),
            Choice("theme",             "🎨  Theme (dark/light)"),
            Separator(),
            Choice("list",  "📋  Show all settings"),
            Choice("reset", "🔄  Reset to defaults"),
            Choice("back",  "← Back"),
        ],
    ).execute()
