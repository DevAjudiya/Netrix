# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/utils/display.py
# Purpose: Rich UI helper functions — banner, panels,
#          tables, badges, and color-coded outputs.
# Author: Netrix Development Team
# ─────────────────────────────────────────

from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


# ─────────────────────────────────────────
# Banner
# ─────────────────────────────────────────
BANNER_ART = r"""
 ███╗   ██╗███████╗████████╗██████╗ ██╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║ ╚███╔╝
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║ ██╔██╗
 ██║ ╚████║███████╗   ██║   ██║  ██║██║██╔╝ ██╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""


def show_banner() -> None:
    """Display the Netrix ASCII-art banner at startup."""
    console.print(
        Panel(
            Text.from_markup(
                f"[bold cyan]{BANNER_ART}[/bold cyan]\n"
                "[bold white]  Network Scanner v1.0  •  "
                "Advanced Vulnerability Assessment[/bold white]"
            ),
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ─────────────────────────────────────────
# Message panels
# ─────────────────────────────────────────
def show_success(message: str) -> None:
    """Show a green success panel."""
    console.print(Panel(f"[bold green]✅ {message}[/bold green]", border_style="green"))


def show_error(message: str) -> None:
    """Show a red error panel."""
    console.print(Panel(f"[bold red]❌ {message}[/bold red]", border_style="red"))


def show_warning(message: str) -> None:
    """Show a yellow warning panel."""
    console.print(Panel(f"[bold yellow]⚠️  {message}[/bold yellow]", border_style="yellow"))


def show_info(message: str) -> None:
    """Show a blue info panel."""
    console.print(Panel(f"[bold blue]ℹ️  {message}[/bold blue]", border_style="blue"))


# ─────────────────────────────────────────
# Risk score & severity helpers
# ─────────────────────────────────────────
def show_risk_score(score: int) -> str:
    """
    Return a Rich-markup string with a color-coded risk score.

    Args:
        score: Integer risk score (0–100).

    Returns:
        str: Color-coded markup string, e.g. ``🟢 INFO (12)``.
    """
    if score <= 20:
        return f"[green]🟢 INFO ({score})[/green]"
    if score <= 40:
        return f"[blue]🔵 LOW ({score})[/blue]"
    if score <= 60:
        return f"[yellow]🟡 MEDIUM ({score})[/yellow]"
    if score <= 80:
        return f"[dark_orange]🟠 HIGH ({score})[/dark_orange]"
    return f"[bold red]🔴 CRITICAL ({score})[/bold red]"


def show_severity_badge(severity: str) -> str:
    """
    Return a Rich-markup badge for a vulnerability severity level.

    Args:
        severity: One of critical, high, medium, low, info.

    Returns:
        str: Color-coded badge string.
    """
    severity_lower = (severity or "").lower()
    mapping = {
        "critical": "[bold red]🔴 CRIT[/bold red]",
        "high":     "[dark_orange]🟠 HIGH[/dark_orange]",
        "medium":   "[yellow]🟡 MED[/yellow]",
        "low":      "[blue]🔵 LOW[/blue]",
        "info":     "[green]🟢 INFO[/green]",
    }
    return mapping.get(severity_lower, f"[white]{severity}[/white]")


def show_status_badge(status: str) -> str:
    """
    Return a Rich-markup badge for a scan status.

    Args:
        status: One of pending, running, completed, failed.

    Returns:
        str: Color-coded status string.
    """
    status_lower = (status or "").lower()
    mapping = {
        "pending":   "[yellow]⏳ Pending[/yellow]",
        "running":   "[cyan]🔄 Running[/cyan]",
        "completed": "[green]✅ Done[/green]",
        "failed":    "[red]❌ Failed[/red]",
    }
    return mapping.get(status_lower, f"[white]{status}[/white]")


# ─────────────────────────────────────────
# Table builders
# ─────────────────────────────────────────
def create_hosts_table(hosts: List[Dict]) -> Table:
    """
    Build a Rich table for discovered hosts.

    Args:
        hosts: List of host dictionaries from the API.

    Returns:
        Table: A Rich Table ready for printing.
    """
    table = Table(
        title="🖥️  HOSTS FOUND",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("IP Address", style="bold white", min_width=14)
    table.add_column("Hostname", style="white")
    table.add_column("OS", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Risk Score", min_width=18)

    for host in hosts:
        risk = host.get("risk_score", 0) or 0
        table.add_row(
            host.get("ip_address", "N/A"),
            host.get("hostname", "—") or "—",
            host.get("os_name", "—") or "—",
            host.get("status", "—") or "—",
            show_risk_score(risk),
        )
    return table


def create_ports_table(hosts: List[Dict]) -> Table:
    """
    Build a Rich table showing open ports across all hosts.

    Args:
        hosts: List of host dictionaries (each containing a 'ports' list).

    Returns:
        Table: A Rich Table ready for printing.
    """
    table = Table(
        title="🔌  OPEN PORTS",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Host", style="bold white", min_width=14)
    table.add_column("Port", justify="right", style="bold white")
    table.add_column("Proto", style="dim")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Product / Version", style="white")
    table.add_column("Critical", justify="center")

    for host in hosts:
        ip = host.get("ip_address", "N/A")
        ports = host.get("ports", [])
        if not ports:
            continue
        for i, port in enumerate(ports):
            is_crit = port.get("is_critical_port", False)
            product = port.get("product", "")
            version = port.get("version", "")
            prod_ver = f"{product} {version}".strip() if product or version else "—"
            crit_badge = "[bold red]⚠ YES[/bold red]" if is_crit else "[dim]—[/dim]"

            table.add_row(
                ip if i == 0 else "",  # Only show IP on first row per host
                str(port.get("port_number", "—")),
                port.get("protocol", "tcp"),
                port.get("state", "—"),
                port.get("service_name", "—") or "—",
                prod_ver,
                crit_badge,
            )

    return table


def create_vulns_table(vulns: List[Dict]) -> Table:
    """
    Build a Rich table for discovered vulnerabilities.

    Args:
        vulns: List of vulnerability dictionaries from the API.

    Returns:
        Table: A Rich Table ready for printing.
    """
    table = Table(
        title="🛡️  VULNERABILITIES FOUND",
        title_style="bold cyan",
        border_style="red",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold white", min_width=18)
    table.add_column("Severity", min_width=10)
    table.add_column("CVSS", justify="center", style="white")
    table.add_column("Title", style="white", max_width=40)

    for vuln in vulns:
        table.add_row(
            vuln.get("cve_id", "N/A") or "N/A",
            show_severity_badge(vuln.get("severity", "")),
            str(vuln.get("cvss_score", "—") or "—"),
            vuln.get("title", "—") or "—",
        )
    return table


def create_scans_table(scans: List[Dict]) -> Table:
    """
    Build a Rich table for the scans list.

    Args:
        scans: List of scan dictionaries from the API.

    Returns:
        Table: A Rich Table ready for printing.
    """
    table = Table(
        title="📋  SCAN HISTORY",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Scan ID", style="bold white", min_width=18)
    table.add_column("Target", style="white")
    table.add_column("Type", style="yellow")
    table.add_column("Status", min_width=12)
    table.add_column("Hosts", justify="center", style="white")
    table.add_column("Created", style="dim")

    for scan in scans:
        created = scan.get("created_at", "")
        if isinstance(created, str) and "T" in created:
            created = created.split("T")[0]

        table.add_row(
            str(scan.get("id", "")),
            scan.get("scan_id", "N/A"),
            scan.get("target", "N/A"),
            scan.get("scan_type", "N/A"),
            show_status_badge(scan.get("status", "")),
            str(scan.get("total_hosts", 0)),
            str(created),
        )
    return table


def create_reports_table(reports: List[Dict]) -> Table:
    """
    Build a Rich table for the reports list.

    Args:
        reports: List of report dictionaries from the API.

    Returns:
        Table: A Rich Table ready for printing.
    """
    table = Table(
        title="📄  REPORTS",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Report Name", style="bold white", min_width=22)
    table.add_column("Format", style="yellow", justify="center")
    table.add_column("Size", style="white", justify="right")
    table.add_column("Hosts", justify="center")
    table.add_column("Vulns", justify="center")
    table.add_column("Generated", style="dim")

    for report in reports:
        generated = report.get("generated_at", "")
        if isinstance(generated, str) and "T" in generated:
            generated = generated.split("T")[0]

        table.add_row(
            str(report.get("id", "")),
            report.get("report_name", "N/A"),
            (report.get("format", "N/A") or "N/A").upper(),
            report.get("file_size_readable", "—"),
            str(report.get("total_hosts", 0)),
            str(report.get("total_vulnerabilities", 0)),
            str(generated),
        )
    return table


# ─────────────────────────────────────────
# Scan results summary panel
# ─────────────────────────────────────────
def show_scan_complete_panel(
    scan_id: str,
    duration: float,
    hosts_count: int,
    vulns_count: int,
    ports_count: int = 0,
) -> None:
    """
    Display a summary panel after a scan completes.

    Args:
        scan_id:     The unique scan identifier.
        duration:    Scan duration in seconds.
        hosts_count: Number of hosts discovered.
        vulns_count: Number of vulnerabilities found.
        ports_count: Number of open ports found.
    """
    if duration and duration > 0:
        minutes = int(duration // 60)
        seconds = int(duration % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
    else:
        duration_str = "N/A"

    panel_text = (
        f"[bold green]SCAN COMPLETE! ✅[/bold green]\n\n"
        f"  [bold]Scan ID:[/bold]          {scan_id}\n"
        f"  [bold]Duration:[/bold]         {duration_str}\n"
        f"  [bold]Hosts Found:[/bold]      {hosts_count}\n"
        f"  [bold]Open Ports:[/bold]       {ports_count}\n"
        f"  [bold]Vulnerabilities:[/bold]  {vulns_count}"
    )
    console.print(Panel(panel_text, border_style="green", padding=(1, 2)))


def show_scan_starting_panel(target: str, scan_type: str) -> None:
    """
    Display a panel when a scan is starting.

    Args:
        target:    The scan target (IP, CIDR, domain).
        scan_type: The type of scan being performed.
    """
    from datetime import datetime

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    panel_text = (
        f"[bold cyan]🔍 NETRIX SCAN STARTING[/bold cyan]\n\n"
        f"  [bold]Target:[/bold]   {target}\n"
        f"  [bold]Type:[/bold]     {scan_type.capitalize()} Scan\n"
        f"  [bold]Started:[/bold]  {now}"
    )
    console.print(Panel(panel_text, border_style="cyan", padding=(1, 2)))
