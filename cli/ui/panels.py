# ─────────────────────────────────────────
# Netrix — cli/ui/panels.py
# Purpose: Rich panels for errors, success, info, warnings,
#          scan summaries, and CVE details.
# ─────────────────────────────────────────

from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


# ── Message panels ───────────────────────────────────────────────────


def show_success(message: str) -> None:
    """Green success panel."""
    console.print(Panel(f"[bold green]✅  {message}[/bold green]", border_style="green"))


def show_error(message: str, fixes: Optional[List[str]] = None) -> None:
    """Red error panel with optional fix hints."""
    body = f"[bold red]{message}[/bold red]"
    if fixes:
        body += "\n\n[bold white]Possible fixes:[/bold white]"
        for i, fix in enumerate(fixes, 1):
            body += f"\n  {i}. {fix}"
    console.print(
        Panel(
            Text.from_markup(body),
            title="[bold red]❌ Error[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )


def show_warning(message: str) -> None:
    """Yellow warning panel."""
    console.print(Panel(f"[bold yellow]⚠️   {message}[/bold yellow]", border_style="yellow"))


def show_info(message: str) -> None:
    """Blue info panel."""
    console.print(Panel(f"[bold blue]ℹ️   {message}[/bold blue]", border_style="blue"))


def show_connection_error(api_url: str) -> None:
    """Formatted panel for backend connection failures."""
    show_error(
        f"Connection Failed\n\nCould not connect to Netrix backend at\n{api_url}",
        fixes=[
            "Check if backend is running: docker-compose up -d",
            f"Verify API URL: netrix config --list",
            "Check network connectivity",
        ],
    )


def show_auth_error() -> None:
    """Formatted panel for authentication failures."""
    show_error(
        "Session expired or not logged in.",
        fixes=["Run: netrix login"],
    )


# ── Scan panels ──────────────────────────────────────────────────────


def show_scan_starting_panel(target: str, scan_type: str) -> None:
    """Panel shown when a scan begins."""
    from datetime import datetime

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = (
        f"[bold cyan]🔍 NETRIX SCAN STARTING[/bold cyan]\n\n"
        f"  [bold]Target   :[/bold] {target}\n"
        f"  [bold]Type     :[/bold] {scan_type.capitalize()} Scan\n"
        f"  [bold]Started  :[/bold] {now}"
    )
    console.print(Panel(Text.from_markup(content), border_style="cyan", padding=(1, 2)))


def show_scan_config_panel(
    target: str,
    scan_type: str,
    formats: Optional[List[str]] = None,
    est_time: str = "",
) -> None:
    """Confirmation panel before starting a scan."""
    scan_descriptions = {
        "quick": "Top 100 ports",
        "stealth": "All ports (SYN scan)",
        "full": "All 65,535 ports + OS + Scripts",
        "aggressive": "All ports + Traceroute + Everything",
        "vulnerability": "NSE vuln scripts + CVE detection",
    }
    ports_desc = scan_descriptions.get(scan_type, "Default")
    fmt_str = ", ".join(f.upper() for f in formats) if formats else "None"

    content = (
        f"[bold white]Target     :[/bold white] {target}\n"
        f"[bold white]Scan Type  :[/bold white] {scan_type.capitalize()} Scan\n"
        f"[bold white]Ports      :[/bold white] {ports_desc}\n"
        f"[bold white]Est. Time  :[/bold white] {est_time or 'Varies'}\n"
        f"[bold white]Report     :[/bold white] {fmt_str}"
    )
    console.print(
        Panel(
            Text.from_markup(content),
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def show_scan_complete_panel(
    scan_id: str,
    duration: float,
    hosts_count: int,
    vulns_count: int,
    ports_count: int = 0,
    severity_breakdown: Optional[Dict] = None,
) -> None:
    """Summary panel after scan completes."""
    if duration and duration > 0:
        minutes = int(duration // 60)
        seconds = int(duration % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
    else:
        duration_str = "N/A"

    content = (
        f"[bold white]Scan ID    :[/bold white] {scan_id}\n"
        f"[bold white]Duration   :[/bold white] {duration_str}\n"
        f"[bold white]Hosts Up   :[/bold white] {hosts_count}\n"
        f"[bold white]Open Ports :[/bold white] {ports_count}\n"
        f"[bold white]Vulns Found:[/bold white] {vulns_count}"
    )

    if severity_breakdown:
        content += "\n\n[bold white]Severity Breakdown:[/bold white]"
        crit = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        med = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)
        if crit:
            content += f"\n  [bold red]🔴 Critical : {crit}[/bold red]"
        if high:
            content += f"\n  [dark_orange]🟠 High     : {high}[/dark_orange]"
        if med:
            content += f"\n  [yellow]🟡 Medium   : {med}[/yellow]"
        if low:
            content += f"\n  [blue]🔵 Low      : {low}[/blue]"

    console.print(
        Panel(
            Text.from_markup(content),
            title="[bold green]Scan Complete ✔[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


# ── CVE detail panel ─────────────────────────────────────────────────


def show_cve_detail_panel(cve: Dict) -> None:
    """Full CVE detail in a formatted panel."""
    from cli.ui.tables import severity_badge

    cve_id = cve.get("cve_id", "N/A")
    title = cve.get("title", "N/A")
    cvss = cve.get("cvss_score", "N/A")
    severity = cve.get("severity", "unknown")
    description = cve.get("description", "No description available.")
    remediation = cve.get("remediation", "No remediation info.")
    published = cve.get("published_date", "N/A")
    source = cve.get("source", "NVD")

    sev_badge = severity_badge(severity)
    content = (
        f"[bold white]CVSS Score  :[/bold white] {cvss} / 10.0  {sev_badge}\n"
        f"[bold white]Published   :[/bold white] {published}\n"
        f"[bold white]Source      :[/bold white] {source}\n"
        f"\n[bold white]Description:[/bold white]\n{description[:400]}"
        f"{'...' if len(str(description)) > 400 else ''}\n"
        f"\n[bold white]Remediation:[/bold white]\n{remediation[:300]}"
        f"{'...' if len(str(remediation)) > 300 else ''}"
    )
    console.print(
        Panel(
            Text.from_markup(content),
            title=f"[bold red]{cve_id}[/bold red]  [dim]{title[:50]}[/dim]",
            border_style="red",
            padding=(1, 2),
        )
    )


# ── Dashboard panel ───────────────────────────────────────────────────


def show_dashboard_panel(stats: Dict, recent_scans: List[Dict], vuln_chart: Optional[Dict] = None) -> None:
    """Full dashboard overview panel."""

    def _bar(count: int, max_count: int, width: int = 20) -> str:
        if max_count == 0:
            return "─" * width
        filled = int((count / max_count) * width)
        return "█" * filled + "░" * (width - filled)

    total_scans = stats.get("total_scans", 0)
    active_scans = stats.get("active_scans", 0)
    total_hosts = stats.get("total_hosts_discovered", 0)
    total_vulns = stats.get("total_vulnerabilities", 0)

    # Backend returns "critical_vulnerabilities" AND "high_count"/"medium_count"/"low_count"
    crit = stats.get("critical_vulnerabilities", stats.get("critical_count", 0))
    high = stats.get("high_vulnerabilities", stats.get("high_count", 0))
    med = stats.get("medium_vulnerabilities", stats.get("medium_count", 0))
    low = stats.get("low_vulnerabilities", stats.get("low_count", 0))
    max_v = max(crit, high, med, low, 1)

    content = (
        f"[bold white]Total Scans     :[/bold white] {total_scans}\n"
        f"[bold white]Active Scans    :[/bold white] {active_scans}\n"
        f"[bold white]Hosts Discovered:[/bold white] {total_hosts}\n"
        f"[bold white]Total Vulns     :[/bold white] {total_vulns}\n"
        f"\n[bold white]Severity Overview:[/bold white]\n"
        f"  [bold red]Critical  {_bar(crit, max_v)}  {crit}[/bold red]\n"
        f"  [dark_orange]High      {_bar(high, max_v)}  {high}[/dark_orange]\n"
        f"  [yellow]Medium    {_bar(med,  max_v)}  {med}[/yellow]\n"
        f"  [blue]Low       {_bar(low,  max_v)}  {low}[/blue]"
    )

    if recent_scans:
        content += "\n\n[bold white]Recent Scans:[/bold white]"
        for sc in recent_scans[:5]:
            sid = sc.get("scan_id", sc.get("id", "?"))
            tgt = sc.get("target", "N/A")
            st = sc.get("status", "?")
            prog = sc.get("progress", 0)
            status_str = f"{st} ({prog}%)" if st == "running" else st
            content += f"\n  • [cyan]{sid}[/cyan]  {tgt}  [dim]{status_str}[/dim]"

    console.print(
        Panel(
            Text.from_markup(content),
            title="[bold cyan]Netrix Dashboard[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
