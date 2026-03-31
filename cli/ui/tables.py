# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/ui/tables.py
# Purpose: Rich table builders for hosts, ports, vulns, scans, reports.
# ─────────────────────────────────────────

from typing import Dict, List

from rich.table import Table


# ── Color helpers ────────────────────────────────────────────────────


def severity_badge(severity: str) -> str:
    """Color-coded severity badge markup."""
    s = (severity or "").lower()
    return {
        "critical": "[bold red]🔴 CRITICAL[/bold red]",
        "high":     "[dark_orange]🟠 HIGH[/dark_orange]",
        "medium":   "[yellow]🟡 MEDIUM[/yellow]",
        "low":      "[blue]🔵 LOW[/blue]",
        "info":     "[green]🟢 INFO[/green]",
    }.get(s, f"[white]{severity}[/white]")


def severity_badge_short(severity: str) -> str:
    """Short color-coded severity badge markup."""
    s = (severity or "").lower()
    return {
        "critical": "[bold red]🔴 CRIT[/bold red]",
        "high":     "[dark_orange]🟠 HIGH[/dark_orange]",
        "medium":   "[yellow]🟡 MED[/yellow]",
        "low":      "[blue]🔵 LOW[/blue]",
        "info":     "[green]🟢 INFO[/green]",
    }.get(s, f"[white]{severity}[/white]")


def risk_score_badge(score: int) -> str:
    """Color-coded risk score badge."""
    score = int(score or 0)
    if score <= 30:
        return f"[green]🟢 {score}[/green]"
    if score <= 60:
        return f"[yellow]🟡 {score}[/yellow]"
    if score <= 80:
        return f"[dark_orange]🟠 {score}[/dark_orange]"
    return f"[bold red]🔴 {score}[/bold red]"


def status_badge(status: str) -> str:
    """Color-coded scan status badge."""
    s = (status or "").lower()
    return {
        "pending":   "[yellow]⏳ Pending[/yellow]",
        "running":   "[cyan]🔄 Running[/cyan]",
        "completed": "[green]✅ Done[/green]",
        "failed":    "[red]❌ Failed[/red]",
    }.get(s, f"[white]{status}[/white]")


# ── Table builders ───────────────────────────────────────────────────


def hosts_table(hosts: List[Dict]) -> Table:
    """Rich table for discovered hosts."""
    table = Table(
        title="🖥️   Discovered Hosts",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#",           style="dim",        justify="right", min_width=3)
    table.add_column("IP Address",  style="bold white",                  min_width=15)
    table.add_column("Hostname",    style="white")
    table.add_column("OS",          style="yellow")
    table.add_column("Ports",       justify="center",   style="white",   min_width=5)
    table.add_column("Risk Score",                                        min_width=10)

    for i, host in enumerate(hosts, 1):
        risk = host.get("risk_score") or 0
        port_count = len(host.get("ports", []))
        table.add_row(
            str(i),
            host.get("ip_address", "N/A"),
            host.get("hostname") or "—",
            host.get("os_name") or "—",
            str(port_count),
            risk_score_badge(risk),
        )
    return table


def ports_table(hosts: List[Dict]) -> Table:
    """Rich table for open ports across all hosts."""
    table = Table(
        title="🔌  Open Ports",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Host",            style="bold white",  min_width=15)
    table.add_column("Port",            justify="right",     style="bold white",  min_width=6)
    table.add_column("Proto",           style="dim",         min_width=5)
    table.add_column("State",           style="green",       min_width=6)
    table.add_column("Service",         style="yellow",      min_width=8)
    table.add_column("Product / Version", style="white",     min_width=20)
    table.add_column("Critical",        justify="center",    min_width=8)

    for host in hosts:
        ip = host.get("ip_address", "N/A")
        ports = host.get("ports", [])
        if not ports:
            continue
        for i, port in enumerate(ports):
            is_crit = port.get("is_critical_port", False)
            product = port.get("product", "") or ""
            version = port.get("version", "") or ""
            prod_ver = f"{product} {version}".strip() or "—"
            crit_badge = "[bold red]⚠ YES[/bold red]" if is_crit else "[dim]—[/dim]"
            table.add_row(
                ip if i == 0 else "",
                str(port.get("port_number", "—")),
                port.get("protocol", "tcp"),
                port.get("state", "—"),
                port.get("service_name") or "—",
                prod_ver,
                crit_badge,
            )
    return table


def vulns_table(vulns: List[Dict]) -> Table:
    """Rich table for vulnerabilities."""
    table = Table(
        title=f"🛡️   Vulnerabilities ({len(vulns)} found)",
        title_style="bold red",
        border_style="red",
        show_lines=True,
    )
    table.add_column("CVE ID",    style="bold white",  min_width=18)
    table.add_column("CVSS",      justify="center",    style="white",   min_width=6)
    table.add_column("Severity",                                         min_width=14)
    table.add_column("Host",      style="white",       min_width=15)
    table.add_column("Port",      style="dim",         min_width=6)
    table.add_column("Title",     style="white",       max_width=35)

    for vuln in vulns:
        table.add_row(
            vuln.get("cve_id") or "N/A",
            str(vuln.get("cvss_score") or "—"),
            severity_badge_short(vuln.get("severity", "")),
            vuln.get("host_ip") or vuln.get("ip_address") or "—",
            str(vuln.get("port_number") or vuln.get("port") or "—"),
            vuln.get("title") or "—",
        )
    return table


def scans_table(scans: List[Dict]) -> Table:
    """Rich table for scan history."""
    table = Table(
        title="📋  Scan History",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#",        style="dim",       justify="right",  min_width=3)
    table.add_column("Scan ID",  style="bold white",                  min_width=18)
    table.add_column("Target",   style="white")
    table.add_column("Type",     style="yellow",    min_width=12)
    table.add_column("Status",                      min_width=12)
    table.add_column("Hosts",    justify="center",  style="white",    min_width=5)
    table.add_column("Date",     style="dim")

    for scan in scans:
        created = scan.get("created_at", "")
        if isinstance(created, str) and "T" in created:
            created = created.split("T")[0]
        table.add_row(
            str(scan.get("id", "")),
            scan.get("scan_id", "N/A"),
            scan.get("target", "N/A"),
            scan.get("scan_type", "N/A"),
            status_badge(scan.get("status", "")),
            str(scan.get("total_hosts") or 0),
            str(created),
        )
    return table


def reports_table(reports: List[Dict]) -> Table:
    """Rich table for reports list."""
    table = Table(
        title="📄  Reports",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#",           style="dim",       justify="right",  min_width=3)
    table.add_column("Report Name", style="bold white",                  min_width=22)
    table.add_column("Format",      style="yellow",    justify="center",  min_width=6)
    table.add_column("Size",        style="white",     justify="right",   min_width=8)
    table.add_column("Hosts",       justify="center",  min_width=5)
    table.add_column("Vulns",       justify="center",  min_width=5)
    table.add_column("Generated",   style="dim")

    for report in reports:
        generated = report.get("generated_at", "")
        if isinstance(generated, str) and "T" in generated:
            generated = generated.split("T")[0]

        size_bytes = report.get("file_size", 0) or 0
        if size_bytes < 1024:
            size_str = f"{size_bytes} B"
        elif size_bytes < 1048576:
            size_str = f"{size_bytes/1024:.1f} KB"
        else:
            size_str = f"{size_bytes/1048576:.1f} MB"

        table.add_row(
            str(report.get("id", "")),
            report.get("report_name", "N/A"),
            (report.get("format") or "N/A").upper(),
            report.get("file_size_readable") or size_str,
            str(report.get("total_hosts") or 0),
            str(report.get("total_vulnerabilities") or 0),
            str(generated),
        )
    return table


def config_table(config: Dict) -> Table:
    """Rich table for configuration settings."""
    table = Table(
        title="⚙️   Configuration",
        title_style="bold cyan",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Key",   style="bold white", min_width=20)
    table.add_column("Value", style="cyan")

    for key, value in config.items():
        table.add_row(key, str(value))
    return table
