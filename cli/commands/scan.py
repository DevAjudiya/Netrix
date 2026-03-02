# ─────────────────────────────────────────
# Netrix — cli/commands/scan.py
# Purpose: CLI commands for launching scans, listing scans,
#          checking status, and viewing results.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from cli.config import API_BASE_URL, get_headers, get_token, is_logged_in
from cli.utils.display import (
    create_hosts_table,
    create_ports_table,
    create_scans_table,
    create_vulns_table,
    show_banner,
    show_error,
    show_info,
    show_scan_complete_panel,
    show_scan_starting_panel,
    show_status_badge,
    show_success,
    show_warning,
)
from cli.utils.progress import scan_progress_bar, spinner

app = typer.Typer(
    name="scan",
    help="Network scanning — launch, monitor, and review scans.",
    rich_markup_mode="rich",
)
console = Console()


# ─────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
_CIDR_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"
)
_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

ALLOWED_SCAN_TYPES = {"quick", "stealth", "full", "aggressive", "vulnerability"}


def _validate_target(target: str) -> bool:
    """Return True if *target* looks like a valid IP, CIDR, or domain."""
    target = target.strip()
    return bool(
        _IP_RE.match(target)
        or _CIDR_RE.match(target)
        or _DOMAIN_RE.match(target)
    )


def _require_login() -> None:
    """Exit with a helpful message if the user is not logged in."""
    if not is_logged_in():
        show_error("You are not logged in. Run: netrix auth login")
        raise typer.Exit(1)


def _handle_api_error(resp: httpx.Response) -> None:
    """Display a formatted error for common HTTP status codes."""
    if resp.status_code == 401:
        show_error("Session expired. Please run: netrix auth login")
    elif resp.status_code == 404:
        show_error("Resource not found.")
    elif resp.status_code == 409:
        detail = resp.json().get("detail", {})
        msg = detail.get("message", "Conflict") if isinstance(detail, dict) else str(detail)
        show_warning(msg)
    elif resp.status_code == 422:
        detail = resp.json().get("detail", "Validation error")
        show_error(f"Validation error: {detail}")
    elif resp.status_code >= 500:
        show_error("Server error. Please try again later.")
    else:
        show_error(f"Request failed (HTTP {resp.status_code}): {resp.text[:200]}")


# ─────────────────────────────────────────
# netrix scan run
# ─────────────────────────────────────────
@app.command("run")
def run_scan(
    target: str = typer.Option(
        ..., "--target", "-t",
        help="Target IP address, CIDR range, or domain name.",
    ),
    scan_type: str = typer.Option(
        "quick", "--type", "-T",
        help="Scan type: quick | stealth | full | aggressive | vulnerability",
    ),
    ports: Optional[str] = typer.Option(
        None, "--ports", "-p",
        help="Custom port range (e.g. '80,443,8080-8090').",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Save results JSON to this file path.",
    ),
) -> None:
    """
    Launch a new network scan against a target.

    Examples:
        netrix scan run --target 192.168.1.1 --type full
        netrix scan run --target 192.168.1.0/24 --type quick
        netrix scan run --target example.com --type vulnerability
    """
    show_banner()
    _require_login()

    # ── Validate inputs ──────────────────────────────────────────
    if not _validate_target(target):
        show_error(
            f"Invalid target format: '{target}'\n"
            "  Supported formats: IP (192.168.1.1), "
            "CIDR (192.168.1.0/24), Domain (example.com)"
        )
        raise typer.Exit(1)

    if scan_type not in ALLOWED_SCAN_TYPES:
        show_error(
            f"Invalid scan type: '{scan_type}'\n"
            f"  Allowed: {', '.join(sorted(ALLOWED_SCAN_TYPES))}"
        )
        raise typer.Exit(1)

    # ── Start scan ───────────────────────────────────────────────
    show_scan_starting_panel(target, scan_type)

    try:
        headers = get_headers()
        payload = {
            "target": target,
            "scan_type": scan_type,
        }
        if ports:
            payload["custom_ports"] = ports

        resp = httpx.post(
            f"{API_BASE_URL}/scans/",
            json=payload,
            headers=headers,
            timeout=30.0,
        )

        if resp.status_code in (200, 201):
            scan_data = resp.json()
            scan_id = scan_data.get("id")
            scan_uid = scan_data.get("scan_id", "N/A")
            show_info(f"Scan created — ID: {scan_uid}")

            # ── Poll progress ────────────────────────────────────
            token = get_token()
            final = scan_progress_bar(
                scan_id=scan_id,
                token=token,
                api_base=API_BASE_URL,
                target=target,
            )

            if final and final.get("status") == "completed":
                # Fetch full results
                results_resp = httpx.get(
                    f"{API_BASE_URL}/scans/{scan_id}/results",
                    headers=headers,
                    timeout=30.0,
                )
                if results_resp.status_code == 200:
                    results = results_resp.json()
                    hosts = results.get("hosts", [])
                    vulns = results.get("vulnerabilities", [])
                    summary = results.get("summary", {})
                    scan_info = results.get("scan", {})

                    show_scan_complete_panel(
                        scan_id=scan_uid,
                        duration=scan_info.get("duration", 0),
                        hosts_count=summary.get("total_hosts", len(hosts)),
                        vulns_count=summary.get("total_vulnerabilities", len(vulns)),
                        ports_count=summary.get("total_open_ports", 0),
                    )

                    if hosts:
                        console.print(create_hosts_table(hosts))
                        # Show ports table if any host has port data
                        has_ports = any(h.get("ports") for h in hosts)
                        if has_ports:
                            console.print(create_ports_table(hosts))
                    if vulns:
                        console.print(create_vulns_table(vulns))
                    if not hosts and not vulns:
                        show_info("No hosts or vulnerabilities discovered.")

                    # Save to file if requested
                    if output:
                        out_path = Path(output)
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_path, "w", encoding="utf-8") as fh:
                            json.dump(results, fh, indent=2, default=str)
                        show_success(f"Results saved to: {out_path.resolve()}")
                else:
                    show_warning("Scan completed but could not retrieve results.")

            elif final and final.get("status") == "failed":
                show_error(
                    f"Scan failed: {final.get('error_message', 'Unknown error')}"
                )
            else:
                show_warning("Could not track scan progress. "
                             "Check status with: netrix scan status <scan_id>")

        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out. The backend may be overloaded.")
    except SystemExit:
        raise


# ─────────────────────────────────────────
# netrix scan list
# ─────────────────────────────────────────
@app.command("list")
def list_scans(
    limit: int = typer.Option(
        20, "--limit", "-l",
        help="Maximum number of scans to display.",
    ),
    status_filter: Optional[str] = typer.Option(
        None, "--status", "-s",
        help="Filter by status: pending | running | completed | failed",
    ),
) -> None:
    """
    List all scans with status and summary information.
    """
    show_banner()
    _require_login()

    try:
        headers = get_headers()
        params = {"page_size": limit}
        if status_filter:
            params["status"] = status_filter

        resp = httpx.get(
            f"{API_BASE_URL}/scans/",
            headers=headers,
            params=params,
            timeout=15.0,
        )

        if resp.status_code == 200:
            data = resp.json()
            scans = data.get("scans", [])
            total = data.get("total", len(scans))

            if not scans:
                show_info("No scans found.")
                return

            console.print(create_scans_table(scans))
            console.print(
                f"\n[dim]Showing {len(scans)} of {total} total scans[/dim]"
            )
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except SystemExit:
        raise


# ─────────────────────────────────────────
# netrix scan status
# ─────────────────────────────────────────
@app.command("status")
def scan_status(
    scan_id: int = typer.Argument(
        ..., help="Numeric scan ID to check.",
    ),
) -> None:
    """
    Check the live progress of a running scan.
    """
    show_banner()
    _require_login()

    try:
        headers = get_headers()
        resp = httpx.get(
            f"{API_BASE_URL}/scans/{scan_id}/status",
            headers=headers,
            timeout=10.0,
        )

        if resp.status_code == 200:
            data = resp.json()
            uid = data.get("scan_id", "N/A")
            status = data.get("status", "unknown")
            progress = data.get("progress", 0)

            from rich.progress import BarColumn, Progress, TextColumn

            console.print(f"\n  [bold]Scan ID:[/bold]  {uid}")
            console.print(f"  [bold]Status:[/bold]   {show_status_badge(status)}")

            p = Progress(
                TextColumn("  Progress:"),
                BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
                TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
            )
            tid = p.add_task("", total=100, completed=progress)
            console.print(p)
            console.print()
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except SystemExit:
        raise


# ─────────────────────────────────────────
# netrix scan results
# ─────────────────────────────────────────
@app.command("results")
def scan_results(
    scan_id: int = typer.Argument(
        ..., help="Numeric scan ID to retrieve results for.",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Save results JSON to this file path.",
    ),
) -> None:
    """
    Display the full results of a completed scan.

    Shows discovered hosts, open ports, and vulnerabilities
    in detailed Rich tables.
    """
    show_banner()
    _require_login()

    try:
        headers = get_headers()

        with spinner("Fetching scan results..."):
            resp = httpx.get(
                f"{API_BASE_URL}/scans/{scan_id}/results",
                headers=headers,
                timeout=30.0,
            )

        if resp.status_code == 200:
            results = resp.json()
            hosts = results.get("hosts", [])
            vulns = results.get("vulnerabilities", [])
            summary = results.get("summary", {})
            scan_info = results.get("scan", {})

            show_scan_complete_panel(
                scan_id=scan_info.get("scan_id", str(scan_id)),
                duration=scan_info.get("duration", 0),
                hosts_count=summary.get("total_hosts", len(hosts)),
                vulns_count=summary.get("total_vulnerabilities", len(vulns)),
                ports_count=summary.get("total_open_ports", 0),
            )

            if hosts:
                console.print(create_hosts_table(hosts))
                has_ports = any(h.get("ports") for h in hosts)
                if has_ports:
                    console.print(create_ports_table(hosts))
            else:
                show_info("No hosts discovered.")

            if vulns:
                console.print(create_vulns_table(vulns))
            else:
                show_info("No vulnerabilities found.")

            # Save to file
            if output:
                out_path = Path(output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as fh:
                    json.dump(results, fh, indent=2, default=str)
                show_success(f"Results saved to: {out_path.resolve()}")

        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except SystemExit:
        raise
