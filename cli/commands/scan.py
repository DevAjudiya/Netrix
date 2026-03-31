# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/commands/scan.py
# Purpose: Scan command — interactive wizard + direct mode.
# ─────────────────────────────────────────

import json
import sys
from pathlib import Path
from typing import List, Optional

import httpx
import typer
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import get_api_url, get_setting, get_token, is_logged_in
from cli.ui.banners import show_banner
from cli.ui.panels import (
    show_connection_error,
    show_error,
    show_info,
    show_scan_complete_panel,
    show_scan_config_panel,
    show_scan_starting_panel,
    show_warning,
)
from cli.ui.progress import scan_progress_bar, spinner
from cli.ui.prompts import (
    prompt_output_formats,
    prompt_post_scan,
    prompt_scan_confirm,
    prompt_scan_type,
    prompt_target,
)
from cli.ui.tables import hosts_table, ports_table, scans_table, vulns_table
from cli.utils.formatters import scan_estimated_time, scan_type_label
from cli.utils.validators import (
    ALLOWED_SCAN_TYPES,
    is_valid_scan_type,
    is_valid_target,
)

console = Console()

# Sub-app kept for backward compatibility (netrix scan run / list / etc.)
app = typer.Typer(
    name="scan",
    help="Network scanning — launch, monitor, and review scans.",
    rich_markup_mode="rich",
    hidden=True,
)


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def _require_login() -> None:
    """
    Ensure the user is authenticated with a non-expired token.
    If not, prompt for Login / Register / Cancel before continuing.
    """
    from cli.config import is_token_valid, clear_token
    from cli.commands.auth import do_login_interactive, do_register_interactive

    if is_token_valid():
        return  # All good — proceed

    # Token missing or expired
    if is_logged_in():
        # Token file exists but JWT is expired
        show_warning("Your session has expired. Please login again.")
        clear_token()
    else:
        show_warning("You are not logged in.")

    try:
        from InquirerPy import inquirer
        action = inquirer.select(
            message="What would you like to do?",
            choices=[
                {"name": "Login", "value": "login"},
                {"name": "Register a new account", "value": "register"},
                {"name": "Cancel", "value": "cancel"},
            ],
        ).execute()
    except KeyboardInterrupt:
        raise typer.Exit(0)

    if action == "login":
        do_login_interactive()
    elif action == "register":
        do_register_interactive()

    if not is_logged_in():
        raise typer.Exit(1)


def _handle_api_error(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        show_error("Session expired. Run: netrix login")
    elif resp.status_code == 404:
        show_error("Resource not found.")
    elif resp.status_code == 409:
        try:
            detail = resp.json().get("detail", {})
            msg = detail.get("message", "Conflict") if isinstance(detail, dict) else str(detail)
        except Exception:
            msg = "Conflict"
        show_warning(msg)
    elif resp.status_code == 422:
        try:
            detail = resp.json().get("detail", "Validation error")
        except Exception:
            detail = "Validation error"
        show_error(f"Validation error: {detail}")
    elif resp.status_code >= 500:
        show_error("Server error. Please try again later.")
    else:
        show_error(f"Request failed (HTTP {resp.status_code}): {resp.text[:200]}")


def _display_results(results: dict, console: Console) -> None:
    """Print hosts, ports, and vulns tables from results dict."""
    hosts = results.get("hosts", [])
    # Backend nests vulns inside each host — flatten them here
    vulns = []
    for host in hosts:
        vulns.extend(host.get("vulnerabilities", []))

    if hosts:
        console.print()
        console.print(hosts_table(hosts))
        if any(h.get("ports") for h in hosts):
            console.print()
            console.print(ports_table(hosts))
    else:
        show_info("No hosts discovered.")

    if vulns:
        console.print()
        console.print(vulns_table(vulns))
    else:
        show_info("No vulnerabilities found.")


def _generate_reports(client: NetrixAPIClient, scan_db_id: int, scan_uid: str, formats: List[str]) -> None:
    """Generate and download reports for the given scan."""
    output_dir = Path(get_setting("output_dir") or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        try:
            with spinner(f"Generating {fmt.upper()} report..."):
                gen_resp = client.generate_report(scan_db_id, fmt)

            if gen_resp.status_code in (200, 201):
                report_data = gen_resp.json()
                report_id = report_data.get("id")
                report_name = report_data.get("report_name", f"{scan_uid}_report.{fmt}")

                with spinner(f"Downloading {fmt.upper()} report..."):
                    dl_resp = client.download_report(report_id)

                if dl_resp.status_code == 200:
                    save_path = output_dir / report_name
                    with open(save_path, "wb") as fh:
                        fh.write(dl_resp.content)
                    from cli.ui.panels import show_success
                    show_success(
                        f"Report saved: {save_path.resolve()} "
                        f"({len(dl_resp.content) // 1024 or 1} KB)"
                    )
                else:
                    show_warning(f"{fmt.upper()} report generated but download failed.")
            else:
                show_warning(f"Failed to generate {fmt.upper()} report (HTTP {gen_resp.status_code})")
        except Exception as e:
            show_warning(f"Report generation error: {e}")


# ─────────────────────────────────────────
# Core scan execution
# ─────────────────────────────────────────

def _run_scan(
    target: str,
    scan_type: str,
    formats: Optional[List[str]] = None,
    output_file: Optional[str] = None,
) -> None:
    """Execute a scan and display results."""
    _require_login()

    api_url = get_api_url()
    token = get_token()
    client = NetrixAPIClient(base_url=api_url, token=token)

    show_scan_starting_panel(target, scan_type)

    try:
        resp = client.start_scan(target, scan_type)

        if resp.status_code not in (200, 201):
            _handle_api_error(resp)
            return

        scan_data = resp.json()
        scan_db_id = scan_data.get("id")
        scan_uid = scan_data.get("scan_id", "N/A")
        show_info(f"Scan queued — ID: [bold cyan]{scan_uid}[/bold cyan]")

        # Live progress — pass string scan_uid (NETRIX_XXX), not integer
        final = scan_progress_bar(
            scan_id=scan_uid,
            token=token,
            api_base=api_url,
            target=target,
            scan_type=scan_type,
        )

        if not final:
            show_warning("Could not track progress. Check: netrix history")
            return

        status = final.get("status")

        if status == "completed":
            # Fetch full results
            with spinner("Fetching results..."):
                results_resp = client.get_scan_results(scan_db_id)

            if results_resp.status_code == 200:
                results = results_resp.json()
                # Backend returns counts at top level, not under "summary"
                scan_info = results.get("scan", {})
                hosts_count = results.get("total_hosts", 0)
                vulns_count = results.get("total_vulnerabilities", 0)
                ports_count = results.get("total_ports", 0)

                # Severity breakdown from vuln stats
                severity_breakdown = None
                try:
                    stats_resp = client.get_vuln_stats(scan_db_id)
                    if stats_resp.status_code == 200:
                        sdata = stats_resp.json()
                        # Backend returns "severity_breakdown", not "by_severity"
                        severity_breakdown = sdata.get("severity_breakdown", {})
                except Exception:
                    pass

                show_scan_complete_panel(
                    scan_id=scan_uid,
                    duration=scan_info.get("duration", 0),
                    hosts_count=hosts_count,
                    vulns_count=vulns_count,
                    ports_count=ports_count,
                    severity_breakdown=severity_breakdown,
                )

                _display_results(results, console)

                # Save JSON output if requested
                if output_file:
                    out = Path(output_file)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with open(out, "w", encoding="utf-8") as fh:
                        json.dump(results, fh, indent=2, default=str)
                    from cli.ui.panels import show_success
                    show_success(f"Results saved: {out.resolve()}")

                # Generate reports if requested
                if formats:
                    _generate_reports(client, scan_db_id, scan_uid, formats)

                # Post-scan "What next?" menu
                try:
                    action = prompt_post_scan(scan_uid)
                    _handle_post_scan_action(action, client, scan_db_id, scan_uid)
                except KeyboardInterrupt:
                    pass

            else:
                show_warning("Scan completed but could not retrieve results.")

        elif status == "failed":
            show_error(f"Scan failed: {final.get('error_message', 'Unknown error')}")
        else:
            show_warning("Unexpected scan status. Check: netrix history")

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out. The backend may be overloaded.")
    except KeyboardInterrupt:
        show_warning("Scan interrupted. The scan may still be running on the backend.")


def _handle_post_scan_action(
    action: str, client: NetrixAPIClient, scan_db_id: int, scan_uid: str
) -> None:
    """Handle the post-scan 'What next?' menu selection."""
    if action == "results":
        try:
            with spinner("Fetching results..."):
                resp = client.get_scan_results(scan_db_id)
            if resp.status_code == 200:
                _display_results(resp.json(), console)
        except Exception as e:
            show_error(str(e))

    elif action == "vulns":
        try:
            with spinner("Fetching vulnerabilities..."):
                resp = client.get_vulnerabilities(scan_id=scan_db_id)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
                if vulns:
                    console.print(vulns_table(vulns))
                else:
                    show_info("No vulnerabilities found.")
        except Exception as e:
            show_error(str(e))

    elif action == "report":
        try:
            from cli.ui.prompts import prompt_report_formats
            formats = prompt_report_formats()
            if formats:
                _generate_reports(client, scan_db_id, scan_uid, formats)
        except KeyboardInterrupt:
            pass

    elif action == "scan":
        cmd_scan()

    elif action == "menu":
        pass  # Return to caller, main loop handles menu


# ─────────────────────────────────────────
# Main flat command: netrix scan
# ─────────────────────────────────────────

def cmd_scan(
    target: Optional[str] = None,
    scan_type: Optional[str] = None,
    output: Optional[str] = None,
    formats: Optional[str] = None,
) -> None:
    """
    Start a network scan.

    With no arguments: launches the interactive scan wizard.
    With arguments: direct mode for expert users.

    Examples:
        netrix scan
        netrix scan --target 192.168.1.0/24 --type full
        netrix scan -t example.com --type vuln --output pdf
    """
    show_banner()
    _require_login()

    # ── Direct mode ────────────────────────────────────────────────────
    if target:
        if not is_valid_target(target):
            show_error(
                f"Invalid target: '{target}'\n"
                "Formats: 192.168.1.1 | 192.168.1.0/24 | example.com"
            )
            raise typer.Exit(1)

        stype = (scan_type or get_setting("default_scan_type") or "quick").lower()
        if not is_valid_scan_type(stype):
            show_error(f"Invalid scan type: '{stype}'. Allowed: {', '.join(sorted(ALLOWED_SCAN_TYPES))}")
            raise typer.Exit(1)

        fmt_list: List[str] = []
        if formats:
            fmt_list = [f.strip().lower() for f in formats.split(",") if f.strip()]

        _run_scan(target, stype, fmt_list, output)
        return

    # ── Wizard mode ────────────────────────────────────────────────────
    try:
        console.print()
        console.rule("[bold cyan]Interactive Scan Wizard[/bold cyan]")
        console.print()

        # Step 1: Target
        tgt = prompt_target()

        # Step 2: Scan type
        stype = prompt_scan_type()

        # Step 3: Report formats
        fmt_list = prompt_output_formats()

        # Step 4: Confirmation
        show_scan_config_panel(
            target=tgt,
            scan_type=stype,
            formats=fmt_list,
            est_time=scan_estimated_time(stype),
        )

        action = prompt_scan_confirm(tgt, stype, fmt_list)

        if action == "cancel":
            console.print("[dim]Scan cancelled.[/dim]")
            return

        if action == "edit":
            # Re-run wizard
            cmd_scan()
            return

        # Step 5: Run
        _run_scan(tgt, stype, fmt_list, output)

    except KeyboardInterrupt:
        console.print("\n[dim]Scan wizard cancelled.[/dim]")


# ─────────────────────────────────────────
# Backward-compatible sub-commands
# ─────────────────────────────────────────

@app.command("run")
def run_scan(
    target: str = typer.Option(..., "--target", "-t", help="Target IP/CIDR/domain"),
    scan_type: str = typer.Option("quick", "--type", "-T", help="Scan type"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Custom ports"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON results"),
) -> None:
    """Launch a scan (use 'netrix scan' for the interactive wizard)."""
    cmd_scan(target=target, scan_type=scan_type, output=output)


@app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-l"),
    status_filter: Optional[str] = typer.Option(None, "--status", "-s"),
) -> None:
    """List all scans."""
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        with spinner("Fetching scans..."):
            resp = client.get_scans(page_size=limit, status=status_filter)
        if resp.status_code == 200:
            data = resp.json()
            scan_list = data.get("scans", [])
            total = data.get("total", len(scan_list))
            if not scan_list:
                show_info("No scans found.")
                return
            console.print(scans_table(scan_list))
            console.print(f"\n[dim]Showing {len(scan_list)} of {total} total scans[/dim]")
        else:
            _handle_api_error(resp)
    except httpx.ConnectError:
        show_connection_error(api_url)


@app.command("status")
def scan_status(
    scan_id: int = typer.Argument(..., help="Numeric scan ID"),
) -> None:
    """Check the live status of a running scan."""
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        resp = client.get_scan_status(scan_id)
        if resp.status_code == 200:
            data = resp.json()
            uid = data.get("scan_id", "N/A")
            status = data.get("status", "unknown")
            progress = data.get("progress", 0)

            from cli.ui.tables import status_badge
            from rich.progress import BarColumn, Progress, TextColumn

            console.print(f"\n  [bold]Scan ID:[/bold]  {uid}")
            console.print(f"  [bold]Status:[/bold]   {status_badge(status)}")

            p = Progress(
                TextColumn("  Progress:"),
                BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
                TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
            )
            p.add_task("", total=100, completed=progress)
            console.print(p)
            console.print()
        else:
            _handle_api_error(resp)
    except httpx.ConnectError:
        show_connection_error(api_url)


@app.command("results")
def scan_results(
    scan_id: int = typer.Argument(..., help="Numeric scan ID"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results JSON"),
) -> None:
    """Display the full results of a completed scan."""
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        with spinner("Fetching scan results..."):
            resp = client.get_scan_results(scan_id)

        if resp.status_code == 200:
            results = resp.json()
            summary = results.get("summary", {})
            scan_info = results.get("scan", {})

            show_scan_complete_panel(
                scan_id=scan_info.get("scan_id", str(scan_id)),
                duration=scan_info.get("duration", 0),
                hosts_count=summary.get("total_hosts", 0),
                vulns_count=summary.get("total_vulnerabilities", 0),
                ports_count=summary.get("total_open_ports", 0),
            )
            _display_results(results, console)

            if output:
                out = Path(output)
                out.parent.mkdir(parents=True, exist_ok=True)
                with open(out, "w", encoding="utf-8") as fh:
                    json.dump(results, fh, indent=2, default=str)
                from cli.ui.panels import show_success
                show_success(f"Results saved: {out.resolve()}")
        else:
            _handle_api_error(resp)
    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
