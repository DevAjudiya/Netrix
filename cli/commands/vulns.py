# ─────────────────────────────────────────
# Netrix — cli/commands/vulns.py
# Purpose: Vulnerability browser — list, filter, and view CVE details.
# ─────────────────────────────────────────

from typing import Optional

import httpx
import typer
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import get_api_url, is_logged_in
from cli.ui.banners import show_banner
from cli.ui.panels import show_connection_error, show_error, show_info, show_cve_detail_panel
from cli.ui.progress import spinner
from cli.ui.prompts import prompt_select_scan, prompt_select_vuln, prompt_severity_filter
from cli.ui.tables import vulns_table

console = Console()


def _require_login() -> None:
    from cli.config import is_token_valid, clear_token
    from cli.commands.auth import do_login_interactive, do_register_interactive

    if is_token_valid():
        return

    if is_logged_in():
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


def cmd_vulns(
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,
) -> None:
    """
    Browse vulnerabilities interactively.

    With no arguments: pick scan and severity filter interactively.
    With arguments: direct mode.

    Examples:
        netrix vulns
        netrix vulns --scan 1 --severity critical
    """
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)

    # ── Determine scan ID ──────────────────────────────────────────────
    selected_scan_id = scan_id
    if not selected_scan_id:
        try:
            with spinner("Loading scans..."):
                scans_resp = client.get_scans(page_size=50)

            if scans_resp.status_code != 200:
                show_error(f"Failed to load scans (HTTP {scans_resp.status_code})")
                return

            all_scans = scans_resp.json().get("scans", [])
            completed = [s for s in all_scans if s.get("status") == "completed"]

            if not completed:
                show_info("No completed scans found. Run a scan first: netrix scan")
                return

            selected_scan_id = prompt_select_scan(completed)
            if selected_scan_id is None:
                console.print("[dim]Cancelled.[/dim]")
                return
        except KeyboardInterrupt:
            console.print("\n[dim]Cancelled.[/dim]")
            return
        except httpx.ConnectError:
            show_connection_error(api_url)
            return

    # ── Determine severity filter ──────────────────────────────────────
    selected_severity = severity
    if not selected_severity:
        try:
            selected_severity = prompt_severity_filter()
        except KeyboardInterrupt:
            console.print("\n[dim]Cancelled.[/dim]")
            return

    # ── Fetch vulnerabilities ──────────────────────────────────────────
    try:
        with spinner("Fetching vulnerabilities..."):
            resp = client.get_vulnerabilities(
                scan_id=selected_scan_id,
                severity=selected_severity if selected_severity != "all" else None,
                page_size=100,
            )

        if resp.status_code != 200:
            show_error(f"Failed to fetch vulnerabilities (HTTP {resp.status_code})")
            return

        data = resp.json()
        # API may return list or paginated dict
        if isinstance(data, list):
            vulns = data
        else:
            vulns = data.get("vulnerabilities", data.get("items", []))

        if not vulns:
            show_info("No vulnerabilities found with the selected filter.")
            return

        # ── Display table ──────────────────────────────────────────────
        console.print()
        console.print(vulns_table(vulns))

        # ── Interactive CVE detail browser ─────────────────────────────
        while True:
            try:
                cve_id = prompt_select_vuln(vulns)
                if cve_id is None:
                    break

                with spinner(f"Fetching {cve_id} details..."):
                    cve_resp = client.get_cve_detail(cve_id)

                if cve_resp.status_code == 200:
                    # Backend wraps detail under "data" key: {"cve_id":..., "found":..., "data":{...}}
                    cve_data = cve_resp.json()
                    show_cve_detail_panel(cve_data.get("data") or cve_data)
                elif cve_resp.status_code == 404:
                    # Try to get info from the vuln itself
                    vuln_data = next((v for v in vulns if v.get("cve_id") == cve_id), {})
                    show_cve_detail_panel(vuln_data)
                else:
                    show_error(f"Could not fetch CVE details (HTTP {cve_resp.status_code})")

            except KeyboardInterrupt:
                break

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")
