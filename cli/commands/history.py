# ─────────────────────────────────────────
# Netrix — cli/commands/history.py
# Purpose: Scan history — view, manage, and delete past scans.
# ─────────────────────────────────────────

from typing import Optional

import httpx
import typer
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import get_api_url, get_token, is_logged_in
from cli.ui.banners import show_banner
from cli.ui.panels import (
    show_connection_error,
    show_error,
    show_info,
    show_scan_complete_panel,
    show_success,
    show_warning,
)
from cli.ui.progress import spinner
from cli.ui.prompts import (
    prompt_confirm_delete,
    prompt_history_action,
    prompt_report_formats,
    prompt_select_scan,
)
from cli.ui.tables import hosts_table, ports_table, scans_table, vulns_table

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


def cmd_history(limit: int = 20) -> None:
    """
    View and manage past scans.

    Shows a paginated list of scans with options to view results,
    generate reports, or delete scans.

    Examples:
        netrix history
        netrix history --limit 50
    """
    show_banner()
    _require_login()

    api_url = get_api_url()
    token = get_token()
    client = NetrixAPIClient(base_url=api_url, token=token)

    try:
        with spinner("Loading scan history..."):
            resp = client.get_scans(page_size=limit)

        if resp.status_code != 200:
            show_error(f"Failed to load history (HTTP {resp.status_code})")
            return

        data = resp.json()
        scan_list = data.get("scans", [])
        total = data.get("total", len(scan_list))

        if not scan_list:
            show_info("No scans found. Start one with: netrix scan")
            return

        console.print()
        console.print(scans_table(scan_list))
        console.print(f"\n[dim]Showing {len(scan_list)} of {total} total scans[/dim]\n")

        # Interactive scan picker
        selected_id = prompt_select_scan(scan_list)
        if selected_id is None:
            return

        selected_scan = next((s for s in scan_list if s.get("id") == selected_id), {})
        scan_uid = selected_scan.get("scan_id", str(selected_id))

        # Action menu
        action = prompt_history_action()

        if action == "view":
            _view_scan_results(client, selected_id, scan_uid)

        elif action == "report":
            _generate_report_for_scan(client, selected_id, scan_uid, api_url)

        elif action == "delete":
            if prompt_confirm_delete(f"scan [bold]{scan_uid}[/bold]"):
                try:
                    with spinner(f"Deleting scan {scan_uid}..."):
                        del_resp = client.delete_scan(selected_id)
                    if del_resp.status_code in (200, 204):
                        show_success(f"Scan {scan_uid} deleted.")
                    elif del_resp.status_code == 400:
                        show_warning("Cannot delete a running scan. Stop it first.")
                    else:
                        show_error(f"Delete failed (HTTP {del_resp.status_code})")
                except httpx.ConnectError:
                    show_connection_error(api_url)
            else:
                console.print("[dim]Delete cancelled.[/dim]")

        elif action == "back":
            return

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")


def _view_scan_results(client: NetrixAPIClient, scan_id: int, scan_uid: str) -> None:
    """Fetch and display full scan results."""
    try:
        with spinner("Fetching results..."):
            resp = client.get_scan_results(scan_id)

        if resp.status_code == 200:
            results = resp.json()
            # Backend returns counts at top level, not under "summary"
            scan_info = results.get("scan", {})
            hosts = results.get("hosts", [])
            # Vulns are nested inside each host, not at top level
            vulns = []
            for host in hosts:
                vulns.extend(host.get("vulnerabilities", []))

            show_scan_complete_panel(
                scan_id=scan_uid,
                duration=scan_info.get("duration", 0),
                hosts_count=results.get("total_hosts", len(hosts)),
                vulns_count=results.get("total_vulnerabilities", len(vulns)),
                ports_count=results.get("total_ports", 0),
            )

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
        elif resp.status_code == 404:
            show_error(f"Scan results not found. The scan may have failed.")
        else:
            show_error(f"Failed to fetch results (HTTP {resp.status_code})")
    except httpx.ConnectError:
        show_connection_error(client.base_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")


def _generate_report_for_scan(
    client: NetrixAPIClient, scan_id: int, scan_uid: str, api_url: str
) -> None:
    """Generate one or more reports for the selected scan."""
    from pathlib import Path
    from cli.config import get_setting

    try:
        formats = prompt_report_formats()
        output_dir = Path(get_setting("output_dir") or "./reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        for fmt in formats:
            with spinner(f"Generating {fmt.upper()} report..."):
                gen_resp = client.generate_report(scan_id, fmt)

            if gen_resp.status_code in (200, 201):
                rdata = gen_resp.json()
                report_id = rdata.get("id")
                report_name = rdata.get("report_name", f"{scan_uid}_report.{fmt}")

                with spinner(f"Downloading {fmt.upper()} report..."):
                    dl_resp = client.download_report(report_id)

                if dl_resp.status_code == 200:
                    save_path = output_dir / report_name
                    with open(save_path, "wb") as fh:
                        fh.write(dl_resp.content)
                    size_kb = len(dl_resp.content) // 1024 or 1
                    show_success(f"Saved: {save_path.resolve()} ({size_kb} KB)")
                else:
                    show_warning(f"{fmt.upper()} download failed (HTTP {dl_resp.status_code})")
            else:
                show_warning(f"Failed to generate {fmt.upper()} report (HTTP {gen_resp.status_code})")
    except KeyboardInterrupt:
        console.print("\n[dim]Report generation cancelled.[/dim]")
    except httpx.ConnectError:
        show_connection_error(api_url)
