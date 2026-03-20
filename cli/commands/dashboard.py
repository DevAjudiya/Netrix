# ─────────────────────────────────────────
# Netrix — cli/commands/dashboard.py
# Purpose: Dashboard command — quick stats overview.
# ─────────────────────────────────────────

import httpx
import typer
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import get_api_url, is_logged_in
from cli.ui.banners import show_banner
from cli.ui.panels import show_connection_error, show_dashboard_panel, show_error
from cli.ui.progress import spinner

console = Console()


def cmd_dashboard() -> None:
    """
    Display a quick stats overview of your Netrix instance.

    Shows total scans, active scans, hosts discovered,
    vulnerability severity breakdown, and recent scan activity.

    Example:
        netrix dashboard
    """
    show_banner()

    from cli.config import is_token_valid, clear_token
    from cli.commands.auth import do_login_interactive, do_register_interactive

    if not is_token_valid():
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

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)

    try:
        with spinner("Loading dashboard..."):
            stats_resp = client.get_dashboard_stats()
            recent_resp = client.get_recent_scans(limit=5)

        if stats_resp.status_code == 401 or recent_resp.status_code == 401:
            show_error("Session expired. Run: netrix login")
            return

        if stats_resp.status_code != 200:
            show_error(f"Failed to load stats (HTTP {stats_resp.status_code})")
            return

        stats = stats_resp.json()
        recent_scans = []
        if recent_resp.status_code == 200:
            rdata = recent_resp.json()
            # Backend returns {"recent_scans": [...], "total": N}
            recent_scans = rdata if isinstance(rdata, list) else rdata.get("recent_scans", rdata.get("scans", []))

        # Try to fetch vulnerability chart data for breakdown
        vuln_chart = None
        try:
            chart_resp = client.get_vuln_chart()
            if chart_resp.status_code == 200:
                vuln_chart = chart_resp.json()
        except Exception:
            pass

        show_dashboard_panel(stats, recent_scans, vuln_chart)

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
