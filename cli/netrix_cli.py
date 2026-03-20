# ─────────────────────────────────────────
# Netrix — cli/netrix_cli.py
# Purpose: Main CLI entry point.
#          No args → interactive main menu.
#          With command → direct execution.
# ─────────────────────────────────────────

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Optional

import httpx
import typer
from rich.console import Console

from cli.ui.banners import show_banner

console = Console()

# ─────────────────────────────────────────
# Typer app — NO no_args_is_help so we can show the interactive menu
# ─────────────────────────────────────────
app = typer.Typer(
    name="netrix",
    help="Netrix — Network Scanning & Vulnerability Assessment Platform",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=False,   # We handle no-args ourselves (interactive menu)
)

# ─────────────────────────────────────────
# Register legacy sub-apps (backward compat)
# ─────────────────────────────────────────
from cli.commands import auth, scan, report

app.add_typer(auth.app,   name="auth",   help="[dim](legacy) netrix auth login|logout|whoami[/dim]")
app.add_typer(scan.app,   name="scan-sub",   help="[dim](legacy) netrix scan run|list|status|results[/dim]", hidden=True)
app.add_typer(report.app, name="report-sub", help="[dim](legacy) netrix report generate|list[/dim]", hidden=True)


# ─────────────────────────────────────────
# Root callback — interactive menu when no command given
# ─────────────────────────────────────────
@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """
    Netrix CLI — Network Scanning & Vulnerability Assessment Platform.

    Run without any command to open the interactive main menu.
    Run 'netrix <command> --help' for detailed usage of each command.
    """
    if ctx.invoked_subcommand is not None:
        return  # A command was given — let it run normally

    # No command → show interactive menu
    show_banner()

    try:
        from cli.ui.prompts import main_menu
        from cli.config import is_logged_in
        from cli.commands.auth import do_login_interactive, do_register_interactive

        while True:
            choice = main_menu(logged_in=is_logged_in())

            if choice == "login":
                do_login_interactive()

            elif choice == "register":
                do_register_interactive()

            elif choice == "logout":
                from cli.commands.auth import cmd_logout
                cmd_logout()

            elif choice == "whoami":
                from cli.commands.auth import cmd_whoami
                cmd_whoami()

            elif choice == "scan":
                from cli.commands.scan import cmd_scan
                cmd_scan()

            elif choice == "dashboard":
                from cli.commands.dashboard import cmd_dashboard
                cmd_dashboard()

            elif choice == "vulns":
                from cli.commands.vulns import cmd_vulns
                cmd_vulns()

            elif choice == "report":
                from cli.commands.report import cmd_report
                cmd_report()

            elif choice == "history":
                from cli.commands.history import cmd_history
                cmd_history()

            elif choice == "config":
                from cli.commands.config_cmd import cmd_config
                cmd_config()

            elif choice == "exit":
                console.print("\n[bold cyan]Goodbye! Stay secure.[/bold cyan]\n")
                raise typer.Exit(0)

            # After each action, loop back to show the menu again
            console.print()

    except KeyboardInterrupt:
        console.print("\n[bold cyan]\nGoodbye! Stay secure.[/bold cyan]\n")
        raise typer.Exit(0)


# ─────────────────────────────────────────
# Flat commands — PRIMARY INTERFACE
# ─────────────────────────────────────────

@app.command("scan")
def scan_cmd(
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Target IP, CIDR range, or domain (e.g. 192.168.1.0/24)",
    ),
    scan_type: Optional[str] = typer.Option(
        None, "--type", "-T",
        help="Scan type: quick | stealth | full | aggressive | vulnerability",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Save JSON results to this file path.",
    ),
    formats: Optional[str] = typer.Option(
        None, "--format", "-f",
        help="Auto-generate report (comma-separated): pdf,json,csv,html",
    ),
) -> None:
    """
    Start a network scan.

    Without arguments: launches the interactive scan wizard.
    With --target: direct mode (expert users).

    \b
    Examples:
      netrix scan                                    # interactive wizard
      netrix scan -t 192.168.1.0/24 --type full      # direct mode
      netrix scan -t example.com --type vuln -f pdf  # with report
    """
    from cli.commands.scan import cmd_scan
    cmd_scan(target=target, scan_type=scan_type, output=output, formats=formats)


@app.command("dashboard")
def dashboard_cmd() -> None:
    """
    Display a quick overview of scan stats and recent activity.

    \b
    Example:
      netrix dashboard
    """
    from cli.commands.dashboard import cmd_dashboard
    cmd_dashboard()


@app.command("vulns")
def vulns_cmd(
    scan_id: Optional[int] = typer.Option(
        None, "--scan", "-s",
        help="Filter by numeric scan ID.",
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity",
        help="Filter: all | critical | high | medium | low",
    ),
) -> None:
    """
    Browse vulnerabilities with interactive filtering and CVE details.

    Without arguments: interactive wizard to select scan and severity.

    \b
    Examples:
      netrix vulns                          # interactive
      netrix vulns --scan 1 --severity high # direct
    """
    from cli.commands.vulns import cmd_vulns
    cmd_vulns(scan_id=scan_id, severity=severity)


@app.command("report")
def report_cmd(
    scan_id: Optional[int] = typer.Option(
        None, "--scan", "-s",
        help="Numeric scan ID to generate a report for.",
    ),
    fmt: Optional[str] = typer.Option(
        None, "--format", "-f",
        help="Report format: pdf | json | csv | html",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output directory to save the report.",
    ),
) -> None:
    """
    Generate a report for a completed scan.

    Without arguments: interactive wizard to select scan and format.

    \b
    Examples:
      netrix report                           # interactive
      netrix report --scan 1 --format pdf     # direct
      netrix report -s 1 -f html -o ./out/   # with output dir
    """
    from cli.commands.report import cmd_report
    cmd_report(scan_id=scan_id, fmt=fmt, output=output)


@app.command("history")
def history_cmd(
    limit: int = typer.Option(
        20, "--limit", "-l",
        help="Number of scans to display.",
    ),
) -> None:
    """
    View past scans with options to view results, generate reports, or delete.

    \b
    Examples:
      netrix history
      netrix history --limit 50
    """
    from cli.commands.history import cmd_history
    cmd_history(limit=limit)


@app.command("login")
def login_cmd(
    username: Optional[str] = typer.Option(
        None, "--username", "-u",
        help="Username (omit for interactive prompt).",
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password (omit for secure prompt).",
        hide_input=True,
    ),
) -> None:
    """
    Authenticate with the Netrix backend.

    Without arguments: interactive prompts for credentials.

    \b
    Examples:
      netrix login                  # interactive
      netrix login -u admin         # prompts for password only
    """
    from cli.commands.auth import cmd_login
    cmd_login(username=username, password=password)


@app.command("register")
def register_cmd() -> None:
    """
    Create a new Netrix account (interactive).

    \b
    Example:
      netrix register
    """
    from cli.commands.auth import cmd_register
    cmd_register()


@app.command("logout")
def logout_cmd() -> None:
    """
    Log out and remove the saved authentication token.

    \b
    Example:
      netrix logout
    """
    from cli.commands.auth import cmd_logout
    cmd_logout()


@app.command("whoami")
def whoami_cmd() -> None:
    """
    Display the currently authenticated user's profile.

    \b
    Example:
      netrix whoami
    """
    from cli.commands.auth import cmd_whoami
    cmd_whoami()


@app.command("config")
def config_cmd(
    list_all: bool = typer.Option(
        False, "--list", "-l",
        help="Show all current settings.",
    ),
    set_kv: Optional[str] = typer.Option(
        None, "--set",
        help="Set a value: KEY=VALUE (e.g. api_url=http://localhost:8000/api/v1)",
    ),
    reset: bool = typer.Option(
        False, "--reset",
        help="Reset all settings to defaults.",
    ),
) -> None:
    """
    View and manage Netrix CLI settings.

    Without arguments: interactive settings menu.

    \b
    Examples:
      netrix config --list
      netrix config --set api_url=http://192.168.1.100:8000/api/v1
      netrix config --set default_scan_type=quick
      netrix config --reset
    """
    from cli.commands.config_cmd import cmd_config
    cmd_config(list_all=list_all, set_kv=set_kv, reset=reset)


@app.command("version")
def version_cmd() -> None:
    """Display the Netrix CLI version."""
    show_banner()
    console.print("[bold white]Netrix CLI[/bold white] v[bold cyan]1.0.0[/bold cyan]")


@app.command("status")
def status_cmd() -> None:
    """Check connectivity to the Netrix backend API."""
    from cli.config import get_api_url

    show_banner()
    api_url = get_api_url()
    base_url = api_url.replace("/api/v1", "")

    try:
        resp = httpx.get(f"{base_url}/health", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            console.print(
                f"[bold green]✅ Backend is running[/bold green] — "
                f"{data.get('app', 'Netrix')} v{data.get('version', '?')}"
            )
            console.print(f"[dim]  API URL: {api_url}[/dim]")
        else:
            console.print(f"[bold red]❌ Backend returned HTTP {resp.status_code}[/bold red]")
    except httpx.ConnectError:
        from cli.ui.panels import show_connection_error
        show_connection_error(api_url)


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────
if __name__ == "__main__":
    app()
