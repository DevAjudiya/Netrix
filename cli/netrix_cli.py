# ─────────────────────────────────────────
# Netrix — cli/netrix_cli.py
# Purpose: Main CLI entry point — registers all sub-apps
#          and displays the startup banner.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import httpx
import typer
from rich.console import Console

from cli.commands import auth, report, scan
from cli.utils.display import show_banner

console = Console()

app = typer.Typer(
    name="netrix",
    help="Netrix — Advanced Network Scanning & Vulnerability Assessment Tool",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# ─────────────────────────────────────────
# Register sub-command groups
# ─────────────────────────────────────────
app.add_typer(auth.app,   name="auth",   help="Login, logout, and session management")
app.add_typer(scan.app,   name="scan",   help="Network scanning commands")
app.add_typer(report.app, name="report", help="Report generation and management")


# ─────────────────────────────────────────
# Root callback — show banner
# ─────────────────────────────────────────
@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
) -> None:
    """
    Netrix CLI — Network Scanning & Vulnerability Assessment Platform.

    Use 'netrix <command> --help' for detailed usage.
    """
    if ctx.invoked_subcommand is None:
        show_banner()


# ─────────────────────────────────────────
# Top-level convenience commands
# ─────────────────────────────────────────
@app.command()
def version() -> None:
    """Display the Netrix CLI version."""
    show_banner()
    console.print("[bold white]Netrix CLI[/bold white] v[bold cyan]1.0.0[/bold cyan]")


@app.command()
def status() -> None:
    """Check the status of the Netrix backend API."""
    show_banner()
    try:
        response = httpx.get("http://127.0.0.1:8000/health", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            console.print(
                f"[bold green]✅ Backend is running[/bold green] — "
                f"{data.get('app', 'Netrix')} v{data.get('version', '?')}"
            )
        else:
            console.print(
                f"[bold red]❌ Backend returned HTTP {response.status_code}[/bold red]"
            )
    except httpx.ConnectError:
        console.print(
            "[bold red]❌ Cannot connect to the Netrix backend "
            "at http://127.0.0.1:8000[/bold red]\n"
            "[dim]Make sure the backend server is running.[/dim]"
        )


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────
if __name__ == "__main__":
    app()
