# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/commands/report.py
# Purpose: Report command — generate, list, download.
# ─────────────────────────────────────────

from pathlib import Path
from typing import List, Optional

import httpx
import typer
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import get_api_url, get_setting, is_logged_in
from cli.ui.banners import show_banner
from cli.ui.panels import (
    show_connection_error,
    show_error,
    show_info,
    show_success,
    show_warning,
)
from cli.ui.progress import spinner
from cli.ui.prompts import prompt_report_formats, prompt_select_scan
from cli.ui.tables import reports_table
from cli.utils.validators import ALLOWED_FORMATS, is_valid_format

console = Console()

app = typer.Typer(
    name="report",
    help="Report generation — create, list, and download reports.",
    rich_markup_mode="rich",
    hidden=True,
)


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

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


def _handle_api_error(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        show_error("Session expired. Run: netrix login")
    elif resp.status_code == 404:
        show_error("Resource not found.")
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


def _download_and_save(
    client: NetrixAPIClient,
    report_id: int,
    report_name: str,
    output_dir: Path,
) -> None:
    """Download a report file and save to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    save_path = output_dir / report_name

    with spinner(f"Downloading {report_name}..."):
        dl_resp = client.download_report(report_id)

    if dl_resp.status_code == 200:
        with open(save_path, "wb") as fh:
            fh.write(dl_resp.content)
        size_kb = len(dl_resp.content) // 1024 or 1
        show_success(f"Saved: {save_path.resolve()} ({size_kb} KB)")
    else:
        show_warning(f"Report generated but download failed (HTTP {dl_resp.status_code})")


# ─────────────────────────────────────────
# Core flat command: netrix report
# ─────────────────────────────────────────

def cmd_report(
    scan_id: Optional[int] = None,
    fmt: Optional[str] = None,
    output: Optional[str] = None,
) -> None:
    """
    Generate a report for a scan.

    With no arguments: interactive wizard to select scan and format.
    With arguments: direct mode.

    Examples:
        netrix report
        netrix report --scan 1 --format pdf
        netrix report --scan 1 --format json --output ./reports/
    """
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    output_dir = Path(output) if output else Path(get_setting("output_dir") or "./reports")

    # ── Direct mode ────────────────────────────────────────────────────
    if scan_id and fmt:
        fmt_lower = fmt.lower()
        if not is_valid_format(fmt_lower):
            show_error(f"Invalid format: '{fmt}'. Allowed: {', '.join(sorted(ALLOWED_FORMATS))}")
            raise typer.Exit(1)

        try:
            with spinner(f"Generating {fmt_lower.upper()} report for scan {scan_id}..."):
                gen_resp = client.generate_report(scan_id, fmt_lower)

            if gen_resp.status_code in (200, 201):
                data = gen_resp.json()
                _download_and_save(client, data["id"], data.get("report_name", f"report.{fmt_lower}"), output_dir)
            else:
                _handle_api_error(gen_resp)
        except httpx.ConnectError:
            show_connection_error(api_url)
        except httpx.ReadTimeout:
            show_error("Request timed out. Large scans take longer to generate.")
        return

    # ── Interactive wizard ─────────────────────────────────────────────
    try:
        console.print()
        console.rule("[bold cyan]Report Generator[/bold cyan]")
        console.print()

        # Fetch completed scans
        with spinner("Loading scans..."):
            scans_resp = client.get_scans(page_size=50)

        if scans_resp.status_code != 200:
            _handle_api_error(scans_resp)
            return

        all_scans = scans_resp.json().get("scans", [])
        completed = [s for s in all_scans if s.get("status") == "completed"]

        if not completed:
            show_info("No completed scans found. Run a scan first: netrix scan")
            return

        # Select scan
        selected_id = prompt_select_scan(completed)
        if selected_id is None:
            console.print("[dim]Cancelled.[/dim]")
            return

        # Select formats
        formats = prompt_report_formats()

        # Generate each format
        for fmt_lower in formats:
            try:
                with spinner(f"Generating {fmt_lower.upper()} report..."):
                    gen_resp = client.generate_report(selected_id, fmt_lower)

                if gen_resp.status_code in (200, 201):
                    data = gen_resp.json()
                    _download_and_save(
                        client, data["id"],
                        data.get("report_name", f"report.{fmt_lower}"),
                        output_dir,
                    )
                else:
                    _handle_api_error(gen_resp)
            except Exception as e:
                show_warning(f"Failed to generate {fmt_lower.upper()} report: {e}")

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")


# ─────────────────────────────────────────
# Backward-compatible sub-commands
# ─────────────────────────────────────────

@app.command("generate")
def generate_report(
    scan: int = typer.Option(..., "--scan", "-s", help="Numeric scan ID"),
    fmt: str = typer.Option("pdf", "--format", "-f", help="Format: pdf|json|csv|html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Custom report name"),
) -> None:
    """Generate a report for a completed scan."""
    cmd_report(scan_id=scan, fmt=fmt, output=output)


@app.command("list")
def list_reports(
    limit: int = typer.Option(20, "--limit", "-l"),
    fmt: Optional[str] = typer.Option(None, "--format", "-f"),
) -> None:
    """List all generated reports."""
    show_banner()
    _require_login()

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        with spinner("Fetching reports..."):
            resp = client.get_reports(page_size=limit, format=fmt)

        if resp.status_code == 200:
            data = resp.json()
            report_list = data.get("reports", [])
            total = data.get("total", len(report_list))
            if not report_list:
                show_info("No reports found.")
                return
            console.print(reports_table(report_list))
            console.print(f"\n[dim]Showing {len(report_list)} of {total} total reports[/dim]")
        else:
            _handle_api_error(resp)
    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")
