# ─────────────────────────────────────────
# Netrix — cli/commands/report.py
# Purpose: CLI commands for report generation, listing,
#          and downloading.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import os
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from cli.config import API_BASE_URL, get_headers, is_logged_in
from cli.utils.display import (
    create_reports_table,
    show_banner,
    show_error,
    show_info,
    show_success,
    show_warning,
)
from cli.utils.progress import spinner

app = typer.Typer(
    name="report",
    help="Report generation — create, list, and download reports.",
    rich_markup_mode="rich",
)
console = Console()

ALLOWED_FORMATS = {"pdf", "json", "csv", "html"}


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────
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
    elif resp.status_code == 422:
        detail = resp.json().get("detail", "Validation error")
        show_error(f"Validation error: {detail}")
    elif resp.status_code >= 500:
        show_error("Server error. Please try again later.")
    else:
        show_error(f"Request failed (HTTP {resp.status_code}): {resp.text[:200]}")


def _format_file_size(size_bytes: int) -> str:
    """Return a human-readable file size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


# ─────────────────────────────────────────
# netrix report generate
# ─────────────────────────────────────────
@app.command("generate")
def generate_report(
    scan: int = typer.Option(
        ..., "--scan", "-s",
        help="Numeric scan ID to generate a report for.",
    ),
    fmt: str = typer.Option(
        "pdf", "--format", "-f",
        help="Report format: pdf | json | csv | html",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output directory to save the report (default: current directory).",
    ),
    name: Optional[str] = typer.Option(
        None, "--name", "-n",
        help="Custom report name.",
    ),
) -> None:
    """
    Generate a report for a completed scan.

    Examples:
        netrix report generate --scan 1 --format pdf
        netrix report generate --scan 1 --format html --output ./reports
    """
    show_banner()
    _require_login()

    fmt_lower = fmt.lower()
    if fmt_lower not in ALLOWED_FORMATS:
        show_error(
            f"Invalid format: '{fmt}'\n"
            f"  Allowed: {', '.join(sorted(ALLOWED_FORMATS))}"
        )
        raise typer.Exit(1)

    try:
        headers = get_headers()

        # ── Generate report ──────────────────────────────────────
        with spinner(f"Generating {fmt_lower.upper()} report..."):
            resp = httpx.post(
                f"{API_BASE_URL}/reports/generate",
                json={"scan_id": scan, "format": fmt_lower},
                headers=headers,
                timeout=120.0,
            )

        if resp.status_code in (200, 201):
            report_data = resp.json()
            report_id = report_data.get("id")
            report_name = report_data.get("report_name", f"report_{scan}.{fmt_lower}")
            file_size = report_data.get("file_size", 0)

            # ── Download the report file ─────────────────────────
            out_dir = Path(output) if output else Path.cwd()
            out_dir.mkdir(parents=True, exist_ok=True)

            save_name = name if name else report_name
            save_path = out_dir / save_name

            with spinner("Downloading report file..."):
                dl_resp = httpx.get(
                    f"{API_BASE_URL}/reports/{report_id}/download",
                    headers=headers,
                    timeout=120.0,
                )

            if dl_resp.status_code == 200:
                with open(save_path, "wb") as fh:
                    fh.write(dl_resp.content)

                actual_size = save_path.stat().st_size
                size_str = _format_file_size(actual_size)

                console.print()
                show_success("Report Generated!")
                console.print(f"  [bold]📄 File:[/bold]     {save_name}")
                console.print(f"  [bold]📁 Saved to:[/bold] {save_path.resolve()}")
                console.print(f"  [bold]📊 Size:[/bold]     {size_str}")
                console.print()
            else:
                show_warning(
                    "Report generated on server but download failed. "
                    f"You can download it later with report ID {report_id}."
                )
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out. Report generation may take a while for large scans.")
    except SystemExit:
        raise


# ─────────────────────────────────────────
# netrix report list
# ─────────────────────────────────────────
@app.command("list")
def list_reports(
    limit: int = typer.Option(
        20, "--limit", "-l",
        help="Maximum number of reports to display.",
    ),
    fmt: Optional[str] = typer.Option(
        None, "--format", "-f",
        help="Filter by format: pdf | json | csv | html",
    ),
) -> None:
    """
    List all generated reports.
    """
    show_banner()
    _require_login()

    try:
        headers = get_headers()
        params: dict = {"page_size": limit}
        if fmt:
            params["format"] = fmt.lower()

        resp = httpx.get(
            f"{API_BASE_URL}/reports/",
            headers=headers,
            params=params,
            timeout=15.0,
        )

        if resp.status_code == 200:
            data = resp.json()
            reports = data.get("reports", [])
            total = data.get("total", len(reports))

            if not reports:
                show_info("No reports found.")
                return

            console.print(create_reports_table(reports))
            console.print(
                f"\n[dim]Showing {len(reports)} of {total} total reports[/dim]"
            )
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except SystemExit:
        raise
