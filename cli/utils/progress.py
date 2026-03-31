# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/utils/progress.py
# Purpose: Progress tracking utilities — live scan progress
#          bar with API polling plus a context-manager spinner.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import time
from contextlib import contextmanager
from typing import Dict, Optional

import httpx
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.text import Text

console = Console()


# ─────────────────────────────────────────
# Live scan progress bar
# ─────────────────────────────────────────
def scan_progress_bar(
    scan_id: int,
    token: str,
    api_base: str,
    target: str = "",
    poll_interval: float = 3.0,
) -> Optional[Dict]:
    """
    Show a live progress panel while polling for scan status.

    Polls ``GET /scans/{scan_id}/status`` every *poll_interval*
    seconds and updates a Rich live display with the current
    progress percentage and elapsed time.

    Args:
        scan_id:        Numeric scan ID to monitor.
        token:          JWT access token for API authentication.
        api_base:       Base URL of the Netrix API.
        target:         The scan target (for display purposes).
        poll_interval:  Seconds between status polls (default: 3).

    Returns:
        dict | None: The final status payload on completion,
                     or None if the scan could not be tracked.
    """
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{api_base}/scans/{scan_id}/status"

    progress = Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
        TimeElapsedColumn(),
    )
    task_id = progress.add_task("Scanning...", total=100)

    final_status: Optional[Dict] = None

    def _build_panel() -> Panel:
        current_pct = progress.tasks[task_id].completed
        status_text = final_status.get("status", "running") if final_status else "running"
        lines = [
            "[bold cyan]🔍 NETRIX SCANNING...[/bold cyan]",
        ]
        if target:
            lines.append(f"  Target: {target}")
        lines.append("")
        lines.append(f"  Status: {status_text.capitalize()}")
        lines.append("")

        panel_content = Text.from_markup("\n".join(lines))
        panel = Panel(
            panel_content,
            border_style="cyan",
            padding=(0, 2),
        )
        return panel

    with Live(console=console, refresh_per_second=4) as live:
        while True:
            # Poll API
            try:
                resp = httpx.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    final_status = resp.json()
                    pct = final_status.get("progress", 0)
                    status_str = final_status.get("status", "running")

                    progress.update(task_id, completed=pct)

                    # Update live display
                    from rich.columns import Columns
                    from rich.layout import Layout

                    status_text = status_str.capitalize()
                    target_line = f"  Target: {target}\n" if target else ""

                    panel_text = (
                        f"[bold cyan]🔍 NETRIX SCANNING...[/bold cyan]\n"
                        f"{target_line}\n"
                    )

                    from rich.console import Group

                    group = Group(
                        Panel(
                            Text.from_markup(panel_text),
                            border_style="cyan",
                            padding=(0, 2),
                        ),
                        progress,
                    )
                    live.update(group)

                    if status_str in ("completed", "failed"):
                        progress.update(
                            task_id,
                            completed=100 if status_str == "completed" else pct,
                        )
                        break
                elif resp.status_code == 401:
                    console.print(
                        "[bold red]❌ Session expired.[/bold red] "
                        "Please run [bold cyan]netrix auth login[/bold cyan]."
                    )
                    return None
                else:
                    # Non-critical: keep polling
                    pass
            except httpx.ConnectError:
                console.print(
                    "[bold red]❌ Lost connection to backend.[/bold red]"
                )
                return None
            except httpx.ReadTimeout:
                pass  # Retry on next poll

            time.sleep(poll_interval)

    return final_status


# ─────────────────────────────────────────
# Simple spinner context manager
# ─────────────────────────────────────────
@contextmanager
def spinner(message: str = "Processing..."):
    """
    Display a spinning animation for short-running operations.

    Usage::

        with spinner("Generating report..."):
            do_something_slow()

    Args:
        message: Text shown next to the spinner.
    """
    with console.status(f"[bold cyan]{message}[/bold cyan]", spinner="dots"):
        yield
