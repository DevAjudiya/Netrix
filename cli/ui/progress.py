# ─────────────────────────────────────────
# Netrix — cli/ui/progress.py
# Purpose: Live progress bars and scan status display.
# ─────────────────────────────────────────

import time
from contextlib import contextmanager
from typing import Dict, List, Optional

import httpx
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.text import Text

console = Console()


# ── Spinner ───────────────────────────────────────────────────────────


@contextmanager
def spinner(message: str = "Processing..."):
    """
    Context manager: show a spinner during short-running operations.

    Usage::

        with spinner("Generating report..."):
            do_something_slow()
    """
    with console.status(f"[bold cyan]{message}[/bold cyan]", spinner="dots"):
        yield


# ── Live scan progress ────────────────────────────────────────────────


def scan_progress_bar(
    scan_id: str,
    token: str,
    api_base: str,
    target: str = "",
    scan_type: str = "",
    poll_interval: float = 2.5,
) -> Optional[Dict]:
    """
    Display a live progress panel while polling scan status.

    Polls ``GET /scans/{scan_id}/status`` every *poll_interval* seconds
    and renders a Rich Live panel with progress bar + live activity feed.

    Returns the final status dict on completion, or None on error.
    """
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{api_base}/scans/{scan_id}/status"
    results_url = f"{api_base}/scans/{scan_id}/results"

    progress = Progress(
        TextColumn("  [bold cyan]{task.description}"),
        BarColumn(bar_width=35, complete_style="cyan", finished_style="green"),
        TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task("Scanning...", total=100)

    final_status: Optional[Dict] = None
    recent_activity: List[str] = []
    hosts_found = 0
    open_ports = 0
    start_time = time.time()

    def _build_live() -> Group:
        elapsed = int(time.time() - start_time)
        mins, secs = divmod(elapsed, 60)
        elapsed_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"

        pct = progress.tasks[task_id].completed
        status_str = (final_status or {}).get("status", "running")

        lines = [
            f"[bold cyan]  Target :[/bold cyan] {target}" if target else "",
            f"[bold cyan]  Type   :[/bold cyan] {scan_type.capitalize()} Scan" if scan_type else "",
            f"[bold cyan]  Status :[/bold cyan] {status_str.capitalize()}",
            "",
            f"  [white]Hosts found : {hosts_found}[/white]",
            f"  [white]Open ports  : {open_ports}[/white]",
            f"  [dim]Elapsed     : {elapsed_str}[/dim]",
        ]
        lines = [l for l in lines if l is not None]

        if recent_activity:
            lines.append("\n  [dim][Last Activity][/dim]")
            for act in recent_activity[-4:]:
                lines.append(f"  [green]✔[/green] {act}")

        panel = Panel(
            Text.from_markup("\n".join(lines)),
            title="[bold cyan]Scanning...[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )
        return Group(panel, progress)

    with Live(console=console, refresh_per_second=4) as live:
        while True:
            try:
                resp = httpx.get(url, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    final_status = resp.json()
                    pct = final_status.get("progress", 0)
                    status_str = final_status.get("status", "running")

                    # Try to get partial host/port counts from status
                    hosts_found = final_status.get("hosts_up", 0) or hosts_found
                    open_ports = final_status.get("open_ports", 0) or open_ports

                    progress.update(task_id, completed=pct)
                    live.update(_build_live())

                    if status_str in ("completed", "failed"):
                        if status_str == "completed":
                            progress.update(task_id, completed=100)
                            # Try to get final counts from results
                            try:
                                res_resp = httpx.get(results_url, headers=headers, timeout=15.0)
                                if res_resp.status_code == 200:
                                    rdata = res_resp.json()
                                    summary = rdata.get("summary", {})
                                    hosts_found = summary.get("total_hosts", hosts_found)
                                    open_ports = summary.get("total_open_ports", open_ports)
                                    live.update(_build_live())
                            except Exception:
                                pass
                        break

                elif resp.status_code == 401:
                    console.print("[bold red]❌ Session expired.[/bold red]")
                    return None

            except httpx.ConnectError:
                console.print("[bold red]❌ Lost connection to backend.[/bold red]")
                return None
            except httpx.ReadTimeout:
                pass  # retry

            time.sleep(poll_interval)

    return final_status


# ── Report download progress ──────────────────────────────────────────


def download_progress(total_size: int = 0) -> Progress:
    """Return a Progress instance for file download tracking."""
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, complete_style="green"),
        TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
    )
