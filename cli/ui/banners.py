# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/ui/banners.py
# Purpose: ASCII art banner and welcome screen.
# ─────────────────────────────────────────

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER_ART = r"""
 ███╗   ██╗███████╗████████╗██████╗ ██╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║ ╚███╔╝
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║ ██╔██╗
 ██║ ╚████║███████╗   ██║   ██║  ██║██║██╔╝ ██╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""


def show_banner() -> None:
    """Display the Netrix ASCII-art banner."""
    console.print(
        Panel(
            Text.from_markup(
                f"[bold cyan]{BANNER_ART}[/bold cyan]\n"
                "[bold white]  Network Scanning & Vulnerability Assessment Platform[/bold white]\n"
                "[dim]  Version 1.0.0  •  Powered by Nmap + NVD CVE Engine[/dim]\n"
                "[dim]  © 2026 @DevAjudiya. All rights reserved.[/dim]"
            ),
            border_style="cyan",
            padding=(0, 2),
        )
    )
