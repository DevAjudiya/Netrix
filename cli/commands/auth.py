# ─────────────────────────────────────────
# Netrix — cli/commands/auth.py
# Purpose: Authentication commands — login, logout, whoami.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cli.config import (
    API_BASE_URL,
    clear_token,
    get_headers,
    get_token,
    is_logged_in,
    save_config,
    save_token,
)
from cli.utils.display import show_banner, show_error, show_success

app = typer.Typer(
    name="auth",
    help="Authentication — login, logout, and session management.",
    rich_markup_mode="rich",
)
console = Console()


# ─────────────────────────────────────────
# Error handling helper
# ─────────────────────────────────────────
def _handle_api_error(resp: httpx.Response) -> None:
    """Display a formatted error based on the HTTP status code."""
    if resp.status_code == 401:
        show_error("Invalid credentials. Please check your username and password.")
    elif resp.status_code == 404:
        show_error("API endpoint not found. Is the backend version correct?")
    elif resp.status_code == 422:
        detail = resp.json().get("detail", "Validation error")
        show_error(f"Validation error: {detail}")
    elif resp.status_code >= 500:
        show_error("Server error. Please try again later.")
    else:
        show_error(f"Request failed (HTTP {resp.status_code}): {resp.text[:200]}")


# ─────────────────────────────────────────
# netrix auth login
# ─────────────────────────────────────────
@app.command("login")
def login() -> None:
    """
    Authenticate with the Netrix backend.

    Prompts for username and password, then saves the JWT token
    to ~/.netrix/config.json for future commands.
    """
    show_banner()

    username = typer.prompt("Username")
    password = typer.prompt("Password", hide_input=True)

    try:
        resp = httpx.post(
            f"{API_BASE_URL}/auth/login",
            json={"username": username, "password": password},
            timeout=15.0,
        )

        if resp.status_code == 200:
            data = resp.json()
            save_token(
                token=data["access_token"],
                refresh_token=data.get("refresh_token", ""),
            )
            save_config({"username": username})

            console.print(
                Panel(
                    f"[bold green]✅ Login Successful![/bold green]\n"
                    f"[white]Welcome, [bold]{username}[/bold][/white]",
                    border_style="green",
                    padding=(1, 2),
                )
            )
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out. The backend may be overloaded.")


# ─────────────────────────────────────────
# netrix auth logout
# ─────────────────────────────────────────
@app.command("logout")
def logout() -> None:
    """
    Log out and clear the saved authentication token.
    """
    show_banner()

    if not is_logged_in():
        show_error("You are not logged in.")
        raise typer.Exit(1)

    # Optionally notify the backend (best-effort)
    try:
        headers = get_headers()
        httpx.post(f"{API_BASE_URL}/auth/logout", headers=headers, timeout=5.0)
    except Exception:
        pass  # Server-side logout is best-effort with JWT

    clear_token()
    show_success("Logged out successfully.")


# ─────────────────────────────────────────
# netrix auth whoami
# ─────────────────────────────────────────
@app.command("whoami")
def whoami() -> None:
    """
    Display the currently authenticated user's profile.
    """
    show_banner()

    if not is_logged_in():
        show_error("You are not logged in. Run: netrix auth login")
        raise typer.Exit(1)

    try:
        headers = get_headers()
        resp = httpx.get(
            f"{API_BASE_URL}/auth/me",
            headers=headers,
            timeout=10.0,
        )

        if resp.status_code == 200:
            user = resp.json()

            table = Table(
                title="👤  Current User",
                title_style="bold cyan",
                border_style="cyan",
                show_lines=True,
            )
            table.add_column("Field", style="bold white", min_width=14)
            table.add_column("Value", style="white")

            table.add_row("Username", user.get("username", "N/A"))
            table.add_row("Email", user.get("email", "N/A"))
            table.add_row("Role", user.get("role", "N/A"))
            table.add_row("Active", "✅ Yes" if user.get("is_active") else "❌ No")

            created = user.get("created_at", "")
            if isinstance(created, str) and "T" in created:
                created = created.split("T")[0]
            table.add_row("Created", str(created))

            last_login = user.get("last_login", "")
            if isinstance(last_login, str) and "T" in last_login:
                last_login = last_login.split("T")[0]
            table.add_row("Last Login", str(last_login) if last_login else "Never")

            console.print(table)
        else:
            _handle_api_error(resp)

    except httpx.ConnectError:
        show_error("Cannot connect to the Netrix backend. Is the server running?")
    except httpx.ReadTimeout:
        show_error("Request timed out.")
    except SystemExit:
        raise
