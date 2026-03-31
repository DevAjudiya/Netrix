# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/commands/auth.py
# Purpose: Auth commands — login, register, logout, whoami.
# ─────────────────────────────────────────

import typer
import httpx
from rich.console import Console

from cli.api_client import NetrixAPIClient
from cli.config import (
    clear_token,
    get_api_url,
    is_logged_in,
    load_config,
    save_config,
    save_token,
)
from cli.ui.banners import show_banner
from cli.ui.panels import (
    show_connection_error,
    show_error,
    show_info,
    show_success,
    show_warning,
)
from cli.ui.tables import config_table
from cli.ui.prompts import prompt_login_credentials, prompt_register_credentials

console = Console()

# ── Kept for backward compatibility (netrix auth login etc.) ──────────
app = typer.Typer(
    name="auth",
    help="Authentication — login, logout, and session management.",
    rich_markup_mode="rich",
    hidden=True,
)


# ─────────────────────────────────────────
# Shared login logic (used by both flat & sub-command)
# ─────────────────────────────────────────

def _do_login(username: str, password: str) -> bool:
    """Perform login. Returns True on success."""
    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        resp = client.login(username, password)
        if resp.status_code == 200:
            data = resp.json()
            save_token(
                token=data["access_token"],
                refresh_token=data.get("refresh_token", ""),
            )
            save_config({"username": username})
            show_success(f"Login successful! Welcome, [bold]{username}[/bold]")
            return True
        elif resp.status_code == 401:
            show_error("Invalid credentials. Check your username and password.")
        elif resp.status_code == 422:
            detail = resp.json().get("detail", "Validation error")
            show_error(f"Validation error: {detail}")
        else:
            show_error(f"Login failed (HTTP {resp.status_code})")
        return False
    except httpx.ConnectError:
        show_connection_error(api_url)
        return False
    except httpx.ReadTimeout:
        show_error("Request timed out. The backend may be overloaded.")
        return False


def _do_register(username: str, email: str, password: str) -> bool:
    """Perform registration. Returns True on success."""
    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        resp = client.register(username, email, password)
        if resp.status_code in (200, 201):
            data = resp.json()
            # Auto-login after registration
            login_resp = client.login(username, password)
            if login_resp.status_code == 200:
                ldata = login_resp.json()
                save_token(
                    token=ldata["access_token"],
                    refresh_token=ldata.get("refresh_token", ""),
                )
                save_config({"username": username})
            show_success(f"Account created! Welcome, [bold]{username}[/bold]")
            return True
        elif resp.status_code == 409:
            show_error("Username or email already exists.")
        elif resp.status_code == 422:
            detail = resp.json().get("detail", "Validation error")
            show_error(f"Validation error: {detail}")
        else:
            show_error(f"Registration failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return False
    except httpx.ConnectError:
        show_connection_error(api_url)
        return False
    except httpx.ReadTimeout:
        show_error("Request timed out.")
        return False


# ─────────────────────────────────────────
# Reusable interactive helpers (call from anywhere, no typer involved)
# ─────────────────────────────────────────

def do_login_interactive() -> bool:
    """
    Prompt for credentials and login. Returns True on success.
    Safe to call from any command without going through typer.
    """
    try:
        creds = prompt_login_credentials()
        return _do_login(creds["username"], creds["password"])
    except KeyboardInterrupt:
        return False


def do_register_interactive() -> bool:
    """
    Prompt for registration details and create account. Returns True on success.
    Safe to call from any command without going through typer.
    """
    try:
        creds = prompt_register_credentials()
        return _do_register(creds["username"], creds["email"], creds["password"])
    except KeyboardInterrupt:
        return False


# ─────────────────────────────────────────
# Flat commands (registered on main app)
# ─────────────────────────────────────────

def cmd_login(
    username: str = typer.Option(None, "--username", "-u", help="Username"),
    password: str = typer.Option(None, "--password", "-p", help="Password", hide_input=True),
) -> None:
    """Authenticate with the Netrix backend."""
    show_banner()

    if is_logged_in():
        cfg = load_config()
        existing_user = cfg.get("username", "unknown")
        show_info(f"Already logged in as [bold]{existing_user}[/bold]. Run 'netrix logout' first.")
        raise typer.Exit(0)

    if username and password:
        _do_login(username, password)
    else:
        try:
            creds = prompt_login_credentials()
            _do_login(creds["username"], creds["password"])
        except KeyboardInterrupt:
            console.print("\n[dim]Login cancelled.[/dim]")


def cmd_register() -> None:
    """Create a new Netrix account."""
    show_banner()

    if is_logged_in():
        cfg = load_config()
        show_info(f"Already logged in as [bold]{cfg.get('username', 'unknown')}[/bold].")
        raise typer.Exit(0)

    try:
        creds = prompt_register_credentials()
        _do_register(creds["username"], creds["email"], creds["password"])
    except KeyboardInterrupt:
        console.print("\n[dim]Registration cancelled.[/dim]")


def cmd_logout() -> None:
    """Log out and clear the saved authentication token."""
    show_banner()

    if not is_logged_in():
        show_error("You are not logged in.")
        raise typer.Exit(1)

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        client.logout_server()
    except Exception:
        pass  # Best-effort

    clear_token()
    show_success("Logged out successfully. Goodbye!")


def cmd_whoami() -> None:
    """Display the currently authenticated user's profile."""
    show_banner()

    if not is_logged_in():
        show_error("You are not logged in. Run: netrix login")
        raise typer.Exit(1)

    api_url = get_api_url()
    client = NetrixAPIClient(base_url=api_url)
    try:
        from cli.ui.progress import spinner
        with spinner("Fetching user profile..."):
            resp = client.get_me()

        if resp.status_code == 200:
            user = resp.json()
            from cli.utils.formatters import format_date, format_datetime

            data = {
                "Username":   user.get("username", "N/A"),
                "Email":      user.get("email", "N/A"),
                "Role":       user.get("role", "N/A"),
                "Active":     "✅ Yes" if user.get("is_active") else "❌ No",
                "Created":    format_date(user.get("created_at")),
                "Last Login": format_datetime(user.get("last_login")) if user.get("last_login") else "Never",
            }
            console.print(config_table(data))
        elif resp.status_code == 401:
            show_error("Session expired. Run: netrix login")
        else:
            show_error(f"Failed to fetch profile (HTTP {resp.status_code})")

    except httpx.ConnectError:
        show_connection_error(api_url)
    except httpx.ReadTimeout:
        show_error("Request timed out.")


# ─────────────────────────────────────────
# Backward-compatible sub-commands (netrix auth login)
# ─────────────────────────────────────────

@app.command("login")
def auth_login(
    username: str = typer.Option(None, "--username", "-u"),
    password: str = typer.Option(None, "--password", "-p", hide_input=True),
) -> None:
    """Login (alias: netrix login)."""
    cmd_login(username=username, password=password)


@app.command("register")
def auth_register() -> None:
    """Register a new account (alias: netrix register)."""
    cmd_register()


@app.command("logout")
def auth_logout() -> None:
    """Logout (alias: netrix logout)."""
    cmd_logout()


@app.command("whoami")
def auth_whoami() -> None:
    """Show current user (alias: netrix whoami)."""
    cmd_whoami()
