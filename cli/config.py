# ─────────────────────────────────────────
# Netrix — cli/config.py
# Purpose: CLI configuration management — persistent token
#          storage, API base URL, and config file helpers.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import json
import os
from pathlib import Path
from typing import Dict, Optional

# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
CONFIG_DIR: Path = Path.home() / ".netrix"
CONFIG_FILE: Path = CONFIG_DIR / "config.json"
API_BASE_URL: str = "http://127.0.0.1:8000/api/v1"


# ─────────────────────────────────────────
# Config file operations
# ─────────────────────────────────────────
def _ensure_config_dir() -> None:
    """Create the ~/.netrix directory if it doesn't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_config(data: dict) -> None:
    """
    Save configuration data to ~/.netrix/config.json.

    Merges *data* into the existing config so that
    callers can update individual keys without losing others.

    Args:
        data: Dictionary of config keys to persist.
    """
    _ensure_config_dir()
    existing = load_config()
    existing.update(data)
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)


def load_config() -> dict:
    """
    Load the config file and return its contents as a dict.

    Returns:
        dict: The parsed config, or an empty dict if the file
              does not exist or is malformed.
    """
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


# ─────────────────────────────────────────
# Token helpers
# ─────────────────────────────────────────
def get_token() -> Optional[str]:
    """
    Retrieve the saved authentication token.

    Returns:
        str | None: The JWT access token, or None if not logged in.
    """
    config = load_config()
    return config.get("access_token")


def save_token(token: str, refresh_token: str = "") -> None:
    """
    Persist an authentication token (and optional refresh token).

    Args:
        token:         JWT access token.
        refresh_token: JWT refresh token (optional).
    """
    data: dict = {"access_token": token}
    if refresh_token:
        data["refresh_token"] = refresh_token
    save_config(data)


def clear_token() -> None:
    """
    Remove authentication tokens from the config file (logout).
    """
    config = load_config()
    config.pop("access_token", None)
    config.pop("refresh_token", None)
    config.pop("username", None)
    _ensure_config_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)


def is_logged_in() -> bool:
    """
    Check whether a valid token is saved.

    Returns:
        bool: True if an access token is present.
    """
    return get_token() is not None


def get_headers() -> Dict[str, str]:
    """
    Build an Authorization header dict using the saved token.

    Returns:
        dict: ``{"Authorization": "Bearer <token>"}``

    Raises:
        SystemExit: If no token is saved (prompts the user to login).
    """
    token = get_token()
    if not token:
        from rich.console import Console
        Console().print(
            "[bold red]❌ Not logged in.[/bold red]  "
            "Please run [bold cyan]netrix auth login[/bold cyan] first."
        )
        raise SystemExit(1)
    return {"Authorization": f"Bearer {token}"}
