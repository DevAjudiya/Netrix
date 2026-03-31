# © 2026 @DevAjudiya. All rights reserved.
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

# Default settings
DEFAULTS: Dict = {
    "api_url":           "http://127.0.0.1:8000/api/v1",
    "default_scan_type": "quick",
    "default_format":    "pdf",
    "output_dir":        "./reports",
    "theme":             "dark",
}


def _get_api_url() -> str:
    cfg = load_config()
    return cfg.get("api_url", DEFAULTS["api_url"])


# Dynamic API_BASE_URL — reads from config file at import time
API_BASE_URL: str = DEFAULTS["api_url"]


def get_api_url() -> str:
    """Return the configured API base URL."""
    return load_config().get("api_url", DEFAULTS["api_url"])


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


def is_token_valid() -> bool:
    """
    Check whether a saved token exists AND is not expired.

    Decodes the JWT payload without verifying the signature (client-side
    expiry check only). Returns False if no token, malformed, or expired.
    """
    token = get_token()
    if not token:
        return False
    try:
        import base64
        import json
        import time

        parts = token.split(".")
        if len(parts) != 3:
            return False
        # JWT payload is base64url-encoded; add padding to make it valid base64
        padded = parts[1] + "=="
        payload = json.loads(base64.urlsafe_b64decode(padded))
        exp = payload.get("exp", 0)
        # Give a 30-second buffer so we re-login slightly before actual expiry
        return exp > (time.time() + 30)
    except Exception:
        # If we can't decode it, treat the token as invalid
        return False


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
            "Please run [bold cyan]netrix login[/bold cyan] first."
        )
        raise SystemExit(1)
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────
# Settings helpers
# ─────────────────────────────────────────

def get_setting(key: str) -> str:
    """Return a config setting, falling back to default."""
    return load_config().get(key, DEFAULTS.get(key, ""))


def get_display_config() -> Dict:
    """Return all user-visible settings (excluding tokens)."""
    cfg = load_config()
    result = {}
    for key in DEFAULTS:
        result[key] = cfg.get(key, DEFAULTS[key])
    return result


def reset_config() -> None:
    """Reset all settings to defaults (keeps token)."""
    cfg = load_config()
    token = cfg.get("access_token")
    refresh = cfg.get("refresh_token")
    username = cfg.get("username")

    new_cfg = dict(DEFAULTS)
    if token:
        new_cfg["access_token"] = token
    if refresh:
        new_cfg["refresh_token"] = refresh
    if username:
        new_cfg["username"] = username

    _ensure_config_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        json.dump(new_cfg, fh, indent=2)
