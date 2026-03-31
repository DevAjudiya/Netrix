# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/commands/config_cmd.py
# Purpose: Config command — view and manage CLI settings.
# ─────────────────────────────────────────

from typing import Optional

import typer
from rich.console import Console

from cli.config import (
    DEFAULTS,
    get_display_config,
    load_config,
    reset_config,
    save_config,
)
from cli.ui.banners import show_banner
from cli.ui.panels import show_error, show_info, show_success, show_warning
from cli.ui.prompts import prompt_config_action
from cli.ui.tables import config_table

console = Console()

VALID_SCAN_TYPES = {"quick", "stealth", "full", "aggressive", "vulnerability"}
VALID_FORMATS = {"pdf", "json", "csv", "html"}
VALID_THEMES = {"dark", "light"}

_SETTING_LABELS = {
    "api_url":           "API URL",
    "default_scan_type": "Default scan type",
    "default_format":    "Default report format",
    "output_dir":        "Report output directory",
    "theme":             "Theme",
}

_SETTING_CHOICES = {
    "default_scan_type": VALID_SCAN_TYPES,
    "default_format":    VALID_FORMATS,
    "theme":             VALID_THEMES,
}


def _set_setting(key: str, value: str) -> bool:
    """Validate and save a setting. Returns True on success."""
    allowed = _SETTING_CHOICES.get(key)
    if allowed and value not in allowed:
        show_error(
            f"Invalid value '{value}' for {key}.\n"
            f"Allowed: {', '.join(sorted(allowed))}"
        )
        return False
    save_config({key: value})
    return True


def cmd_config(
    list_all: bool = False,
    set_kv: Optional[str] = None,
    reset: bool = False,
) -> None:
    """
    View and manage Netrix CLI settings.

    With no arguments: opens an interactive settings menu.

    Examples:
        netrix config --list
        netrix config --set api_url=http://192.168.1.100:8000/api/v1
        netrix config --reset
    """
    show_banner()

    # ── --reset ────────────────────────────────────────────────────────
    if reset:
        from cli.ui.prompts import prompt_confirm_delete
        if prompt_confirm_delete("all settings (token will be kept)"):
            reset_config()
            show_success("Settings reset to defaults.")
        else:
            console.print("[dim]Reset cancelled.[/dim]")
        return

    # ── --list ─────────────────────────────────────────────────────────
    if list_all:
        cfg = get_display_config()
        console.print()
        console.print(config_table(cfg))
        return

    # ── --set KEY=VALUE ────────────────────────────────────────────────
    if set_kv:
        if "=" not in set_kv:
            show_error("Format: --set KEY=VALUE  (e.g. --set api_url=http://localhost:8000/api/v1)")
            raise typer.Exit(1)

        key, _, value = set_kv.partition("=")
        key = key.strip()
        value = value.strip()

        if key not in DEFAULTS:
            show_error(
                f"Unknown setting: '{key}'\n"
                f"Valid keys: {', '.join(sorted(DEFAULTS.keys()))}"
            )
            raise typer.Exit(1)

        if _set_setting(key, value):
            show_success(f"[bold]{key}[/bold] updated to: {value}")
        return

    # ── Interactive menu ───────────────────────────────────────────────
    try:
        while True:
            action = prompt_config_action()

            if action == "back":
                return

            if action == "list":
                cfg = get_display_config()
                console.print()
                console.print(config_table(cfg))
                continue

            if action == "reset":
                from cli.ui.prompts import prompt_confirm_delete
                if prompt_confirm_delete("all settings (token will be kept)"):
                    reset_config()
                    show_success("Settings reset to defaults.")
                continue

            # Edit a specific setting
            if action in DEFAULTS:
                current = get_display_config().get(action, DEFAULTS.get(action, ""))
                label = _SETTING_LABELS.get(action, action)
                allowed = _SETTING_CHOICES.get(action)

                if allowed:
                    from InquirerPy import inquirer
                    from InquirerPy.base.control import Choice
                    value = inquirer.select(
                        message=f"{label}:",
                        choices=[Choice(v, v) for v in sorted(allowed)],
                        default=current if current in allowed else None,
                    ).execute()
                else:
                    from InquirerPy import inquirer
                    value = inquirer.text(
                        message=f"{label}:",
                        default=current,
                        validate=lambda v: len(v.strip()) > 0 or "Cannot be empty",
                    ).execute()
                    value = value.strip()

                if _set_setting(action, value):
                    show_success(f"[bold]{action}[/bold] = {value}")

    except KeyboardInterrupt:
        console.print("\n[dim]Config closed.[/dim]")
