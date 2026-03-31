# © 2026 @DevAjudiya. All rights reserved.
# ─────────────────────────────────────────
# Netrix — cli/utils/formatters.py
# Purpose: Formatters for dates, file sizes, durations, severity.
# ─────────────────────────────────────────

from datetime import datetime
from typing import Optional


def format_date(date_str: Optional[str]) -> str:
    """Convert ISO datetime string to human-readable date."""
    if not date_str:
        return "N/A"
    if isinstance(date_str, str) and "T" in date_str:
        return date_str.split("T")[0]
    return str(date_str)


def format_datetime(date_str: Optional[str]) -> str:
    """Convert ISO datetime string to human-readable date+time."""
    if not date_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(date_str)


def format_duration(seconds: Optional[float]) -> str:
    """Convert seconds to human-readable duration string."""
    if not seconds or seconds <= 0:
        return "N/A"
    s = int(seconds)
    hours, remainder = divmod(s, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_file_size(size_bytes: Optional[int]) -> str:
    """Convert bytes to human-readable file size."""
    if not size_bytes:
        return "0 B"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1048576:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / 1048576:.1f} MB"


def scan_type_label(scan_type: str) -> str:
    """Return a human-readable scan type label."""
    return {
        "quick":         "⚡ Quick",
        "stealth":       "🥷 Stealth",
        "full":          "🔍 Full",
        "aggressive":    "💥 Aggressive",
        "vulnerability": "🛡️  Vulnerability",
    }.get(scan_type.lower(), scan_type.capitalize())


def scan_estimated_time(scan_type: str) -> str:
    """Return estimated scan time for a given scan type."""
    return {
        "quick":         "~2 minutes",
        "stealth":       "~20 minutes",
        "full":          "~30 minutes",
        "aggressive":    "~45 minutes",
        "vulnerability": "~60 minutes",
    }.get(scan_type.lower(), "Varies")
