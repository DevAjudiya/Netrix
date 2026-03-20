# ─────────────────────────────────────────
# Netrix — cli/utils/validators.py
# Purpose: Input validation for targets, IPs, CIDRs, domains.
# ─────────────────────────────────────────

import re

_IP_RE     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_RANGE_RE  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

ALLOWED_SCAN_TYPES   = {"quick", "stealth", "full", "aggressive", "vulnerability"}
ALLOWED_FORMATS      = {"pdf", "json", "csv", "html"}
ALLOWED_SEVERITIES   = {"all", "critical", "high", "medium", "low", "info"}


def is_valid_target(target: str) -> bool:
    """Return True if target is a valid IP, CIDR, IP range, or domain."""
    t = target.strip()
    return bool(
        _IP_RE.match(t)
        or _CIDR_RE.match(t)
        or _RANGE_RE.match(t)
        or _DOMAIN_RE.match(t)
    )


def is_valid_ip(ip: str) -> bool:
    """Return True if string is a valid IPv4 address."""
    if not _IP_RE.match(ip.strip()):
        return False
    parts = ip.strip().split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def is_valid_scan_type(scan_type: str) -> bool:
    return scan_type.lower() in ALLOWED_SCAN_TYPES


def is_valid_format(fmt: str) -> bool:
    return fmt.lower() in ALLOWED_FORMATS


def is_valid_severity(severity: str) -> bool:
    return severity.lower() in ALLOWED_SEVERITIES
