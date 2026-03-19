# ─────────────────────────────────────────
# Netrix — validators.py
# Purpose: Input validation and sanitization functions for scan targets,
#          port ranges, IP addresses, CIDR blocks, and domain names.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import ipaddress
import re
from typing import Tuple

from app.core.exceptions import InvalidTargetException


# Pre-compiled regex patterns for performance
_DOMAIN_PATTERN: re.Pattern = re.compile(
    r"^(?!-)"                          # Must not start with a hyphen
    r"[A-Za-z0-9-]{1,63}"             # First label (1-63 alphanumeric or hyphens)
    r"(\.[A-Za-z0-9-]{1,63})*"        # Additional labels separated by dots
    r"\.[A-Za-z]{2,}$"                # TLD must be at least 2 alphabetic chars
)

_PORT_RANGE_PATTERN: re.Pattern = re.compile(
    r"^(\d{1,5}(-\d{1,5})?)"          # Single port or port range (e.g. 80 or 80-443)
    r"(,\d{1,5}(-\d{1,5})?)*$"        # Optional additional ports/ranges
)

# Characters that could be used for shell injection
_DANGEROUS_CHARS: str = ";|&$`\\><\"'{}()!"


def validate_ip_address(
    ip_address: str,
    allow_private: bool = False,
) -> str:
    """
    Validate and clean an IPv4 address string.

    Ensures the IP is a valid IPv4 address and optionally blocks private
    and reserved address ranges.

    Args:
        ip_address:    The IP address string to validate.
        allow_private: If True, allow private/RFC1918 addresses (10.x, 172.16-31.x, 192.168.x).
                       Defaults to False for production safety.

    Returns:
        str: The cleaned and validated IP address string.

    Raises:
        InvalidTargetException: If the IP address is invalid, loopback,
                                unspecified, or private (when not allowed).
    """
    cleaned_ip = ip_address.strip()

    # Attempt to parse as an IPv4 address
    try:
        addr = ipaddress.IPv4Address(cleaned_ip)
    except (ipaddress.AddressValueError, ValueError) as parse_error:
        raise InvalidTargetException(
            message=f"'{cleaned_ip}' is not a valid IPv4 address.",
            details=str(parse_error),
        )

    # Block loopback addresses (127.0.0.0/8)
    if addr.is_loopback:
        raise InvalidTargetException(
            message="Loopback addresses (127.x.x.x) are not allowed as scan targets.",
            details=f"Received: {cleaned_ip}",
        )

    # Block unspecified address (0.0.0.0)
    if addr.is_unspecified:
        raise InvalidTargetException(
            message="The unspecified address (0.0.0.0) is not a valid scan target.",
            details=f"Received: {cleaned_ip}",
        )

    # Block reserved addresses (e.g. 240.0.0.0/4, 255.255.255.255)
    if addr.is_reserved:
        raise InvalidTargetException(
            message="Reserved IP addresses are not allowed as scan targets.",
            details=f"Received: {cleaned_ip}",
        )

    # Block multicast addresses (224.0.0.0/4)
    if addr.is_multicast:
        raise InvalidTargetException(
            message="Multicast addresses are not allowed as scan targets.",
            details=f"Received: {cleaned_ip}",
        )

    # Block private addresses unless explicitly allowed
    if addr.is_private and not allow_private:
        raise InvalidTargetException(
            message="Private IP addresses are not allowed unless explicitly permitted.",
            details=f"Received: {cleaned_ip}. Set allow_private=True to scan private ranges.",
        )

    return str(addr)


def validate_cidr(cidr: str, allow_private: bool = False) -> str:
    """
    Validate and clean a CIDR notation network string.

    Ensures the CIDR block is valid and rejects overly broad ranges that
    could overwhelm the scanner or be used for abuse.

    Args:
        cidr:          The CIDR notation string to validate (e.g. '192.168.1.0/24').
        allow_private: If True, allow private address ranges.

    Returns:
        str: The cleaned and validated CIDR string.

    Raises:
        InvalidTargetException: If the CIDR is invalid or the prefix length
                                is /8 or larger (too broad).
    """
    cleaned_cidr = cidr.strip()

    # Attempt to parse as an IPv4 network
    try:
        network = ipaddress.IPv4Network(cleaned_cidr, strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as parse_error:
        raise InvalidTargetException(
            message=f"'{cleaned_cidr}' is not a valid CIDR notation.",
            details=str(parse_error),
        )

    # Block overly broad ranges (/8 or larger = 16M+ addresses)
    if network.prefixlen < 9:
        raise InvalidTargetException(
            message=f"CIDR range /{network.prefixlen} is too broad. Maximum allowed is /9.",
            details=f"Received: {cleaned_cidr} covers {network.num_addresses:,} addresses.",
        )

    # Block loopback networks
    if network.is_loopback:
        raise InvalidTargetException(
            message="Loopback networks (127.0.0.0/8) are not allowed as scan targets.",
            details=f"Received: {cleaned_cidr}",
        )

    # Block private networks unless explicitly allowed
    if network.is_private and not allow_private:
        raise InvalidTargetException(
            message="Private CIDR ranges are not allowed unless explicitly permitted.",
            details=f"Received: {cleaned_cidr}. Set allow_private=True to scan private ranges.",
        )

    return str(network)


def validate_domain(domain: str) -> str:
    """
    Validate and clean a domain name string.

    Ensures the domain follows valid DNS naming conventions and blocks
    dangerous domains such as localhost variations and .local domains.

    Args:
        domain: The domain name string to validate.

    Returns:
        str: The cleaned and validated domain name (lowercased).

    Raises:
        InvalidTargetException: If the domain format is invalid or the domain
                                is a localhost variation or .local domain.
    """
    cleaned_domain = domain.strip().lower()

    # Block empty domains
    if not cleaned_domain:
        raise InvalidTargetException(
            message="Domain name cannot be empty.",
        )

    # Block localhost variations
    localhost_variations = [
        "localhost",
        "localhost.localdomain",
        "local",
        "127.0.0.1",
        "::1",
    ]
    if cleaned_domain in localhost_variations:
        raise InvalidTargetException(
            message="Localhost and its variations are not allowed as scan targets.",
            details=f"Received: {cleaned_domain}",
        )

    # Block .local domains (mDNS / Bonjour)
    if cleaned_domain.endswith(".local"):
        raise InvalidTargetException(
            message=".local domains (mDNS) are not allowed as scan targets.",
            details=f"Received: {cleaned_domain}",
        )

    # Block .localhost TLD
    if cleaned_domain.endswith(".localhost"):
        raise InvalidTargetException(
            message=".localhost domains are not allowed as scan targets.",
            details=f"Received: {cleaned_domain}",
        )

    # Check domain length (max 253 characters per RFC 1035)
    if len(cleaned_domain) > 253:
        raise InvalidTargetException(
            message="Domain name exceeds the maximum length of 253 characters.",
            details=f"Received length: {len(cleaned_domain)}",
        )

    # Validate format with regex
    if not _DOMAIN_PATTERN.match(cleaned_domain):
        raise InvalidTargetException(
            message=f"'{cleaned_domain}' is not a valid domain name.",
            details="Domain must contain only alphanumeric characters, hyphens, and dots.",
        )

    return cleaned_domain


def validate_port_range(ports: str) -> str:
    """
    Validate and clean a port specification string.

    Accepts individual ports, comma-separated lists, and ranges using
    hyphen notation. All ports must be in the valid range 1–65535.

    Accepted formats:
        - Single port:      "80"
        - Comma-separated:  "80,443,8080"
        - Range:            "1-1000"
        - Mixed:            "80,443,8080-8090"

    Args:
        ports: The port specification string to validate.

    Returns:
        str: The cleaned and validated port specification string.

    Raises:
        InvalidTargetException: If the format is invalid or any port
                                is outside the range 1–65535.
    """
    cleaned_ports = ports.strip().replace(" ", "")

    # Block empty port strings
    if not cleaned_ports:
        raise InvalidTargetException(
            message="Port specification cannot be empty.",
        )

    # Validate format with regex
    if not _PORT_RANGE_PATTERN.match(cleaned_ports):
        raise InvalidTargetException(
            message=f"'{cleaned_ports}' is not a valid port specification.",
            details="Accepted formats: '80', '80,443', '1-1000', '80,443,8080-8090'.",
        )

    # Validate each port number is within range
    for segment in cleaned_ports.split(","):
        if "-" in segment:
            parts = segment.split("-")
            start_port = int(parts[0])
            end_port = int(parts[1])

            if start_port < 1 or start_port > 65535:
                raise InvalidTargetException(
                    message=f"Port {start_port} is out of range. Valid range: 1–65535.",
                )
            if end_port < 1 or end_port > 65535:
                raise InvalidTargetException(
                    message=f"Port {end_port} is out of range. Valid range: 1–65535.",
                )
            if start_port > end_port:
                raise InvalidTargetException(
                    message=f"Invalid port range: {start_port}–{end_port}. Start must be ≤ end.",
                )
        else:
            port_number = int(segment)
            if port_number < 1 or port_number > 65535:
                raise InvalidTargetException(
                    message=f"Port {port_number} is out of range. Valid range: 1–65535.",
                )

    return cleaned_ports


def validate_target(target: str, allow_private: bool = False) -> Tuple[str, str]:
    """
    Auto-detect the type of a scan target and validate it accordingly.

    Determines whether the target is an IPv4 address, a CIDR block,
    or a domain name, then delegates to the appropriate validator.

    Args:
        target:        The scan target string to validate.
        allow_private: If True, allow private IP addresses and CIDR ranges.

    Returns:
        tuple[str, str]: A tuple of (cleaned_target, target_type) where
                         target_type is one of 'ip', 'cidr', or 'domain'.

    Raises:
        InvalidTargetException: If the target cannot be identified as a valid
                                IP, CIDR, or domain, or if validation fails.
    """
    cleaned_target = target.strip()

    # Block empty targets
    if not cleaned_target:
        raise InvalidTargetException(
            message="Scan target cannot be empty.",
        )

    # Strip URL protocol prefix (http:// or https://) and extract hostname
    if cleaned_target.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(cleaned_target)
        hostname = parsed.hostname or ""
        if not hostname:
            raise InvalidTargetException(
                message="Could not extract a hostname from the provided URL.",
            )
        cleaned_target = hostname

    # First, sanitize the input string
    cleaned_target = sanitize_string(cleaned_target)

    # Try CIDR notation first (contains '/')
    if "/" in cleaned_target:
        validated = validate_cidr(cleaned_target, allow_private=allow_private)
        return validated, "cidr"

    # Try IPv4 address
    try:
        validated = validate_ip_address(cleaned_target, allow_private=allow_private)
        return validated, "ip"
    except InvalidTargetException:
        pass  # Not an IP — try domain next

    # Try domain name
    validated = validate_domain(cleaned_target)
    return validated, "domain"


def sanitize_string(text: str) -> str:
    """
    Remove dangerous characters from a string to prevent shell injection.

    Strips characters that could be used to break out of shell commands
    or inject additional commands when passed to subprocess calls.

    The following characters are removed:
        ; | & $ ` \\ > < " ' { } ( ) !

    Args:
        text: The raw input string to sanitize.

    Returns:
        str: The sanitized string with all dangerous characters removed.

    Raises:
        InvalidTargetException: If the string is empty after sanitization.
    """
    sanitized = text.strip()

    # Remove each dangerous character
    for char in _DANGEROUS_CHARS:
        sanitized = sanitized.replace(char, "")

    # Remove any remaining non-printable characters
    sanitized = "".join(
        char for char in sanitized
        if char.isprintable()
    )

    # Ensure the result is not empty after sanitization
    sanitized = sanitized.strip()
    if not sanitized:
        raise InvalidTargetException(
            message="Input became empty after removing dangerous characters.",
            details=f"Original input contained only dangerous or non-printable characters.",
        )

    return sanitized
