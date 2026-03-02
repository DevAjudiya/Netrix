# ─────────────────────────────────────────
# Netrix — exceptions.py
# Purpose: Custom exception hierarchy for structured error handling
#          across the entire Netrix application.
# Author: Netrix Development Team
# ─────────────────────────────────────────

from typing import Optional


class NetrixBaseException(Exception):
    """
    Base exception for all Netrix application errors.

    Every custom exception inherits from this class so that the global
    exception handler can catch any Netrix-specific error uniformly and
    return a consistent JSON error response to the client.

    Attributes:
        message:     Human-readable description of the error.
        status_code: HTTP status code to return to the client.
        error_code:  Machine-readable error identifier string.
    """

    def __init__(
        self,
        message: str = "An unexpected error occurred in Netrix.",
        status_code: int = 500,
        error_code: str = "NETRIX_ERROR",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize the base Netrix exception.

        Args:
            message:     Human-readable error description.
            status_code: HTTP status code for the response.
            error_code:  Machine-readable error identifier.
            details:     Optional additional context about the error.
        """
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return a formatted string representation of the exception."""
        base = f"[{self.error_code}] {self.message} (HTTP {self.status_code})"
        if self.details:
            base += f" — {self.details}"
        return base

    def to_dict(self) -> dict:
        """
        Serialize the exception into a dictionary suitable for JSON responses.

        Returns:
            dict: A dictionary with error_code, message, status_code, and details.
        """
        return {
            "error_code": self.error_code,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
        }


# ─────────────────────────────────────────
# Scan-related exceptions
# ─────────────────────────────────────────

class ScanNotFoundException(NetrixBaseException):
    """
    Raised when a requested scan cannot be found in the database.

    This typically occurs when a client provides a scan ID that does not
    exist or has been deleted.
    """

    def __init__(
        self,
        message: str = "The requested scan was not found.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize ScanNotFoundException.

        Args:
            message: Human-readable error description.
            details: Optional additional context (e.g. the scan ID).
        """
        super().__init__(
            message=message,
            status_code=404,
            error_code="SCAN_NOT_FOUND",
            details=details,
        )


class ScanAlreadyRunningException(NetrixBaseException):
    """
    Raised when a user attempts to start a scan that is already in progress.

    Prevents duplicate scans against the same target from consuming
    unnecessary resources.
    """

    def __init__(
        self,
        message: str = "A scan is already running for the specified target.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize ScanAlreadyRunningException.

        Args:
            message: Human-readable error description.
            details: Optional additional context (e.g. existing scan ID).
        """
        super().__init__(
            message=message,
            status_code=409,
            error_code="SCAN_ALREADY_RUNNING",
            details=details,
        )


# ─────────────────────────────────────────
# Validation exceptions
# ─────────────────────────────────────────

class InvalidTargetException(NetrixBaseException):
    """
    Raised when a scan target fails validation.

    A target is invalid if it:
    - Is not a valid IPv4 address, CIDR block, or domain name
    - Points to a loopback address (127.x.x.x)
    - Points to 0.0.0.0
    - Uses an overly broad CIDR range (/8 or larger)
    - Contains shell injection characters
    - Is a localhost variation or .local domain
    """

    def __init__(
        self,
        message: str = "The provided scan target is invalid.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize InvalidTargetException.

        Args:
            message: Human-readable error description.
            details: Optional specifics about why the target is invalid.
        """
        super().__init__(
            message=message,
            status_code=422,
            error_code="INVALID_TARGET",
            details=details,
        )


# ─────────────────────────────────────────
# Authorization exceptions
# ─────────────────────────────────────────

class InsufficientPermissionsException(NetrixBaseException):
    """
    Raised when a user attempts an action they are not authorized to perform.

    For example, a regular user trying to access admin-only endpoints or
    another user's scan results.
    """

    def __init__(
        self,
        message: str = "You do not have permission to perform this action.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize InsufficientPermissionsException.

        Args:
            message: Human-readable error description.
            details: Optional context about the required permission.
        """
        super().__init__(
            message=message,
            status_code=403,
            error_code="INSUFFICIENT_PERMISSIONS",
            details=details,
        )


class AuthenticationException(NetrixBaseException):
    """
    Raised when authentication fails.

    This covers invalid credentials, expired tokens, malformed tokens,
    and inactive user accounts.
    """

    def __init__(
        self,
        message: str = "Authentication failed. Please check your credentials.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize AuthenticationException.

        Args:
            message: Human-readable error description.
            details: Optional context (e.g. 'Token expired', 'User inactive').
        """
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_FAILED",
            details=details,
        )


# ─────────────────────────────────────────
# External service exceptions
# ─────────────────────────────────────────

class CVEFetchException(NetrixBaseException):
    """
    Raised when fetching CVE data from the NVD API or the offline
    database fails.

    This can be caused by network issues, NVD API rate limiting, or
    a missing/corrupt offline CVE database file.
    """

    def __init__(
        self,
        message: str = "Failed to fetch CVE data. The vulnerability database is temporarily unavailable.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize CVEFetchException.

        Args:
            message: Human-readable error description.
            details: Optional context (e.g. HTTP status from NVD).
        """
        super().__init__(
            message=message,
            status_code=503,
            error_code="CVE_FETCH_FAILED",
            details=details,
        )


# ─────────────────────────────────────────
# Report exceptions
# ─────────────────────────────────────────

class ReportGenerationException(NetrixBaseException):
    """
    Raised when report generation (PDF, HTML, CSV, or JSON) fails.

    Possible causes include template errors, disk write failures,
    or missing scan data required for the report.
    """

    def __init__(
        self,
        message: str = "Failed to generate report. Please try again.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize ReportGenerationException.

        Args:
            message: Human-readable error description.
            details: Optional context (e.g. which format failed).
        """
        super().__init__(
            message=message,
            status_code=500,
            error_code="REPORT_GENERATION_FAILED",
            details=details,
        )


# ─────────────────────────────────────────
# Database exceptions
# ─────────────────────────────────────────

class DatabaseException(NetrixBaseException):
    """
    Raised when a database operation fails unexpectedly.

    This covers connection errors, query failures, integrity violations,
    and migration issues.
    """

    def __init__(
        self,
        message: str = "A database error occurred. Please try again later.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize DatabaseException.

        Args:
            message: Human-readable error description.
            details: Optional context (e.g. the SQLAlchemy error message).
        """
        super().__init__(
            message=message,
            status_code=500,
            error_code="DATABASE_ERROR",
            details=details,
        )


# ─────────────────────────────────────────
# Rate limiting exceptions
# ─────────────────────────────────────────

class RateLimitExceededException(NetrixBaseException):
    """
    Raised when a user or IP address exceeds the configured rate limit.

    The client should wait until the rate limit window resets before
    retrying the request.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded. Please slow down and try again later.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize RateLimitExceededException.

        Args:
            message: Human-readable error description.
            details: Optional context (e.g. retry-after time).
        """
        super().__init__(
            message=message,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details=details,
        )


# ─────────────────────────────────────────
# Report exceptions
# ─────────────────────────────────────────

class ReportGenerationException(NetrixBaseException):
    """
    Raised when a report cannot be generated or accessed.

    Covers file-system errors, missing reports, invalid formats,
    and scan-state precondition failures.
    """

    def __init__(
        self,
        message: str = "Report generation failed.",
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize ReportGenerationException.

        Args:
            message: Human-readable error description.
            details: Optional specifics about the failure.
        """
        super().__init__(
            message=message,
            status_code=500,
            error_code="REPORT_GENERATION_ERROR",
            details=details,
        )
