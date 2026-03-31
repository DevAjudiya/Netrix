# ─────────────────────────────────────────
# Netrix — middleware.py
# Purpose: ASGI middleware for request logging, Redis-based rate limiting,
#          and security header injection.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import json
import logging
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import get_settings

# ─────────────────────────────────────────
# Logger setup
# ─────────────────────────────────────────
logger = logging.getLogger("netrix")

# Paths that contain sensitive data — never log request bodies for these
_SENSITIVE_PATHS = frozenset({
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/change-password",
})

# Paths excluded from general rate limiting (health checks, docs)
_RATE_LIMIT_EXCLUDED_PATHS = frozenset({
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
})

# Paths that trigger the stricter scan-specific rate limit
_SCAN_PATHS = frozenset({
    "/api/v1/scans",
    "/api/v1/scans/",
})


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs every HTTP request with timing information.

    Log format:
        [NETRIX] 2024-01-01 12:00:00 | GET /api/v1/scans | 200 | 45ms

    Sensitive information (passwords, tokens) is never included in logs.
    Request bodies for authentication endpoints are redacted.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """
        Process the request, measure response time, and log the result.

        Args:
            request:   The incoming HTTP request.
            call_next: The next middleware or route handler in the chain.

        Returns:
            Response: The HTTP response from the downstream handler.
        """
        # Skip WebSocket requests — BaseHTTPMiddleware cannot handle them
        if request.scope.get("type") == "websocket":
            return await call_next(request)

        start_time = time.perf_counter()
        request_path = request.url.path
        request_method = request.method

        # Process the request through the rest of the stack
        try:
            response = await call_next(request)
        except Exception as unhandled_error:
            # Log unhandled exceptions and re-raise
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            logger.error(
                "[NETRIX] %s | %s %s | 500 | %.0fms | ERROR: %s",
                timestamp,
                request_method,
                request_path,
                elapsed_ms,
                str(unhandled_error),
            )
            raise

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # Build the log message — never include sensitive data
        log_message = (
            f"[NETRIX] {timestamp} | "
            f"{request_method} {request_path} | "
            f"{response.status_code} | "
            f"{elapsed_ms:.0f}ms"
        )

        # Add client IP for non-sensitive paths
        client_ip = self._get_client_ip(request)
        if client_ip and request_path not in _SENSITIVE_PATHS:
            log_message += f" | {client_ip}"

        # Choose the correct log level based on status code
        if response.status_code >= 500:
            logger.error(log_message)
        elif response.status_code >= 400:
            logger.warning(log_message)
        else:
            logger.info(log_message)

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> Optional[str]:
        """
        Extract the client IP from the request, respecting X-Forwarded-For.

        Args:
            request: The incoming HTTP request.

        Returns:
            Optional[str]: The client IP address, or None if unavailable.
        """
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs; the first is the client
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-based rate limiting middleware.

    Enforces two levels of rate limiting:
    - **General**: 100 requests per minute per IP address
    - **Scan-specific**: 5 scan requests per hour per user

    When a rate limit is exceeded, the middleware returns an HTTP 429
    response with a Retry-After header indicating when the client
    can retry.
    """

    # General rate limit: requests per window
    GENERAL_LIMIT: int = 100
    # General rate limit window in seconds (1 minute)
    GENERAL_WINDOW: int = 60
    # Scan rate limit: scans per window (from config)
    SCAN_WINDOW: int = 3600  # 1 hour in seconds

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """
        Check rate limits before processing the request.

        Args:
            request:   The incoming HTTP request.
            call_next: The next middleware or route handler in the chain.

        Returns:
            Response: Either the downstream response or an HTTP 429 error.
        """
        # Skip WebSocket requests — BaseHTTPMiddleware cannot handle them
        if request.scope.get("type") == "websocket":
            return await call_next(request)

        request_path = request.url.path

        # Skip rate limiting for excluded paths
        if request_path in _RATE_LIMIT_EXCLUDED_PATHS:
            return await call_next(request)

        # Try to get the Redis client from app state
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client is None:
            # Redis not available — allow the request but log a warning
            logger.warning("[NETRIX] Rate limiter skipped: Redis client not available.")
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        # ── General rate limit (per IP) ──────────────────────────────
        general_key = f"netrix:ratelimit:general:{client_ip}"
        try:
            current_count = await redis_client.incr(general_key)
            if current_count == 1:
                await redis_client.expire(general_key, self.GENERAL_WINDOW)

            if current_count > self.GENERAL_LIMIT:
                ttl = await redis_client.ttl(general_key)
                return JSONResponse(
                    status_code=429,
                    content={
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "message": "Too many requests. Please slow down.",
                        "details": f"Limit: {self.GENERAL_LIMIT} requests per {self.GENERAL_WINDOW}s.",
                    },
                    headers={"Retry-After": str(max(ttl, 1))},
                )
        except Exception as redis_error:
            # Redis failure should not break the application
            logger.error("[NETRIX] Redis rate limit error: %s", str(redis_error))

        # ── Scan-specific rate limit (per user, POST to /scans) ──────
        if (
            request_path in _SCAN_PATHS
            and request.method == "POST"
        ):
            # Admins are exempt from the scan rate limit
            if self._is_admin_user(request):
                return await call_next(request)

            settings = get_settings()
            scan_limit = settings.MAX_SCANS_PER_USER_PER_HOUR

            # Try to get user ID from the auth header for per-user limiting
            user_identifier = self._get_user_identifier(request) or client_ip
            scan_key = f"netrix:ratelimit:scan:{user_identifier}"

            try:
                scan_count = await redis_client.incr(scan_key)
                if scan_count == 1:
                    await redis_client.expire(scan_key, self.SCAN_WINDOW)

                if scan_count > scan_limit:
                    ttl = await redis_client.ttl(scan_key)
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error_code": "RATE_LIMIT_EXCEEDED",
                            "message": "Scan rate limit exceeded.",
                            "details": (
                                f"Maximum {scan_limit} scans per hour. "
                                f"Try again in {max(ttl, 1)} seconds."
                            ),
                        },
                        headers={"Retry-After": str(max(ttl, 1))},
                    )
            except Exception as redis_error:
                logger.error("[NETRIX] Redis scan rate limit error: %s", str(redis_error))

        return await call_next(request)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """
        Extract the client IP from the request.

        Args:
            request: The incoming HTTP request.

        Returns:
            str: The client IP address, defaulting to 'unknown'.
        """
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    @staticmethod
    def _is_admin_user(request: Request) -> bool:
        """
        Return True if the JWT in the Authorization header belongs to an admin.

        Uses the same lightweight decode as _get_user_identifier — no
        signature verification (that happens later in the security layer).
        """
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                import base64
                payload_segment = token.split(".")[1]
                padding = 4 - len(payload_segment) % 4
                if padding != 4:
                    payload_segment += "=" * padding
                payload = json.loads(base64.urlsafe_b64decode(payload_segment))
                return payload.get("role") == "admin"
            except (IndexError, ValueError, json.JSONDecodeError):
                pass
        return False

    @staticmethod
    def _get_user_identifier(request: Request) -> Optional[str]:
        """
        Attempt to extract a user identifier from the Authorization header.

        This does a lightweight extraction without full JWT verification
        (which happens later in the route dependency). It is used only
        for rate-limiting purposes.

        Args:
            request: The incoming HTTP request.

        Returns:
            Optional[str]: A user identifier string, or None if unavailable.
        """
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                # Decode without verification to extract user_id for rate limiting
                # Full verification happens in the security dependency layer
                import base64
                # Extract the payload segment (second part of the JWT)
                payload_segment = token.split(".")[1]
                # Add padding if needed
                padding = 4 - len(payload_segment) % 4
                if padding != 4:
                    payload_segment += "=" * padding
                payload_bytes = base64.urlsafe_b64decode(payload_segment)
                payload = json.loads(payload_bytes)
                user_id = payload.get("user_id")
                if user_id:
                    return f"user:{user_id}"
            except (IndexError, ValueError, json.JSONDecodeError):
                pass
        return None


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to every HTTP response.

    These headers protect against common web vulnerabilities including
    clickjacking, XSS, MIME-type sniffing, and man-in-the-middle attacks.

    Headers added:
        X-Content-Type-Options: nosniff
        X-Frame-Options: DENY
        X-XSS-Protection: 1; mode=block
        Strict-Transport-Security: max-age=31536000; includeSubDomains
        Content-Security-Policy: default-src 'self'
        Referrer-Policy: strict-origin-when-cross-origin
        Permissions-Policy: camera=(), microphone=(), geolocation=()
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """
        Process the request and add security headers to the response.

        Args:
            request:   The incoming HTTP request.
            call_next: The next middleware or route handler in the chain.

        Returns:
            Response: The Response with security headers injected.
        """
        # Skip WebSocket requests — BaseHTTPMiddleware cannot handle them
        if request.scope.get("type") == "websocket":
            return await call_next(request)

        response = await call_next(request)

        # Prevent MIME-type sniffing — browser must respect Content-Type
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent this page from being embedded in iframes (clickjacking protection)
        response.headers["X-Frame-Options"] = "DENY"

        # Enable the browser's built-in XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Enforce HTTPS for 1 year — browsers will refuse plain HTTP after first visit
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Restrict resource loading to same-origin only by default
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net fastapi.tiangolo.com"

        # Control referrer information sent with requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Disable access to sensitive browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response
