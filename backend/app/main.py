# ─────────────────────────────────────────
# Netrix — main.py
# Purpose: FastAPI application entry point with middleware registration,
#          router mounting, and startup/shutdown lifecycle hooks.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.core.exceptions import NetrixBaseException
from app.core.middleware import (
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.router import api_router
from app.database.init_db import init_database

# ─────────────────────────────────────────
# Logging configuration
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netrix")

settings = get_settings()


# ─────────────────────────────────────────
# Application lifespan (startup + shutdown)
# ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application startup and shutdown lifecycle.

    On startup: initialize database tables and connect to Redis.
    On shutdown: close the Redis connection pool.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    # ── Startup ──────────────────────────────────────────────────────
    logger.info("[NETRIX] Starting Netrix v%s ...", settings.APP_VERSION)

    # Initialize database tables
    init_database()

    # Connect to Redis
    try:
        app.state.redis = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        await app.state.redis.ping()
        logger.info("[NETRIX] Redis connection established.")
    except Exception as redis_error:
        logger.warning("[NETRIX] Redis not available: %s", str(redis_error))
        app.state.redis = None

    logger.info("[NETRIX] Application started successfully.")

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    logger.info("[NETRIX] Shutting down...")
    if app.state.redis:
        await app.state.redis.close()
        logger.info("[NETRIX] Redis connection closed.")
    logger.info("[NETRIX] Shutdown complete.")


# ─────────────────────────────────────────
# FastAPI application instance
# ─────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Network Scanning & Vulnerability Assessment Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─────────────────────────────────────────
# Middleware registration (order matters — outermost first)
# ─────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────
# Global exception handler for all Netrix exceptions
# ─────────────────────────────────────────
@app.exception_handler(NetrixBaseException)
async def netrix_exception_handler(
    request: Request,
    exc: NetrixBaseException,
) -> JSONResponse:
    """
    Global handler for all Netrix custom exceptions.

    Returns a consistent JSON error response body.

    Args:
        request: The incoming HTTP request.
        exc:     The NetrixBaseException that was raised.

    Returns:
        JSONResponse: A structured JSON error response.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


# ─────────────────────────────────────────
# Router registration
# ─────────────────────────────────────────
app.include_router(api_router, prefix="/api")


# ─────────────────────────────────────────
# Health check endpoint
# ─────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """
    Health check endpoint used by Docker and load balancers.

    Returns:
        dict: A dictionary with status and version information.
    """
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
