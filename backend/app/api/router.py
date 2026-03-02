# ─────────────────────────────────────────
# Netrix — router.py
# Purpose: Central API router that aggregates all v1 endpoint routers.
# Author: Netrix Development Team
# ─────────────────────────────────────────

from fastapi import APIRouter

from app.api.v1 import auth, scans, reports, vulnerabilities, hosts, dashboard

api_router = APIRouter()

# ── v1 endpoint routers ─────────────────────────────────────────────
api_router.include_router(
    auth.router,
    prefix="/v1/auth",
    tags=["Authentication"],
)
api_router.include_router(
    scans.router,
    prefix="/v1/scans",
    tags=["Scans"],
)
api_router.include_router(
    reports.router,
    prefix="/v1/reports",
    tags=["Reports"],
)
api_router.include_router(
    vulnerabilities.router,
    prefix="/v1/vulnerabilities",
    tags=["Vulnerabilities"],
)
api_router.include_router(
    hosts.router,
    prefix="/v1/hosts",
    tags=["Hosts"],
)
api_router.include_router(
    dashboard.router,
    prefix="/v1/dashboard",
    tags=["Dashboard"],
)
