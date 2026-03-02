# ─────────────────────────────────────────
# Netrix — Scan Schemas
# Purpose: Pydantic models for scan creation, status
#          tracking, and paginated list responses.
# ─────────────────────────────────────────

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ─────────────────────────────────────────
# Create
# ─────────────────────────────────────────
class ScanCreate(BaseModel):
    """Schema for initiating a new network scan."""

    target: str
    scan_type: str = "full"
    custom_args: Optional[str] = None
    custom_ports: Optional[str] = None

    @field_validator("target")
    @classmethod
    def validate_target_not_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Scan target must not be empty")
        return stripped

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, value: str) -> str:
        allowed = {"quick", "stealth", "full", "aggressive", "vulnerability", "custom"}
        if value not in allowed:
            raise ValueError(f"scan_type must be one of: {', '.join(sorted(allowed))}")
        return value


# ─────────────────────────────────────────
# Response (full scan record)
# ─────────────────────────────────────────
class ScanResponse(BaseModel):
    """Complete scan data returned by the API."""

    id: int
    scan_id: str
    user_id: int
    target: str
    target_type: str
    scan_type: str
    scan_args: Optional[str] = None
    status: str
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    total_hosts: int
    hosts_up: int
    hosts_down: int
    nmap_version: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# Status (lightweight progress update)
# ─────────────────────────────────────────
class ScanStatus(BaseModel):
    """Lightweight scan status update for polling endpoints."""

    scan_id: str
    status: str
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# Paginated list
# ─────────────────────────────────────────
class ScanList(BaseModel):
    """Paginated list of scans."""

    scans: List[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
