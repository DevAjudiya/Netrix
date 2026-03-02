# ─────────────────────────────────────────
# Netrix — Report Schemas
# Purpose: Pydantic models for report creation requests
#          and response payloads.
# ─────────────────────────────────────────

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ─────────────────────────────────────────
# Create
# ─────────────────────────────────────────
class ReportCreate(BaseModel):
    """Schema for requesting a new report generation."""

    scan_id: int
    format: str

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        allowed = {"pdf", "json", "csv", "html"}
        if value.lower() not in allowed:
            raise ValueError(f"Report format must be one of: {', '.join(sorted(allowed))}")
        return value.lower()


# ─────────────────────────────────────────
# Response
# ─────────────────────────────────────────
class ReportResponse(BaseModel):
    """Complete report data returned by the API."""

    id: int
    scan_id: int
    user_id: int
    report_name: str
    format: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_size_readable: str
    total_hosts: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    generated_at: datetime
    download_count: int
    last_downloaded: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
