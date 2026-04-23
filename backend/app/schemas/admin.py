# ─────────────────────────────────────────
# Netrix — Admin Schemas
# Purpose: Pydantic models for admin user-management endpoints.
# ─────────────────────────────────────────

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class AdminUserResponse(BaseModel):
    """User record as seen by an admin — includes ban fields and scan count."""

    id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_banned: bool
    ban_reason: Optional[str] = None
    scan_count: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AdminUserCreate(BaseModel):
    """Body for POST /admin/users — admin creates a new account."""

    username: str
    email: str
    password: str
    role: str = "analyst"   # "admin" | "analyst"


class AdminUserUpdate(BaseModel):
    """Fields an admin may change on any user account."""

    role: Optional[str] = None        # "admin" | "analyst"
    is_active: Optional[bool] = None
    is_banned: Optional[bool] = None
    ban_reason: Optional[str] = None


class AdminUserListResponse(BaseModel):
    """Paginated list of users returned by GET /admin/users."""

    users: List[AdminUserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AdminStats(BaseModel):
    """Platform-wide statistics for the admin summary cards."""

    # User counts
    total_users: int
    active_users: int
    banned_users: int
    admins: int
    analysts: int
    # Scan / report counts
    total_scans_all_users: int = 0
    scans_today: int = 0
    reports_generated: int = 0
    # CVE database
    cve_count: int = 0
    last_cve_sync: Optional[datetime] = None


class PasswordResetResponse(BaseModel):
    """Response after an admin resets a user's password."""

    message: str
    username: str
    temp_password: str


# ── Scan oversight schemas ────────────────────────────────────────────────


class AdminScanResponse(BaseModel):
    """Scan record as seen by an admin — includes owner info."""

    id: int
    scan_id: str
    target: str
    target_type: str
    scan_type: str
    status: str
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    total_hosts: int = 0
    hosts_up: int = 0
    error_message: Optional[str] = None
    # Flattened owner info
    user_id: int
    username: str
    email: str

    model_config = ConfigDict(from_attributes=True)


class AdminScanListResponse(BaseModel):
    """Paginated list of scans returned by GET /admin/scans."""

    scans: List[AdminScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ── Audit log schemas ─────────────────────────────────────────────────────


class AdminLogResponse(BaseModel):
    """Single audit log entry as seen by an admin."""

    id: int
    action: str
    ip_address: Optional[str] = None
    details: Optional[dict] = None
    created_at: datetime
    # Flattened user info (None when user_id is NULL)
    user_id: Optional[int] = None
    username: Optional[str] = None
    email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AdminLogListResponse(BaseModel):
    """Paginated list of audit log entries."""

    logs: List[AdminLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ── System health schemas ──────────────────────────────────────────────────


class AdminHealthResponse(BaseModel):
    """Real-time system health snapshot returned by GET /admin/health."""

    mysql_status: bool
    redis_status: bool
    nmap_status: bool
    active_scans: int
    queue_depth: int
    failed_scans_24h: int
    cpu_percent: float
    memory_percent: float


class SystemMetricPoint(BaseModel):
    """Single time-series data point for a system metric."""

    recorded_at: datetime
    cpu_percent: float
    memory_percent: float

    model_config = ConfigDict(from_attributes=True)


class AdminMetricsResponse(BaseModel):
    """Time-series metrics for the last N hours."""

    hours: int
    points: List[SystemMetricPoint]


# ── CVE control schemas ────────────────────────────────────────────────────


class CVEStatusResponse(BaseModel):
    """Current state of the offline CVE database and NVD connectivity."""

    total_cves: int
    last_sync: Optional[datetime] = None
    cves_added_last_sync: int = 0
    nvd_api_online: bool
    nvd_last_checked: Optional[datetime] = None
    nvd_check_pending: bool = False
    sync_in_progress: bool


class CVESyncResponse(BaseModel):
    """Acknowledgement that a CVE sync has been queued."""

    message: str
    status: str


class CVERematchResponse(BaseModel):
    """Acknowledgement that a CVE rematch has been queued."""

    message: str
    status: str


class CVEEntry(BaseModel):
    """Single CVE record from the offline database."""

    cve_id: str
    title: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: str
    published_date: str
    affected: List[str]
    remediation: str
    references: List[str]


class CVEListResponse(BaseModel):
    """Paginated list of CVEs from the offline database."""

    cves: List[CVEEntry]
    total: int
    page: int
    page_size: int
    total_pages: int
