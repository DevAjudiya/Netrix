# ─────────────────────────────────────────
# Netrix — Schemas Package
# Purpose: Centralised import of every Pydantic schema.
# ─────────────────────────────────────────

from app.schemas.user import (  # noqa: F401
    Token,
    TokenData,
    UserBase,
    UserCreate,
    UserLogin,
    UserResponse,
)
from app.schemas.scan import (  # noqa: F401
    ScanCreate,
    ScanList,
    ScanResponse,
    ScanStatus,
)
from app.schemas.host import (  # noqa: F401
    HostResponse,
    HostWithPorts,
    PortResponse,
)
from app.schemas.vulnerability import (  # noqa: F401
    VulnerabilityFilter,
    VulnerabilityList,
    VulnerabilityResponse,
)
from app.schemas.report import (  # noqa: F401
    ReportCreate,
    ReportResponse,
)

__all__ = [
    # User
    "UserBase",
    "UserCreate",
    "UserResponse",
    "UserLogin",
    "Token",
    "TokenData",
    # Scan
    "ScanCreate",
    "ScanResponse",
    "ScanStatus",
    "ScanList",
    # Host / Port
    "HostResponse",
    "HostWithPorts",
    "PortResponse",
    # Vulnerability
    "VulnerabilityResponse",
    "VulnerabilityFilter",
    "VulnerabilityList",
    # Report
    "ReportCreate",
    "ReportResponse",
]
