# ─────────────────────────────────────────
# Netrix — Host Schemas
# Purpose: Pydantic models for host and port data responses.
# ─────────────────────────────────────────

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


# ─────────────────────────────────────────
# Port
# ─────────────────────────────────────────
class PortResponse(BaseModel):
    """Schema for a single discovered port."""

    id: int
    host_id: int
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe: Optional[str] = None
    nse_output: Optional[Dict[str, Any]] = None
    is_critical_port: bool
    is_web_port: bool
    is_database_port: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# Host (basic)
# ─────────────────────────────────────────
class HostResponse(BaseModel):
    """Schema for a single discovered host (without port details)."""

    id: int
    scan_id: int
    ip_address: str
    hostname: Optional[str] = None
    status: str
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    os_family: Optional[str] = None
    os_generation: Optional[str] = None
    os_cpe: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    uptime: Optional[str] = None
    tcp_sequence: Optional[str] = None
    risk_score: int
    risk_level: str
    risk_level_color: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# Host with ports (nested)
# ─────────────────────────────────────────
class HostWithPorts(HostResponse):
    """Host response that also embeds the full list of ports."""

    ports: List[PortResponse] = []
