# ─────────────────────────────────────────
# Netrix — Models Package
# Purpose: Centralised import of every ORM model so that
#          SQLAlchemy's metadata registry is fully populated.
#
# IMPORT ORDER MATTERS — parent tables (no FKs or only
# self-referencing FKs) must be imported before child tables
# that declare foreign keys pointing at them.
#
# Current dependency chain:
#   User  →  Scan  →  Host  →  Port  →  Vulnerability
#                  →  Report
# ─────────────────────────────────────────

from app.models.user import User                        # noqa: F401
from app.models.scan import Scan                        # noqa: F401
from app.models.host import Host                        # noqa: F401
from app.models.port import Port                        # noqa: F401
from app.models.vulnerability import Vulnerability      # noqa: F401
from app.models.report import Report                    # noqa: F401

__all__ = [
    "User",
    "Scan",
    "Host",
    "Port",
    "Vulnerability",
    "Report",
]
