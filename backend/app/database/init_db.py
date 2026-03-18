# ─────────────────────────────────────────
# Netrix — Database Initialization
# Purpose: Create all tables, seed the default admin user,
#          and provide a single init_database() entry point.
# ─────────────────────────────────────────

import logging
import time
from typing import Dict

from sqlalchemy import inspect, text

from app.config import get_settings
from app.core.security import get_password_hash
from app.database.session import Base, SessionLocal, engine

logger = logging.getLogger("netrix")

# ── Import every model so SQLAlchemy registers them ──────────────
# ORDER MATTERS — tables with foreign keys must be imported after
# the tables they reference.
from app.models.user import User                # noqa: F401, E402
from app.models.scan import Scan                # noqa: F401, E402
from app.models.host import Host                # noqa: F401, E402
from app.models.port import Port                # noqa: F401, E402
from app.models.vulnerability import Vulnerability  # noqa: F401, E402
from app.models.report import Report            # noqa: F401, E402


# ─────────────────────────────────────────
# DB readiness wait
# ─────────────────────────────────────────
def wait_for_db(max_retries: int = 30, delay: float = 2.0) -> None:
    """Retry DB connection until MySQL is accepting connections."""
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("[NETRIX] Database ready (attempt %d)", attempt)
            return
        except Exception as exc:
            logger.warning(
                "[NETRIX] Database not ready (attempt %d/%d): %s",
                attempt, max_retries, exc,
            )
            if attempt < max_retries:
                time.sleep(delay)
    raise RuntimeError("Database did not become available after %d attempts" % max_retries)


# ─────────────────────────────────────────
# Table Creation
# ─────────────────────────────────────────
def create_all_tables() -> None:
    """
    Create all database tables registered on ``Base.metadata``.

    Tables that already exist are silently skipped (``checkfirst=True``
    is the default behaviour of ``create_all``).  Every newly created
    table is logged individually.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    logger.info("[NETRIX] Starting database table creation …")

    Base.metadata.create_all(bind=engine)

    # Re-inspect to discover which tables were actually created
    new_tables = set(inspect(engine).get_table_names())
    created = new_tables - existing_tables

    if created:
        for table_name in sorted(created):
            logger.info("[NETRIX] ✓ Created table: %s", table_name)
    else:
        logger.info("[NETRIX] All tables already exist — nothing to create")

    logger.info(
        "[NETRIX] Database schema ready — %d table(s) total",
        len(new_tables),
    )


# ─────────────────────────────────────────
# Default Admin Seeding
# ─────────────────────────────────────────
def create_default_admin() -> bool:
    """
    Ensure that a default administrator account exists.

    If the ``netrix_admin`` user is not found in the ``users`` table a
    new record is inserted with:

    * **username**: ``netrix_admin``
    * **email**: ``admin@netrix.local``
    * **password**: ``Admin@Netrix123`` (bcrypt-hashed)
    * **role**: ``admin``

    Returns:
        bool: ``True`` if the admin was created, ``False`` if it already
              existed.
    """
    db = SessionLocal()
    try:
        existing_admin = (
            db.query(User)
            .filter(User.username == "netrix_admin")
            .first()
        )

        if existing_admin is not None:
            logger.info(
                "[NETRIX] Default admin already exists (ID: %d)",
                existing_admin.id,
            )
            return False

        admin_user = User(
            username="netrix_admin",
            email="admin@netrix.local",
            password_hash=get_password_hash("Admin@Netrix123"),
            role="admin",
            is_active=True,
        )

        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        logger.info(
            "[NETRIX] ✓ Default admin created — username: netrix_admin, "
            "ID: %d",
            admin_user.id,
        )
        return True

    except Exception as seed_error:
        db.rollback()
        # IntegrityError means another worker already created the admin
        from sqlalchemy.exc import IntegrityError
        if isinstance(seed_error, IntegrityError):
            logger.info("[NETRIX] Default admin already created by another worker")
            return False
        logger.error(
            "[NETRIX] Failed to create default admin: %s",
            str(seed_error),
        )
        raise
    finally:
        db.close()


# ─────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────
def init_database() -> Dict[str, bool]:
    """
    Initialise the database in two steps:

    1. Create all tables that do not yet exist.
    2. Seed the default ``netrix_admin`` administrator account.

    This function is designed to be called once during application
    startup (e.g. inside the FastAPI lifespan handler).

    Returns:
        dict: ``{"tables_created": bool, "admin_created": bool}``
              indicating what work was performed.
    """
    logger.info("[NETRIX] ═══ Database initialisation started ═══")

    result: Dict[str, bool] = {
        "tables_created": False,
        "admin_created": False,
    }

    try:
        # Step 0 — wait for MySQL to accept connections
        wait_for_db()

        # Step 1 — schema
        create_all_tables()
        result["tables_created"] = True

        # Step 2 — seed data
        result["admin_created"] = create_default_admin()

    except Exception as init_error:
        logger.error(
            "[NETRIX] Database initialisation failed: %s",
            str(init_error),
        )
        raise

    logger.info(
        "[NETRIX] ═══ Database initialisation complete ═══  "
        "tables_created=%s  admin_created=%s",
        result["tables_created"],
        result["admin_created"],
    )
    return result


def drop_all_tables() -> None:
    """
    Drop every table managed by the ORM.

    .. danger::
        This is destructive — use only in development/test environments.
    """
    logger.warning("[NETRIX] Dropping ALL tables — this is destructive!")
    Base.metadata.drop_all(bind=engine)
    logger.info("[NETRIX] All tables dropped successfully")
