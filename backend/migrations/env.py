# ─────────────────────────────────────────
# Netrix — Alembic Migrations Environment
# Purpose: Configure Alembic to auto-detect model changes and
#          generate/run migrations against the MySQL database.
# ─────────────────────────────────────────

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import get_settings
from app.database.session import Base

# ── Import every model so that Base.metadata is fully populated ──
# ORDER MATTERS — see app/models/__init__.py for the dependency chain
from app.models.user import User                        # noqa: F401
from app.models.scan import Scan                        # noqa: F401
from app.models.host import Host                        # noqa: F401
from app.models.port import Port                        # noqa: F401
from app.models.vulnerability import Vulnerability      # noqa: F401
from app.models.report import Report                    # noqa: F401

# ── Alembic Config ───────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# ── Override sqlalchemy.url with the runtime DATABASE_URL ────────
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)


# ─────────────────────────────────────────
# Offline mode — generates SQL without a live connection
# ─────────────────────────────────────────
def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Configures the context with just a URL (no Engine). Alembic
    emits the generated SQL to stdout instead of executing it.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ─────────────────────────────────────────
# Online mode — executes against a live database
# ─────────────────────────────────────────
def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    Creates an Engine from the configuration and associates a
    connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ─────────────────────────────────────────
# Async online mode — for aiomysql driver
# ─────────────────────────────────────────
async def run_async_migrations() -> None:
    """
    Run migrations using the async engine (aiomysql).

    This is an alternative to ``run_migrations_online`` for
    projects that exclusively use async drivers.
    """
    async_url = settings.DATABASE_URL.replace(
        "mysql+pymysql://", "mysql+aiomysql://"
    )
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = async_url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def do_run_migrations(connection) -> None:
    """Helper: configure context and run migrations synchronously."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ─────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
