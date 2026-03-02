# ─────────────────────────────────────────
# Netrix — Database Session
# Purpose: SQLAlchemy engine, session factory, and FastAPI dependency
#          with connection pooling, async support, and error handling.
# ─────────────────────────────────────────

import logging
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger("netrix")

# ─────────────────────────────────────────
# Settings
# ─────────────────────────────────────────
settings = get_settings()


# ─────────────────────────────────────────
# Declarative Base for all ORM models
# ─────────────────────────────────────────
class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models in the Netrix platform.

    Every model inherits from this class so that Alembic and
    ``create_all`` can discover the full schema automatically.
    """
    pass


# ─────────────────────────────────────────
# Synchronous Engine — MySQL 8.0 + PyMySQL
# ─────────────────────────────────────────
try:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_timeout=30,
        echo=settings.DEBUG,
        connect_args={
            "connect_timeout": 10,
        },
    )
    logger.info("[NETRIX] Synchronous database engine created — %s", settings.MYSQL_HOST)
except Exception as engine_error:
    logger.error("[NETRIX] Failed to create database engine: %s", str(engine_error))
    raise


# ─────────────────────────────────────────
# Asynchronous Engine — MySQL 8.0 + aiomysql
# ─────────────────────────────────────────
ASYNC_DATABASE_URL = settings.DATABASE_URL.replace(
    "mysql+pymysql://", "mysql+aiomysql://"
)

try:
    async_engine = create_async_engine(
        ASYNC_DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=settings.DEBUG,
    )
    logger.info("[NETRIX] Asynchronous database engine created — %s", settings.MYSQL_HOST)
except Exception as async_engine_error:
    logger.error("[NETRIX] Failed to create async database engine: %s", str(async_engine_error))
    raise


# ─────────────────────────────────────────
# Session Factories
# ─────────────────────────────────────────
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# ─────────────────────────────────────────
# Connection event listeners for logging
# ─────────────────────────────────────────
@event.listens_for(engine, "connect")
def _on_connect(dbapi_connection, connection_record):
    """Log every new physical database connection."""
    logger.debug("[NETRIX] New database connection established")


@event.listens_for(engine, "checkout")
def _on_checkout(dbapi_connection, connection_record, connection_proxy):
    """Log when a connection is checked out from the pool."""
    logger.debug("[NETRIX] Connection checked out from pool")


# ─────────────────────────────────────────
# Synchronous FastAPI dependency
# ─────────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session.

    The session is automatically committed on success and rolled back
    on any exception, then closed in the ``finally`` block so that
    connections are always returned to the pool.

    Yields:
        Session: A SQLAlchemy ORM session bound to the sync engine.
    """
    db: Session = SessionLocal()
    try:
        yield db
        db.commit()
    except SQLAlchemyError as db_error:
        db.rollback()
        logger.error("[NETRIX] Database error — rolled back: %s", str(db_error))
        raise
    finally:
        db.close()


# ─────────────────────────────────────────
# Asynchronous FastAPI dependency
# ─────────────────────────────────────────
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides an async transactional session.

    Yields:
        AsyncSession: A SQLAlchemy async ORM session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except SQLAlchemyError as db_error:
            await session.rollback()
            logger.error("[NETRIX] Async database error — rolled back: %s", str(db_error))
            raise
        finally:
            await session.close()


# ─────────────────────────────────────────
# Health-check utility
# ─────────────────────────────────────────
def check_database_connection() -> bool:
    """
    Verify that the database is reachable by executing a simple query.

    Returns:
        bool: True if the connection succeeds, False otherwise.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("[NETRIX] Database connection verified — healthy")
        return True
    except OperationalError as conn_error:
        logger.error("[NETRIX] Database connection failed: %s", str(conn_error))
        return False


async def check_async_database_connection() -> bool:
    """
    Verify async database reachability.

    Returns:
        bool: True if the connection succeeds, False otherwise.
    """
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("[NETRIX] Async database connection verified — healthy")
        return True
    except OperationalError as conn_error:
        logger.error("[NETRIX] Async database connection failed: %s", str(conn_error))
        return False
