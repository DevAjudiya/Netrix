# ─────────────────────────────────────────
# Netrix — Health Service
# Purpose: Async helpers that probe MySQL, Redis, Nmap, and system resources.
# ─────────────────────────────────────────

import logging
import shutil
import subprocess

import psutil

logger = logging.getLogger("netrix")


async def check_mysql(engine) -> bool:
    """Ping MySQL by running a trivial synchronous query."""
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def check_redis(redis_client) -> bool:
    """Ping Redis asynchronously."""
    if redis_client is None:
        return False
    try:
        await redis_client.ping()
        return True
    except Exception:
        return False


async def check_nmap() -> bool:
    """Check that nmap is on PATH and returns a zero exit code."""
    try:
        path = shutil.which("nmap")
        if path is None:
            return False
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


async def get_redis_queue_depth(redis_client) -> int:
    """Return the length of the main scan task queue, or 0 if unavailable."""
    if redis_client is None:
        return 0
    try:
        depth = await redis_client.llen("netrix:scan_queue")
        return int(depth)
    except Exception:
        return 0


def get_cpu_percent() -> float:
    """Return current CPU utilisation (non-blocking, 0.1-second interval)."""
    return psutil.cpu_percent(interval=0.1)


def get_memory_percent() -> float:
    """Return current virtual-memory utilisation."""
    return psutil.virtual_memory().percent
