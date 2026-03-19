# ─────────────────────────────────────────
# Netrix — Background Metrics Task
# Purpose: Asyncio loop that snapshots system health every 5 minutes
#          and prunes records older than 7 days.
# ─────────────────────────────────────────

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.database.session import SessionLocal, engine
from app.models.system_metric import SystemMetric
from app.services.health_service import (
    check_mysql,
    check_redis,
    check_nmap,
    get_redis_queue_depth,
    get_cpu_percent,
    get_memory_percent,
)

logger = logging.getLogger("netrix")

COLLECT_INTERVAL = 300   # seconds (5 minutes)
RETAIN_DAYS = 7


async def _collect_and_store(app_state) -> None:
    """Gather one snapshot of system metrics and persist it."""
    redis_client = getattr(app_state, "redis", None)

    mysql_ok, redis_ok, nmap_ok, queue_depth = await asyncio.gather(
        check_mysql(engine),
        check_redis(redis_client),
        check_nmap(),
        get_redis_queue_depth(redis_client),
    )

    cpu = get_cpu_percent()
    memory = get_memory_percent()

    # Active scans count from ScanManager
    try:
        from app.services.scan_manager import get_scan_manager_instance
        sm = get_scan_manager_instance()
        active_scans = len(sm.active_scans)
    except Exception:
        active_scans = 0

    db = SessionLocal()
    try:
        metric = SystemMetric(
            cpu_percent=cpu,
            memory_percent=memory,
            redis_status=redis_ok,
            mysql_status=mysql_ok,
            nmap_status=nmap_ok,
            active_scans=active_scans,
            queue_depth=queue_depth,
            recorded_at=datetime.now(timezone.utc),
        )
        db.add(metric)

        # Prune records older than RETAIN_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETAIN_DAYS)
        db.query(SystemMetric).filter(SystemMetric.recorded_at < cutoff).delete()

        db.commit()
        logger.debug("[METRICS] Snapshot stored — cpu=%.1f%% mem=%.1f%%", cpu, memory)
    except Exception as exc:
        db.rollback()
        logger.warning("[METRICS] Failed to store snapshot: %s", exc)
    finally:
        db.close()


async def metrics_loop(app_state) -> None:
    """Run forever, collecting metrics every COLLECT_INTERVAL seconds."""
    logger.info("[METRICS] Background metrics task started (interval=%ds)", COLLECT_INTERVAL)
    while True:
        try:
            await _collect_and_store(app_state)
        except Exception as exc:
            logger.warning("[METRICS] Unhandled error in metrics loop: %s", exc)
        await asyncio.sleep(COLLECT_INTERVAL)
