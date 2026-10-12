"""Background jobs: end temporary access on time (and, if enabled, check for permission drift)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .config import get_settings
from .services import drift, expiring

log = logging.getLogger("pgac.scheduler")


async def scheduler_loop(app: Any, interval: int) -> None:
    await app.state.store.run(expiring.db_reset_stuck)  # a crash mid-run must not strand a schedule
    drift_every = get_settings().drift_check_interval_minutes * 60
    last_drift = 0.0
    while True:
        try:
            n = await expiring.run_due(app)
            if n:
                log.info("Ended %d temporary access entr%s", n, "y" if n == 1 else "ies")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("Temporary-access job failed")
        if drift_every and asyncio.get_running_loop().time() - last_drift >= drift_every:
            last_drift = asyncio.get_running_loop().time()
            try:
                found = await drift.check_baselines(app)
                if found:
                    log.warning("Permission drift detected against %d baseline snapshot(s)", found)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Drift check failed")
        await asyncio.sleep(max(5, interval))
