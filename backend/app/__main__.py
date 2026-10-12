"""``python -m app`` — start the server using HOST / PORT / WORKERS / LOG_LEVEL from the environment."""

import asyncio
import sys

import uvicorn

from .config import get_settings

if __name__ == "__main__":
    loop = "auto"
    if sys.platform == "win32":
        # psycopg's async API cannot use the Proactor loop that uvicorn picks on Windows, so let
        # asyncio create the loop from the (selector) policy instead.
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        loop = "none"
    s = get_settings()
    uvicorn.run(
        "app.main:app",
        host=s.host,
        port=s.port,
        workers=s.workers,
        log_level=s.log_level.lower(),
        loop=loop,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
