"""Logging setup for the `claude_proxy.*` logger tree.

Configured via `CLAUDE_PROXY_LOG_LEVEL` (default INFO). We attach our own
handler and disable propagation, so uvicorn's access/error loggers are
untouched and we don't interfere with anyone embedding the package.
"""
from __future__ import annotations

import logging
import os


def configure() -> None:
    level = os.environ.get("CLAUDE_PROXY_LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("claude_proxy")
    if logger.handlers:
        # Already configured — keep it idempotent across re-imports / re-entry.
        logger.setLevel(level)
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
