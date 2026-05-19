"""Logging setup for the `claude_proxy.*` logger tree.

Two logger surfaces:
  - `claude_proxy` — protocol / control-flow tracing. Level set by
    `CLAUDE_PROXY_LOG_LEVEL` (default INFO). Safe to set to DEBUG when
    sharing a session, since it never emits plaintext.
  - `claude_proxy.values` — plaintext ↔ placeholder pairs. Off unless
    `CLAUDE_PROXY_LOG_VALUES` is truthy. Decoupled so that DEBUG-ing the
    proxy doesn't dump credentials into journald / a tail buffer.

We attach our own handler and disable propagation, so uvicorn's
access/error loggers are untouched and we don't interfere with anyone
embedding the package.
"""
from __future__ import annotations

import logging
import os

_TRUTHY = {"1", "true", "yes", "on"}


def configure() -> None:
    level = os.environ.get("CLAUDE_PROXY_LOG_LEVEL", "INFO").upper()
    values_on = os.environ.get("CLAUDE_PROXY_LOG_VALUES", "").lower() in _TRUTHY

    logger = logging.getLogger("claude_proxy")
    if logger.handlers:
        # Already configured — keep it idempotent across re-imports / re-entry.
        logger.setLevel(level)
        _configure_values_logger(values_on)
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
    _configure_values_logger(values_on)


def _configure_values_logger(enabled: bool) -> None:
    """Set `claude_proxy.values` level independently. Propagates to the
    parent handler so output formatting stays consistent; the level here
    is the gate."""
    vlog = logging.getLogger("claude_proxy.values")
    vlog.setLevel(logging.DEBUG if enabled else logging.WARNING)
