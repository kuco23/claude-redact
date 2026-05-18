"""Claude reverse proxy with Presidio-based secret masking.

The public surface is the FastAPI `app` re-exported here, so you can run
`uvicorn claude_proxy:app` or `python -m claude_proxy`.
"""
from claude_proxy.logging_config import configure as _configure_logging

_configure_logging()

from claude_proxy.app import app  # noqa: E402  — depends on logging setup above

__all__ = ["app"]
