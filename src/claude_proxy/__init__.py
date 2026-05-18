"""Claude reverse proxy with Presidio-based secret masking.

The public surface is the FastAPI `app` re-exported here, so you can run
`uvicorn claude_proxy:app` or `python -m claude_proxy`.
"""
from claude_proxy.app import app

__all__ = ["app"]
