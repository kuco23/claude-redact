"""Entry point for `python -m claude_proxy`.

Host / port come from CLAUDE_PROXY_HOST / CLAUDE_PROXY_PORT (loaded from
.env if present). When launching via `uvicorn claude_proxy:app …` directly,
uvicorn's own CLI flags govern bind address — this module isn't invoked.
"""
import os

import uvicorn

from claude_proxy.app import app

uvicorn.run(
    app,
    host=os.environ.get("CLAUDE_PROXY_HOST", "127.0.0.1"),
    port=int(os.environ.get("CLAUDE_PROXY_PORT", "8888")),
)
