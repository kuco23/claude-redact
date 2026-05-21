"""Entry point for `python -m claude_redact`.

Host / port come from CLAUDE_REDACT_HOST / CLAUDE_REDACT_PORT (loaded from
.env if present). When launching via `uvicorn claude_redact:app …` directly,
uvicorn's own CLI flags govern bind address — this module isn't invoked.
"""
import os

import uvicorn

from claude_redact.app import app

uvicorn.run(
    app,
    host=os.environ.get("CLAUDE_REDACT_HOST", "127.0.0.1"),
    port=int(os.environ.get("CLAUDE_REDACT_PORT", "8888")),
)
