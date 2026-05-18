"""Entry point for `python -m claude_proxy`."""
import uvicorn

from claude_proxy.app import app

uvicorn.run(app, host="127.0.0.1", port=8888)
