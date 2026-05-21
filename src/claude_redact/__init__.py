"""Claude reverse proxy with Presidio-based secret masking.

The public surface is the FastAPI `app` re-exported here, so you can run
`uvicorn claude_redact:app` or `python -m claude_redact`.
"""
from dotenv import find_dotenv as _find_dotenv, load_dotenv as _load_dotenv

# Load .env before any module reads os.environ. `usecwd=True` walks up from
# the user's working directory rather than from the installed package path,
# so the dotfile is picked up whether the package is editable or installed.
_load_dotenv(_find_dotenv(usecwd=True))

from claude_redact.logging_config import configure as _configure_logging  # noqa: E402

_configure_logging()

from claude_redact.app import app  # noqa: E402  — depends on env + logging setup above

__all__ = ["app"]
