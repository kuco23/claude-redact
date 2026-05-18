FROM mcr.microsoft.com/devcontainers/python:3.12

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Place venv outside workspace so it exists before the mount overlays /workspaces
ENV UV_PROJECT_ENVIRONMENT=/home/vscode/.venv

# Pre-install Python dependencies so the interpreter is available on attach
# Paths are relative to the build context (repo root, set in devcontainer.json)
COPY pyproject.toml uv.lock /tmp/build/
RUN cd /tmp/build && uv sync --no-install-project && rm -rf /tmp/build \
    && chown -R vscode:vscode /home/vscode/.venv

# Install Claude Code (requires Node, installed via devcontainer feature)
# Node is added via the devcontainer feature, so we install claude in postCreateCommand