# syntax=docker/dockerfile:1.7

# --- Build stage -------------------------------------------------------------
# Resolve and install dependencies into a self-contained venv that we copy
# into the runtime image. Using uv (not pip) keeps the build deterministic
# from uv.lock and parallelizes wheel installs.
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

# Install runtime deps first (no project) so the layer is cacheable across
# source-only changes. --no-dev skips pytest et al.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Now install the project itself.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# --- Runtime stage -----------------------------------------------------------
FROM python:3.13-slim AS runtime

# Non-root user. UID/GID 10001 is a common convention for service accounts.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CLAUDE_PROXY_HOST=0.0.0.0 \
    CLAUDE_PROXY_PORT=8888

EXPOSE 8888
USER app

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('CLAUDE_PROXY_PORT','8888')}/_health\", timeout=2).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "claude_proxy"]
