"""FastAPI reverse proxy in front of api.anthropic.com.

Point a client at this app:
    ANTHROPIC_BASE_URL=http://127.0.0.1:8888 ANTHROPIC_API_KEY=sk-... claude

Routes:
  POST /v1/messages   — bodies go through mask/unmask (incl. SSE streams)
  /{path:path}        — everything else is forwarded untouched
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from claude_proxy.content import mask_request, unmask_response
from claude_proxy.streaming import transform_sse

logger = logging.getLogger(__name__)

UPSTREAM = os.environ.get("CLAUDE_PROXY_UPSTREAM", "https://api.anthropic.com")

# Headers whose values get redacted in logs. Names are matched case-insensitively.
_LOG_REDACT_HEADERS = {
    "x-api-key", "anthropic-api-key", "authorization", "cookie", "set-cookie",
}

# Cap for body dumps at DEBUG level. Override via env if you need more.
_BODY_LOG_LIMIT = int(os.environ.get("CLAUDE_PROXY_LOG_BODY_LIMIT", "8000"))

# Outbound: httpx recomputes Host/Content-Length itself; Accept-Encoding is
# dropped so we always get plaintext bodies back rather than gzip.
_DROP_REQ_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
# Inbound: body sizes change after un-masking, so the length/encoding headers
# from upstream no longer apply.
_DROP_RESP_HEADERS = {"content-length", "content-encoding", "transfer-encoding"}


def _filter_headers(h: dict[str, str], drop: set[str]) -> dict[str, str]:
    return {k: v for k, v in h.items() if k.lower() not in drop}


def _redact_headers(h: dict[str, str]) -> dict[str, str]:
    """Return a copy of `h` with sensitive header *values* obscured for logs."""
    out: dict[str, str] = {}
    for k, v in h.items():
        if k.lower() in _LOG_REDACT_HEADERS and v:
            out[k] = f"{v[:6]}…{v[-4:]}" if len(v) > 14 else "***"
        else:
            out[k] = v
    return out


def _truncate(obj: Any, limit: int = _BODY_LOG_LIMIT) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    if limit <= 0 or len(s) <= limit:
        return s
    return f"{s[:limit]}…(+{len(s) - limit} chars)"


app = FastAPI()
client = httpx.AsyncClient(base_url=UPSTREAM, timeout=httpx.Timeout(600.0, connect=10.0))


@app.post("/v1/messages")
async def messages(request: Request) -> Response:
    raw = await request.body()
    body = json.loads(raw) if raw else {}
    is_stream = bool(body.get("stream"))

    inbound_headers = dict(request.headers)
    logger.info("POST /v1/messages stream=%s body=%dB", is_stream, len(raw))
    logger.debug("inbound headers: %s", _redact_headers(inbound_headers))
    logger.debug("request body pre-mask: %s", _truncate(body))

    mask_request(body)
    logger.debug("request body post-mask: %s", _truncate(body))

    masked_bytes = json.dumps(body).encode()
    headers = _filter_headers(inbound_headers, _DROP_REQ_HEADERS)
    logger.debug("forwarding headers: %s", _redact_headers(headers))
    upstream_req = client.build_request(
        "POST", "/v1/messages", headers=headers, content=masked_bytes
    )

    if is_stream:
        upstream = await client.send(upstream_req, stream=True)
        logger.info("upstream stream open: status=%d", upstream.status_code)
        logger.debug("upstream headers: %s", _redact_headers(dict(upstream.headers)))
        return StreamingResponse(
            transform_sse(upstream),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_filter_headers(dict(upstream.headers), _DROP_RESP_HEADERS),
        )

    upstream = await client.send(upstream_req)
    logger.info(
        "upstream response: status=%d type=%s len=%dB",
        upstream.status_code,
        upstream.headers.get("content-type", "?"),
        len(upstream.content),
    )
    logger.debug("upstream headers: %s", _redact_headers(dict(upstream.headers)))

    if upstream.headers.get("content-type", "").startswith("application/json"):
        data = upstream.json()
        logger.debug("response body pre-unmask: %s", _truncate(data))
        unmask_response(data)
        logger.debug("response body post-unmask: %s", _truncate(data))
        return Response(
            content=json.dumps(data),
            status_code=upstream.status_code,
            media_type="application/json",
        )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers), _DROP_RESP_HEADERS),
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def passthrough(path: str, request: Request) -> Response:
    raw = await request.body()
    upstream = await client.request(
        request.method,
        "/" + path,
        headers=_filter_headers(dict(request.headers), _DROP_REQ_HEADERS),
        content=raw,
        params=dict(request.query_params),
    )
    logger.info(
        "%s /%s passthrough: status=%d len=%dB",
        request.method, path, upstream.status_code, len(upstream.content),
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers), _DROP_RESP_HEADERS),
    )
