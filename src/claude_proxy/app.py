"""FastAPI reverse proxy in front of api.anthropic.com.

Point a client at this app:
    ANTHROPIC_BASE_URL=http://127.0.0.1:8888 ANTHROPIC_API_KEY=sk-... claude

Routes:
  POST /v1/messages   — bodies go through mask/unmask (incl. SSE streams)
  /{path:path}        — everything else is forwarded untouched
"""
from __future__ import annotations

import json

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from claude_proxy.content import mask_request, unmask_response
from claude_proxy.streaming import transform_sse

UPSTREAM = "https://api.anthropic.com"

# Outbound: httpx recomputes Host/Content-Length itself; Accept-Encoding is
# dropped so we always get plaintext bodies back rather than gzip.
_DROP_REQ_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
# Inbound: body sizes change after un-masking, so the length/encoding headers
# from upstream no longer apply.
_DROP_RESP_HEADERS = {"content-length", "content-encoding", "transfer-encoding"}


def _filter_headers(h: dict[str, str], drop: set[str]) -> dict[str, str]:
    return {k: v for k, v in h.items() if k.lower() not in drop}


app = FastAPI()
client = httpx.AsyncClient(base_url=UPSTREAM, timeout=httpx.Timeout(600.0, connect=10.0))


@app.post("/v1/messages")
async def messages(request: Request) -> Response:
    raw = await request.body()
    body = json.loads(raw) if raw else {}
    is_stream = bool(body.get("stream"))
    mask_request(body)
    masked_bytes = json.dumps(body).encode()

    headers = _filter_headers(dict(request.headers), _DROP_REQ_HEADERS)
    upstream_req = client.build_request(
        "POST", "/v1/messages", headers=headers, content=masked_bytes
    )

    if is_stream:
        upstream = await client.send(upstream_req, stream=True)
        return StreamingResponse(
            transform_sse(upstream),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_filter_headers(dict(upstream.headers), _DROP_RESP_HEADERS),
        )

    upstream = await client.send(upstream_req)
    if upstream.headers.get("content-type", "").startswith("application/json"):
        data = unmask_response(upstream.json())
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
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter_headers(dict(upstream.headers), _DROP_RESP_HEADERS),
    )
