"""SSE event transformation — un-mask `text_delta` events on the wire.

Placeholders can straddle chunk boundaries, so we buffer the tail of each
content block until we either see a closing `>>` or the `content_block_stop`
event arrives. Anything held back at stop time is flushed as a synthetic
`text_delta` so the client sees the complete original text.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from claude_proxy.masking import MAX_PLACEHOLDER_LEN, unmask


async def transform_sse(upstream: httpx.Response) -> AsyncIterator[bytes]:
    """Iterate `upstream` and yield SSE bytes with text deltas un-masked."""
    buffers: dict[int, str] = {}
    try:
        async for raw_line in upstream.aiter_lines():
            line = raw_line
            if line.startswith("data: "):
                try:
                    evt = json.loads(line[6:])
                except json.JSONDecodeError:
                    yield (line + "\n").encode()
                    continue
                etype = evt.get("type")
                if etype == "content_block_delta":
                    delta = evt.get("delta", {})
                    if delta.get("type") == "text_delta":
                        idx = evt.get("index", 0)
                        buf = buffers.get(idx, "") + delta.get("text", "")
                        flush, hold = _split_buffer(buf)
                        buffers[idx] = hold
                        delta["text"] = unmask(flush)
                        line = "data: " + json.dumps(evt)
                elif etype == "content_block_stop":
                    idx = evt.get("index", 0)
                    tail = buffers.pop(idx, "")
                    if tail:
                        tail_evt = {
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": {"type": "text_delta", "text": unmask(tail)},
                        }
                        yield ("data: " + json.dumps(tail_evt) + "\n\n").encode()
            yield (line + "\n").encode()
    finally:
        await upstream.aclose()


def _split_buffer(buf: str) -> tuple[str, str]:
    """Return (flush, hold). A trailing `<<…` without its matching `>>` is
    held back in case the placeholder is finishing in the next chunk."""
    tail_start = buf.rfind("<<", max(0, len(buf) - MAX_PLACEHOLDER_LEN))
    if tail_start == -1 or ">>" in buf[tail_start:]:
        return buf, ""
    return buf[:tail_start], buf[tail_start:]
