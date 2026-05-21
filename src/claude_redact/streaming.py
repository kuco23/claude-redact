"""SSE event transformation — un-mask `text_delta` and `input_json_delta` on the wire.

Anthropic streams two delta kinds we care about:
  * `text_delta.text`         — the user-visible reply
  * `input_json_delta.partial_json` — fragments of `tool_use.input` JSON
Both can contain placeholders, and a placeholder can straddle chunk
boundaries, so we buffer the tail of each content block until we either see
a closing `>>` or the `content_block_stop` event arrives. Anything held
back at stop time is flushed as a synthetic delta of the same kind.

Plaintext we leak into the user-facing transcript here is re-masked by
`mask_request` on the next request leg, so Anthropic still only ever sees
placeholders.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from claude_redact.masking import MAX_PLACEHOLDER_LEN, unmask


# Map each streamable delta kind to the field that carries its payload.
_DELTA_PAYLOAD_FIELD = {
    "text_delta": "text",
    "input_json_delta": "partial_json",
}


async def transform_sse(upstream: httpx.Response) -> AsyncIterator[bytes]:
    """Iterate `upstream` and yield SSE bytes with text + tool-use deltas un-masked."""
    # Per-index (delta_kind, held_tail). delta_kind is remembered so the
    # synthetic tail event at content_block_stop uses the right shape.
    buffers: dict[int, tuple[str, str]] = {}
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
                    dkind = delta.get("type")
                    field = _DELTA_PAYLOAD_FIELD.get(dkind)
                    if field is not None:
                        idx = evt.get("index", 0)
                        _, held = buffers.get(idx, (dkind, ""))
                        buf = held + delta.get(field, "")
                        flush, hold = _split_buffer(buf)
                        buffers[idx] = (dkind, hold)
                        delta[field] = unmask(flush)
                        line = "data: " + json.dumps(evt)
                elif etype == "content_block_stop":
                    idx = evt.get("index", 0)
                    dkind, tail = buffers.pop(idx, ("", ""))
                    if tail:
                        field = _DELTA_PAYLOAD_FIELD[dkind]
                        tail_evt = {
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": {"type": dkind, field: unmask(tail)},
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
