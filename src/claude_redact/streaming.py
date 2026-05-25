"""SSE event transformation — un-mask `text_delta` and `input_json_delta` on the wire.

Anthropic streams two delta kinds we care about:
  * `text_delta.text`         — the user-visible reply
  * `input_json_delta.partial_json` — fragments of `tool_use.input` JSON
Both can contain fakes the proxy minted on the request leg, and a fake
can straddle chunk boundaries. We buffer the unprocessed tail of each
content block: whatever looks like the prefix of a known fake is held
until either the rest of the fake arrives (or doesn't) — when it
doesn't, `content_block_stop` flushes the tail verbatim.

Plaintext we leak into the user-facing transcript here is re-masked by
`mask_request` on the next request leg, so Anthropic still only ever
sees fakes.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from claude_redact.masking import flush_hold, scan_with_hold


# Map each streamable delta kind to the field that carries its payload.
_DELTA_PAYLOAD_FIELD = {
    "text_delta": "text",
    "input_json_delta": "partial_json",
}


async def transform_sse(upstream: httpx.Response) -> AsyncIterator[bytes]:
    """Iterate `upstream` and yield SSE bytes with text + tool-use deltas un-masked.

    `event:` lines are buffered, not emitted immediately, so that when we
    need to inject a synthetic `content_block_delta` event at
    `content_block_stop` time (to flush a held tail), the synthetic gets its
    own `event: content_block_delta` header and the stop event's `event:`
    header is re-emitted in front of its own `data:` line. Without this
    buffering, the upstream's `event: content_block_stop` line lands in
    front of the synthetic `data:` and clients that dispatch by event name
    drop the flush as a type mismatch (the response then appears empty).
    """
    # Per-index (delta_kind, held_tail). delta_kind is remembered so the
    # synthetic tail event at content_block_stop uses the right shape.
    buffers: dict[int, tuple[str, str]] = {}
    # The most-recent `event:` line seen but not yet emitted. Flushed
    # immediately before whichever non-event line consumes it (typically
    # `data:`, but blank/comment lines flush it too so an event header
    # never ends up paired with the wrong line by the parser).
    pending_event: str | None = None
    try:
        async for raw_line in upstream.aiter_lines():
            line = raw_line
            if line.startswith("event: "):
                pending_event = line
                continue
            if line.startswith("data: "):
                try:
                    evt = json.loads(line[6:])
                except json.JSONDecodeError:
                    if pending_event is not None:
                        yield (pending_event + "\n").encode()
                        pending_event = None
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
                        flushed, new_hold = scan_with_hold(buf)
                        buffers[idx] = (dkind, new_hold)
                        delta[field] = flushed
                        line = "data: " + json.dumps(evt)
                elif etype == "content_block_stop":
                    idx = evt.get("index", 0)
                    dkind, tail = buffers.pop(idx, ("", ""))
                    if tail:
                        field = _DELTA_PAYLOAD_FIELD[dkind]
                        tail_evt = {
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": {"type": dkind, field: flush_hold(tail)},
                        }
                        # Self-framed synthetic event: header + data + blank-
                        # line terminator. The pending `event: content_block_stop`
                        # is re-emitted right after, in front of its own data.
                        yield b"event: content_block_delta\n"
                        yield ("data: " + json.dumps(tail_evt) + "\n\n").encode()
                if pending_event is not None:
                    yield (pending_event + "\n").encode()
                    pending_event = None
                yield (line + "\n").encode()
                continue
            # Blank-line event separator, comment line, or anything else.
            # Flush any buffered `event:` first so it doesn't get glued to a
            # later data line.
            if pending_event is not None:
                yield (pending_event + "\n").encode()
                pending_event = None
            yield (line + "\n").encode()
    finally:
        await upstream.aclose()
