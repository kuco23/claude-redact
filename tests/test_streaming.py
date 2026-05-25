"""SSE chunk-buffering tests for streaming.py.

The new buffer logic holds back any tail that is a strict prefix of a
known fake, so a fake that straddles a chunk boundary is never half-
flushed. There's no `<<…>>` marker any more — the test surface is the
end-to-end transform.
"""
from __future__ import annotations

import json
from typing import AsyncIterator, cast

import httpx

from claude_redact.masking import fake_for
from claude_redact.streaming import transform_sse


class _FakeUpstream:
    """Minimal stand-in for httpx.Response with the two methods transform_sse uses."""

    def __init__(self, lines: list[str]):
        self._lines = lines
        self.closed = False

    async def aiter_lines(self) -> AsyncIterator[str]:
        for line in self._lines:
            yield line

    async def aclose(self):
        self.closed = True


def _sse(payload: dict) -> str:
    return "data: " + json.dumps(payload)


async def _collect(it: AsyncIterator[bytes]) -> str:
    chunks: list[bytes] = []
    async for chunk in it:
        chunks.append(chunk)
    return b"".join(chunks).decode()


async def test_transform_unmasks_text_delta():
    fake = fake_for("EMAIL_ADDRESS", "dave@example.com")
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"reply to {fake} now"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    assert "dave@example.com" in out
    assert fake not in out
    assert upstream.closed


async def test_transform_buffers_fake_across_chunks():
    """A fake split mid-token across two deltas must round-trip correctly:
    the trailing fragment is held until the rest arrives."""
    fake = fake_for("API_KEY", "sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGG1234")
    half = len(fake) // 2
    part1, part2 = fake[:half], fake[half:]
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"prefix {part1}"}}),
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"{part2} suffix"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    # Original is restored, and the half-fake never appears alone on the wire.
    assert "sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGG1234" in out
    # The full fake string should not appear in output (it got unmasked).
    assert fake not in out


async def test_transform_flushes_tail_at_stop():
    """If a fake-prefix is still buffered when `content_block_stop` arrives
    (because the rest never came), the tail is emitted as a synthetic delta
    so nothing is silently dropped."""
    fake = fake_for("API_KEY", "sk-ant-api03-XXXXyyyyZZZZwwwwVVVVuuuuTTTT5678")
    half = len(fake) // 2
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"incomplete {fake[:half]}"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    # The held tail must appear before content_block_stop reaches the client.
    tail_pos = out.find(fake[:half])
    stop_pos = out.find("content_block_stop")
    assert tail_pos != -1 and stop_pos != -1
    assert tail_pos < stop_pos


async def test_transform_passes_through_unknown_events():
    upstream = _FakeUpstream([
        _sse({"type": "message_start", "message": {"id": "msg_1"}}),
        ": comment line",
        "",
        _sse({"type": "message_stop"}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    assert "msg_1" in out
    assert "message_stop" in out


async def test_transform_handles_malformed_data_line():
    """A `data:` line that isn't JSON must pass through verbatim, not crash."""
    upstream = _FakeUpstream([
        "data: not json {{{",
        _sse({"type": "message_stop"}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    assert "not json" in out
    assert "message_stop" in out


async def test_transform_does_not_hold_when_no_fakes_minted():
    """With no entries in the reverse map, every delta flushes immediately."""
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": "plain text"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    assert "plain text" in out


# --- SSE framing regression -----------------------------------------------

def _parse_sse_events(text: str) -> list[tuple[str, object]]:
    """Walk an SSE-formatted byte stream into (event_name, parsed_data) pairs.

    Per the SSE spec, `event:` sets the event name for the upcoming `data:`
    payload and the name resets to "message" after each blank-line-terminated
    event. We need this here because the existing tests only feed bare
    `data:` lines — they don't exercise interactions with `event:` headers,
    which is where the streaming transform's flush-at-stop logic breaks
    framing when the synthetic delta is injected between an `event:` line
    and its own `data:`.
    """
    events: list[tuple[str, object]] = []
    event_name = "message"
    data_lines: list[str] = []

    def flush():
        nonlocal event_name, data_lines
        if not data_lines:
            return
        payload = "\n".join(data_lines)
        try:
            parsed: object = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload
        events.append((event_name, parsed))
        event_name = "message"
        data_lines = []

    for line in text.split("\n"):
        if line.startswith("event: "):
            event_name = line[len("event: "):].strip()
        elif line.startswith("data: "):
            data_lines.append(line[len("data: "):])
        elif line == "":
            flush()
    flush()
    return events


async def test_transform_preserves_event_headers_when_flushing_held_tail():
    """Reproduces the 'response disappears' bug.

    When the entire `text_delta` payload is a strict prefix of a known fake,
    `scan_with_hold` swallows it all and the synthetic flush event has to
    fire at `content_block_stop` time to deliver the held tail. The current
    implementation yields the synthetic `data:` line *between* the upstream's
    `event: content_block_stop` header and that header's own `data:` line,
    so an SSE parser pairs:

      - `event: content_block_stop`  with  `data: {type: content_block_delta}`
      - default `event: message`     with  `data: {type: content_block_stop}`

    Both are framing violations. Clients that dispatch by event name (the
    Anthropic SDK among them) drop the synthetic delta and the response
    appears empty to the user.

    This test asserts that every event's header name matches the `type`
    field in its data payload. It is expected to FAIL on the current
    streaming.py and pass once the synthetic event is emitted with its own
    `event: content_block_delta` header and the stop event's header is
    re-emitted after it.
    """
    fake = fake_for("HASH", "abcdef" * 6 + "1234")  # 40-hex fake
    first_char = fake[0]
    # Realistic upstream framing: each event has its own `event:` line, then
    # `data:`, then a blank line. (Existing tests omit `event:` lines so they
    # don't exercise this interaction.)
    upstream = _FakeUpstream([
        "event: content_block_delta",
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": first_char}}),
        "",
        "event: content_block_stop",
        _sse({"type": "content_block_stop", "index": 0}),
        "",
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    events = _parse_sse_events(out)

    # Framing check: every event header name must match its data payload type.
    mismatches = [
        (name, data.get("type"))
        for name, data in events
        if isinstance(data, dict) and name != data.get("type")
    ]
    assert not mismatches, (
        f"SSE event header/payload type mismatches: {mismatches}\n"
        f"Raw output:\n{out}"
    )

    # Delivery check: the held character must actually reach the client via
    # some content_block_delta event's text payload.
    delivered = "".join(
        data["delta"].get("text", "")
        for _, data in events
        if isinstance(data, dict)
        and data.get("type") == "content_block_delta"
        and isinstance(data.get("delta"), dict)
    )
    assert first_char in delivered, (
        f"held char {first_char!r} never delivered; concatenated delta text "
        f"was {delivered!r}\nRaw output:\n{out}"
    )
