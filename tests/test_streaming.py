"""SSE chunk-buffering tests for streaming.py."""
from __future__ import annotations

import json
from typing import AsyncIterator, cast

import httpx

from claude_proxy.masking import placeholder_for
from claude_proxy.streaming import _split_buffer, transform_sse


# --- Pure split_buffer logic --------------------------------------------

def test_split_buffer_complete_placeholder_fully_flushes():
    buf = "hello <<MASK:API_KEY:0123456789abcdef>> world"
    flush, hold = _split_buffer(buf)
    assert flush == buf and hold == ""


def test_split_buffer_holds_incomplete_tail():
    buf = "hello <<MASK:API_KEY:0123"
    flush, hold = _split_buffer(buf)
    assert flush == "hello "
    assert hold == "<<MASK:API_KEY:0123"


def test_split_buffer_closing_marker_releases_hold():
    """A `>>` after the candidate `<<` means the placeholder is complete
    in this chunk and the whole buffer can flush."""
    buf = "<<MASK:API_KEY:0123456789abcdef>> trailing"
    flush, hold = _split_buffer(buf)
    assert flush == buf and hold == ""


def test_split_buffer_no_marker_flushes_all():
    buf = "plain text with no placeholder markers at all"
    flush, hold = _split_buffer(buf)
    assert flush == buf and hold == ""


def test_split_buffer_only_considers_recent_window():
    """A `<<` more than MAX_PLACEHOLDER_LEN chars back can't be a real
    in-flight placeholder — don't hold the entire stream tail hostage."""
    buf = "<<bogus" + ("x" * 200)  # the `<<` is way past the window
    flush, hold = _split_buffer(buf)
    assert hold == ""
    assert flush == buf


# --- transform_sse end-to-end -------------------------------------------

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
    ph = placeholder_for("EMAIL_ADDRESS", "alice@example.com")
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"reply to {ph} now"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    assert "alice@example.com" in out
    assert ph not in out
    assert upstream.closed


async def test_transform_buffers_placeholder_across_chunks():
    """A placeholder split mid-token across two deltas must round-trip
    correctly: the trailing fragment is held until the closing `>>`."""
    ph = placeholder_for("API_KEY", "secret-token-abc")
    # Split the placeholder roughly in half.
    half = len(ph) // 2
    part1, part2 = ph[:half], ph[half:]
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"prefix {part1}"}}),
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": f"{part2} suffix"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    # The first chunk should not have leaked the half-placeholder; the
    # second chunk should contain the unmasked secret.
    assert "secret-token-abc" in out
    assert part1 not in out or out.index("secret-token-abc") < out.index(part1 + part2)


async def test_transform_flushes_tail_at_stop():
    """If a placeholder is still buffered when `content_block_stop` arrives
    (because no `>>` ever came), the tail is emitted as a synthetic delta
    so nothing is silently dropped."""
    upstream = _FakeUpstream([
        _sse({"type": "content_block_delta", "index": 0,
              "delta": {"type": "text_delta", "text": "incomplete <<MASK:API_KEY:abc"}}),
        _sse({"type": "content_block_stop", "index": 0}),
    ])
    out = await _collect(transform_sse(cast(httpx.Response, upstream)))
    # The held tail must appear before content_block_stop reaches the client.
    tail_pos = out.find("<<MASK:API_KEY:abc")
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
