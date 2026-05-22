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
