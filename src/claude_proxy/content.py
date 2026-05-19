"""Walk Anthropic Messages-API JSON bodies and apply mask / unmask.

Anthropic's `content` is either a plain string or a list of typed blocks
(`text`, `tool_result`, `tool_use`, `image`, `document`, ...). We only
descend into the kinds that carry user-visible prose; image bytes and
tool-use inputs are passed through untouched.
"""
from __future__ import annotations

from typing import Any

from claude_proxy.masking import mask, unmask


def mask_request(body: dict[str, Any]) -> dict[str, Any]:
    """Mutate `body` in place, masking `system` and each `messages[].content`."""
    if "system" in body:
        body["system"] = _walk_mask(body["system"])
    for msg in body.get("messages", []) or []:
        if "content" in msg:
            msg["content"] = _walk_mask(msg["content"])
    return body


def unmask_response(body: dict[str, Any]) -> dict[str, Any]:
    """Mutate `body` in place, un-masking `text` blocks (so the user reads
    plaintext in chat) and the `input` JSON of every `tool_use` block (so
    local tools receive real values). Plaintext that lands back in the next
    request's transcript is re-masked by `mask_request`, so Anthropic still
    only ever sees placeholders on the wire."""
    for block in body.get("content", []) or []:
        if not isinstance(block, dict):
            continue
        t = block.get("type")
        if t == "text" and "text" in block:
            block["text"] = unmask(block["text"])
        elif t == "tool_use" and "input" in block:
            block["input"] = _walk_unmask(block["input"])
    return body


def _walk_mask(content: Any) -> Any:
    if isinstance(content, str):
        return mask(content)
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            t = block.get("type")
            if t == "text" and "text" in block:
                block["text"] = mask(block["text"])
            elif t == "tool_result" and "content" in block:
                block["content"] = _walk_mask(block["content"])
    return content


def _walk_unmask(value: Any) -> Any:
    if isinstance(value, str):
        return unmask(value)
    if isinstance(value, dict):
        return {k: _walk_unmask(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_unmask(v) for v in value]
    return value
