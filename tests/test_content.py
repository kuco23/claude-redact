"""JSON-walker tests for content.py — mask_request / unmask_response."""
from __future__ import annotations

from claude_redact.content import mask_request, unmask_response
from claude_redact.masking import fake_for


def test_mask_request_string_system_prompt():
    body = {"system": "Use the key sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGG1234"}
    mask_request(body)
    # Original key must be gone; replaced by a same-prefix fake of the same shape.
    assert "sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGG1234" not in body["system"]
    assert "sk-ant-" in body["system"]


def test_mask_request_walks_message_text_blocks():
    body = {
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "ssh into 192.168.1.42 now"},
                {"type": "image", "source": {"data": "BIN..."}},  # untouched
            ]},
        ],
    }
    mask_request(body)
    text_block = body["messages"][0]["content"][0]
    assert "192.168.1.42" not in text_block["text"]
    # Some IPv4-shaped value remains in its place.
    assert any(c.isdigit() for c in text_block["text"])
    # Image block must pass through untouched.
    assert body["messages"][0]["content"][1]["source"]["data"] == "BIN..."


def test_mask_request_walks_tool_result_nested():
    body = {
        "messages": [
            {"role": "user", "content": [
                {"type": "tool_result", "content": [
                    {"type": "text", "text": "got key sk-ant-api03-ZZZZyyyyXXXXwwwwVVVVuuuuTTTT9999"},
                ]},
            ]},
        ],
    }
    mask_request(body)
    inner = body["messages"][0]["content"][0]["content"][0]
    assert "sk-ant-api03-ZZZZyyyyXXXXwwwwVVVVuuuuTTTT9999" not in inner["text"]


def test_mask_request_string_content_in_message():
    """Anthropic accepts `content` as a bare string too — must still be masked."""
    body = {"messages": [{"role": "user", "content": "email me at eve@example.com"}]}
    mask_request(body)
    assert "eve@example.com" not in body["messages"][0]["content"]


def test_mask_request_no_messages_or_system():
    body = {"max_tokens": 100}
    assert mask_request(body) == {"max_tokens": 100}


def test_unmask_response_text_block():
    fake = fake_for("EMAIL_ADDRESS", "frank@example.com")
    body = {"content": [{"type": "text", "text": f"reply to {fake} soon"}]}
    unmask_response(body)
    assert body["content"][0]["text"] == "reply to frank@example.com soon"


def test_unmask_response_tool_use_input():
    """tool_use.input is walked recursively — strings inside dicts/lists
    must all have their fakes restored so local tools see real values."""
    fake = fake_for("IP_ADDRESS", "10.20.30.40")
    body = {"content": [{
        "type": "tool_use",
        "name": "ssh",
        "input": {"host": fake, "ports": [22, fake]},
    }]}
    unmask_response(body)
    out = body["content"][0]["input"]
    assert out["host"] == "10.20.30.40"
    assert out["ports"] == [22, "10.20.30.40"]


def test_unmask_response_leaves_non_text_blocks_alone():
    body = {"content": [
        {"type": "thinking", "thinking": "internal reasoning"},  # not unmasked
        {"type": "text", "text": "hello"},
    ]}
    unmask_response(body)
    assert body["content"][0]["thinking"] == "internal reasoning"
