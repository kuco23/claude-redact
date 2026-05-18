"""Minimal Claude reverse proxy with Presidio-based masking.

Run:
    uv sync
    uv run python proxy.py

Point a client at it:
    ANTHROPIC_BASE_URL=http://127.0.0.1:8888 ANTHROPIC_API_KEY=sk-... claude

Detected entities in outbound request bodies are replaced with deterministic
placeholders (same secret -> same placeholder, for the life of the process);
the reverse map is applied to JSON response bodies and to SSE `text_delta`
events on the way back to the client.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, AsyncIterator

import httpx
from detect_secrets.core.scan import scan_line
from detect_secrets.settings import transient_settings
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

UPSTREAM = "https://api.anthropic.com"

ENTITIES = [
    # Built-in PII recognizers
    "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "IP_ADDRESS",
    # Custom recognizers registered below
    "UUID", "JWT", "API_KEY", "CRYPTO_PRIVATE_KEY", "HASH",
    "ETH_ADDRESS", "BTC_ADDRESS", "LTC_ADDRESS", "DOGE_ADDRESS",
    "XRP_ADDRESS", "TRX_ADDRESS", "XMR_ADDRESS", "ADA_ADDRESS", "BCH_ADDRESS",
]

# detect-secrets plugins. We deliberately enable only the entropy-based
# detectors — provider-specific patterns already live in _CUSTOM_PATTERNS.
# Limits are detect-secrets defaults; raise them to reduce false positives.
_DS_PLUGINS = [
    {"name": "Base64HighEntropyString", "limit": 4.5},
    {"name": "HexHighEntropyString", "limit": 3.0},
]

# (entity_type, regex, score). Scores break ties when ranges overlap —
# more specific patterns get higher scores so they win over generic ones.
_CUSTOM_PATTERNS: list[tuple[str, str, float]] = [
    # UUID / GUID (8-4-4-4-12), commonly used as API keys, tenant IDs, secrets.
    ("UUID",
     r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
     0.85),

    # JSON Web Token: three base64url segments joined by dots, header starts with eyJ.
    ("JWT",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     0.95),

    # PEM-encoded private keys: RSA, EC, DSA, PKCS#8, OpenSSH, encrypted variants.
    ("CRYPTO_PRIVATE_KEY",
     r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
     0.99),

    # Hex digests: MD5 / SHA1 / SHA256 / SHA512. Also catches raw 64-hex secp256k1 keys.
    ("HASH", r"\b[a-f0-9]{32}\b", 0.4),
    ("HASH", r"\b[a-f0-9]{40}\b", 0.5),
    ("HASH", r"\b[a-f0-9]{64}\b", 0.5),
    ("HASH", r"\b[a-f0-9]{128}\b", 0.6),

    # Ethereum (and EVM-compatible chains): 0x + 40 hex.
    ("ETH_ADDRESS", r"\b0x[a-fA-F0-9]{40}\b", 0.85),

    # Bitcoin: legacy P2PKH (1...) / P2SH (3...) and bech32 SegWit (bc1...).
    # Base58 alphabet excludes 0, O, I, l. Length 26-35 incl. prefix.
    ("BTC_ADDRESS", r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b", 0.75),
    ("BTC_ADDRESS", r"\bbc1[ac-hj-np-z02-9]{39,59}\b", 0.95),

    # Bitcoin Cash CashAddr (`bitcoincash:q...`/`...p...`).
    ("BCH_ADDRESS", r"\bbitcoincash:[qp][ac-hj-np-z02-9]{40,42}\b", 0.95),

    # Litecoin: legacy (L.../M...) and bech32 (ltc1...).
    ("LTC_ADDRESS", r"\b[LM][1-9A-HJ-NP-Za-km-z]{26,33}\b", 0.75),
    ("LTC_ADDRESS", r"\bltc1[ac-hj-np-z02-9]{39,59}\b", 0.95),

    # Dogecoin: P2PKH starts with D, 34 chars total.
    ("DOGE_ADDRESS", r"\bD[1-9A-HJ-NP-Za-km-z]{33}\b", 0.75),

    # Ripple (XRP): starts with r, base58, 25-35 chars.
    ("XRP_ADDRESS", r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", 0.65),

    # Tron (TRX): starts with T, 34 chars total.
    ("TRX_ADDRESS", r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", 0.75),

    # Monero (XMR): base58, 95 chars, starts with 4 (standard) or 8 (subaddress).
    ("XMR_ADDRESS", r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", 0.95),

    # Cardano (ADA) Shelley-era bech32 addresses.
    ("ADA_ADDRESS", r"\baddr1[ac-hj-np-z02-9]{50,}\b", 0.95),

    # Provider-prefixed API keys. Order matters only via score (more specific = higher).
    ("API_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", 0.99),           # Anthropic
    ("API_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", 0.95),          # OpenAI project key
    ("API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b", 0.80),                  # OpenAI generic
    ("API_KEY", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", 0.95),  # Stripe
    ("API_KEY", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", 0.95),            # GitHub classic
    ("API_KEY", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", 0.99),          # GitHub fine-grained
    ("API_KEY",                                                      # GitLab (PAT, deploy, runner,
     r"\bgl(?:pat|dt|rt|ptt|ft|agent|oas|cbt|soat|imt)-[A-Za-z0-9_\-]{20,}\b",
     0.97),                                                          # trigger, feed, agent, oauth, ci/build, scim, mail)
    ("API_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.95),            # AWS access key id
    ("API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.95),               # Google API key
    ("API_KEY", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", 0.90),        # Slack
]


def _register_custom_recognizers(engine: AnalyzerEngine) -> None:
    by_entity: dict[str, list[Pattern]] = {}
    for entity, regex, score in _CUSTOM_PATTERNS:
        lst = by_entity.setdefault(entity, [])
        lst.append(Pattern(name=f"{entity}_{len(lst)}", regex=regex, score=score))
    for entity, patterns in by_entity.items():
        engine.registry.add_recognizer(
            PatternRecognizer(supported_entity=entity, patterns=patterns)
        )


analyzer = AnalyzerEngine()
_register_custom_recognizers(analyzer)

PLACEHOLDER_RE = re.compile(r"<<MASK:[A-Z_]+:[0-9a-f]{10}>>")
MAX_PLACEHOLDER_LEN = 64

FORWARD_MAP: dict[str, str] = {}
REVERSE_MAP: dict[str, str] = {}


def _placeholder_for(entity_type: str, value: str) -> str:
    if value in FORWARD_MAP:
        return FORWARD_MAP[value]
    digest = hashlib.sha256(value.encode()).hexdigest()[:10]
    ph = f"<<MASK:{entity_type}:{digest}>>"
    FORWARD_MAP[value] = ph
    REVERSE_MAP[ph] = value
    return ph


def _splice(text: str, matches: list[tuple[int, int, str]]) -> str:
    out = text
    for start, end, etype in sorted(matches, key=lambda m: m[0], reverse=True):
        ph = _placeholder_for(etype, out[start:end])
        out = out[:start] + ph + out[end:]
    return out


def _ds_entity_type(secret_type: str) -> str:
    if "Base64" in secret_type:
        return "BASE64_SECRET"
    if "Hex" in secret_type:
        return "HEX_SECRET"
    return "HIGH_ENTROPY_SECRET"


def _detect_secrets_matches(text: str) -> list[tuple[int, int, str]]:
    # Exclude any region already covered by a placeholder from the Presidio pass,
    # so we don't re-mask our own `<<MASK:…:hex>>` strings as hex secrets.
    masked = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]

    def in_masked(s: int, e: int) -> bool:
        return any(s < me and e > ms for ms, me in masked)

    matches: list[tuple[int, int, str]] = []
    offset = 0
    with transient_settings({"plugins_used": _DS_PLUGINS}):
        for line in text.splitlines(keepends=True):
            for secret in scan_line(line):
                value = getattr(secret, "secret_value", None)
                if not value:
                    continue
                idx = line.find(value)
                if idx == -1:
                    continue
                start = offset + idx
                end = start + len(value)
                if in_masked(start, end):
                    continue
                matches.append((start, end, _ds_entity_type(secret.type)))
            offset += len(line)
    return matches


def mask(text: str) -> str:
    if not text:
        return text
    # Pass 1: Presidio (built-in PII + the custom regex recognizers).
    results = analyzer.analyze(text=text, entities=ENTITIES, language="en")
    text = _splice(text, [(r.start, r.end, r.entity_type) for r in results])
    # Pass 2: detect-secrets entropy-based detectors on whatever survived.
    text = _splice(text, _detect_secrets_matches(text))
    return text


def unmask(text: str) -> str:
    if not text or "<<MASK:" not in text:
        return text
    return PLACEHOLDER_RE.sub(lambda m: REVERSE_MAP.get(m.group(0), m.group(0)), text)


def _mask_content(content: Any) -> Any:
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
                block["content"] = _mask_content(block["content"])
    return content


def mask_request(body: dict[str, Any]) -> dict[str, Any]:
    if "system" in body:
        body["system"] = _mask_content(body["system"])
    for msg in body.get("messages", []) or []:
        if "content" in msg:
            msg["content"] = _mask_content(msg["content"])
    return body


def unmask_response(body: dict[str, Any]) -> dict[str, Any]:
    for block in body.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text" and "text" in block:
            block["text"] = unmask(block["text"])
    return body


# Headers we must not pass through verbatim — httpx will recompute these,
# and Accept-Encoding is stripped so we always get plaintext bodies back.
_DROP_REQ_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
_DROP_RESP_HEADERS = {"content-length", "content-encoding", "transfer-encoding"}


def _filter(h: dict[str, str], drop: set[str]) -> dict[str, str]:
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

    headers = _filter(dict(request.headers), _DROP_REQ_HEADERS)
    upstream_req = client.build_request(
        "POST", "/v1/messages", headers=headers, content=masked_bytes
    )

    if is_stream:
        upstream = await client.send(upstream_req, stream=True)

        async def gen() -> AsyncIterator[bytes]:
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

        return StreamingResponse(
            gen(),
            status_code=upstream.status_code,
            media_type="text/event-stream",
            headers=_filter(dict(upstream.headers), _DROP_RESP_HEADERS),
        )

    upstream = await client.send(upstream_req)
    ctype = upstream.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        data = unmask_response(upstream.json())
        return Response(
            content=json.dumps(data),
            status_code=upstream.status_code,
            media_type="application/json",
        )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter(dict(upstream.headers), _DROP_RESP_HEADERS),
    )


def _split_buffer(buf: str) -> tuple[str, str]:
    # Hold back any trailing fragment that might be the start of a placeholder
    # we haven't fully received yet. A `<<` that already has a matching `>>`
    # after it is a complete placeholder and is safe to flush.
    tail_start = buf.rfind("<<", max(0, len(buf) - MAX_PLACEHOLDER_LEN))
    if tail_start == -1 or ">>" in buf[tail_start:]:
        return buf, ""
    return buf[:tail_start], buf[tail_start:]


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def passthrough(path: str, request: Request) -> Response:
    raw = await request.body()
    upstream = await client.request(
        request.method,
        "/" + path,
        headers=_filter(dict(request.headers), _DROP_REQ_HEADERS),
        content=raw,
        params=dict(request.query_params),
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=_filter(dict(upstream.headers), _DROP_RESP_HEADERS),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8888)
