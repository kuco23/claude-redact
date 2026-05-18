# claude-proxy

A local HTTP reverse proxy that sits in front of `api.anthropic.com` and masks
secrets / PII in both directions: detected entities in outbound request bodies
are replaced with stable placeholders, and inbound responses (including SSE
streams) are un-masked before reaching the client.

Point Claude Code or any Anthropic SDK at the proxy via `ANTHROPIC_BASE_URL`
and your prompts will reach Anthropic with phone numbers, API keys, crypto
addresses, PEM private keys, JWTs, high-entropy tokens, etc. stripped —
while you still see the originals in the model's replies.

## How it works

Detection runs in two passes:

1. **Presidio** — built-in PII recognizers (phones, emails, SSNs, credit
   cards, IPs) plus a curated set of regex `PatternRecognizer`s for UUIDs,
   JWTs, PEM private keys, hex hashes, EVM/BTC/LTC/DOGE/XRP/TRX/XMR/ADA/BCH
   addresses, and provider-prefixed API keys (Anthropic, OpenAI, Stripe,
   GitHub classic + fine-grained, GitLab, AWS, Google, Slack).
2. A small **entropy scanner** runs on the already-masked text: regex-extract
   base64- or hex-shaped runs of 20+ chars, then Shannon-entropy filter at
   4.5 / 3.0 bits per char. Catches opaque tokens that don't fit any known
   prefix; rejects ordinary English. (`detect-secrets` was tried first but
   its high-entropy plugins only fire on quoted source-code literals.)

Each detected range is replaced with `<<MASK:ENTITY_TYPE:<sha10>>>`, a
deterministic placeholder keyed off the original value — so the same secret
gets the same token across turns, letting the model reason about identity
("the user's wallet") without seeing the actual value. The reverse map is
applied on the way back, with per-content-block buffering for SSE so a
placeholder that straddles a chunk boundary doesn't get partially restored.

## Install

Requires Python 3.13+ and [uv](https://github.com/astral-sh/uv).

```bash
uv sync
```

First run downloads spaCy's `en_core_web_lg` model (~600 MB) — Presidio uses
it for the NLP-backed recognizers. Subsequent starts are fast.

## Run

Pick one:

```bash
uv run python -m claude_proxy
uv run uvicorn claude_proxy:app --host 127.0.0.1 --port 8888
```

Then point a client at it:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8888 ANTHROPIC_API_KEY=sk-ant-... claude
```

Or for the Python SDK:

```python
from anthropic import Anthropic
client = Anthropic(base_url="http://127.0.0.1:8888")
```

## Configuration

Settings come from environment variables; `.env` at the project root is
loaded automatically at startup. Copy [.env.template](.env.template) and
edit:

```bash
cp .env.template .env
```

| Variable | Default | Purpose |
|---|---|---|
| `CLAUDE_PROXY_LOG_LEVEL` | `INFO` | `DEBUG` to log headers + every placeholder ↔ value pair |
| `CLAUDE_PROXY_HOST` | `127.0.0.1` | Bind address for `python -m claude_proxy` |
| `CLAUDE_PROXY_PORT` | `8888` | Bind port for `python -m claude_proxy` |
| `CLAUDE_PROXY_UPSTREAM` | `https://api.anthropic.com` | Where to forward |

Quick offline sanity check (no API key, no network):

```bash
uv run python -c "
from claude_proxy.masking import mask, unmask
t = 'Email alice@example.com re ETH 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1 with glpat-abcdefghijklmnopqrst'
m = mask(t); print('MASKED:', m); print('ROUND-TRIPS:', unmask(m) == t)
"
```

## Layout

```
src/claude_proxy/
  recognizers.py    pattern data + register(engine)
  detection.py      Presidio analyzer + detect-secrets scanners
  masking.py        placeholder maps, splice, mask()/unmask() pipeline
  content.py        walks Anthropic Messages-API JSON bodies
  streaming.py      SSE delta buffering / unmask-while-streaming
  app.py            FastAPI app + routes + httpx client
```

Dependency direction is linear:
`recognizers` ← `detection` ← `masking` ← {`content`, `streaming`} ← `app`.

## Extending

**Add a new regex recognizer.** Append a tuple to `CUSTOM_PATTERNS` in
[recognizers.py](src/claude_proxy/recognizers.py). Patterns sharing an entity
type are auto-folded into one `PatternRecognizer`. Add the entity to
`ENTITY_TYPES` in the same file so Presidio surfaces it.

**Tune the entropy scanner.** Edit `BASE64_ENTROPY_LIMIT` / `HEX_ENTROPY_LIMIT`
/ `ENTROPY_MIN_LEN` in [detection.py](src/claude_proxy/detection.py). Raise the
limits if legitimate base64 (image data, signed URLs, CSP nonces) is being
masked; lower them to catch shorter / lower-entropy tokens at the cost of
more false positives.

**Target a different upstream API.** Replace [content.py](src/claude_proxy/content.py)
— it's the only module that knows about Anthropic's message shape — and
update the route in [app.py](src/claude_proxy/app.py).

## Caveats

- The forward/reverse placeholder maps live in process memory and are shared
  across all conversations the proxy sees. Restart the process to clear
  them. For multi-tenant use, swap the module-level dicts in
  [masking.py](src/claude_proxy/masking.py) for a keyed/TTL'd store.
- The `x-api-key` header passes through untouched. Headers are never masked,
  only request bodies.
- Tool-use round trips: if the model emits a placeholder inside
  `tool_use.input`, it reaches your tool runner as the placeholder, not the
  original. Add `tool_use` handling to `unmask_response` if your tools need
  the originals.
- Regex detection is best-effort. Over-masking is the safe failure mode;
  under-masking leaks. Tune entropy limits in `DS_PLUGINS` if legitimate
  base64 (image data, signed URLs, CSP nonces) is being masked.
- The proxy terminates TLS in plaintext on localhost. Don't expose it to a
  network you don't control.
