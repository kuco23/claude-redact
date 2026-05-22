# claude-redact

A local HTTP reverse proxy that sits in front of `api.anthropic.com` and masks
secrets / PII in both directions: detected entities in outbound request bodies
are replaced with structure-preserving fakes (an email becomes an email, an
IPv4 becomes an IPv4, a Luhn-valid credit card becomes a Luhn-valid credit
card), and inbound responses (including SSE streams) are un-masked before
reaching the client.

Point Claude Code or any Anthropic SDK at the proxy via `ANTHROPIC_BASE_URL`
and your prompts will reach Anthropic with phone numbers, API keys, crypto
addresses, PEM private keys, JWTs, high-entropy tokens, etc. swapped for
plausible-looking decoys — while you still see the originals in the model's
replies.

## How it works

Detection runs in two passes:

1. **Regex recognizers** — built-in PII (emails, SSNs, credit cards with
   Luhn check, IPv4/IPv6) plus a curated table of patterns for UUIDs, JWTs,
   PEM private keys, hex hashes, EVM/BTC/LTC/DOGE/XRP/TRX/XMR/ADA/BCH
   addresses, and provider-prefixed API keys (Anthropic, OpenAI, Stripe,
   GitHub classic + fine-grained, GitLab, AWS, Google, Slack, plus a set
   adapted from gitleaks). Phone numbers use `phonenumbers.PhoneNumberMatcher`
   directly because a single regex can't capture all valid international forms.
2. A small **entropy scanner** runs on the already-masked text: regex-extract
   base64- or hex-shaped runs of 20+ chars, then Shannon-entropy filter at
   4.5 / 3.0 bits per char. Catches opaque tokens that don't fit any known
   prefix; rejects ordinary English.

Each detected range is replaced with a value of the same shape (see
[generators.py](src/claude_redact/generators.py)) — a `sk-ant-…` key
becomes another `sk-ant-…` key of the same length, a `0x…` Ethereum
address becomes another 40-hex Ethereum address, a `4111…` Luhn-valid card
becomes another Luhn-valid card with the same separator pattern, and so on.

When `CLAUDE_REDACT_SEED` is set, the fake is a deterministic function of
`(seed, entity_type, original_value)` — HMAC-SHA256 keys a fresh RNG per
call, and the generator runs against that. Same secret produces the same
fake across processes, machines, and restarts, so the model keeps seeing
stable references for "the user's wallet" vs. "your API key" even after
the proxy is restarted or the conversation resumes days later. Without a
seed, fakes are random per process (no persistence). The reverse map is
applied on the way back, scanning for any minted fake case-insensitively
(Claude sometimes case-normalizes quoted values). SSE streaming holds
back any tail that is a strict prefix of a known fake so chunk-boundary
splits never half-flush.

Compared to a tagged-placeholder scheme (`<<MASK:ENTITY:hash>>`), this
removes the marker that the model could inadvertently break — paraphrasing
a fake email is still a fake email, but mangling `<<MASK:…>>` with
whitespace breaks the reverse lookup. The tradeoff is the new failure mode:
if Claude paraphrases or truncates a fake in its reply, the case-insensitive
exact-match scan won't restore it. In practice models leave realistic-
looking values intact far more often than they leave structured markers
intact. Neither design defends against an *adversarial* model that
fragments output to evade the scan — see the caveat on exfiltration below.

## Install

Requires Python 3.13+ and [uv](https://github.com/astral-sh/uv).

```bash
uv sync
```

## Run

Pick one:

```bash
uv run python -m claude_redact
uv run uvicorn claude_redact:app --host 127.0.0.1 --port 8888
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

## Devcontainer

The repo ships a devcontainer config that runs the proxy as a sidecar so
Claude Code inside the container talks to Anthropic *through* claude-redact
by default. You don't have to start the proxy by hand or set
`ANTHROPIC_BASE_URL` — both are wired up by [docker-compose.yaml](.devcontainer/docker-compose.yaml).

**Layout.**

```
.devcontainer/
  devcontainer.json    dev image config, VS Code extensions, postCreate steps
  docker-compose.yaml  two services: dev (built locally) + claude-redact (sidecar)
  Dockerfile           dev-image base (Python + uv + dev tooling)
  initialize.sh        runs on the host before the container starts
```

The `dev` service depends on the `claude-redact` service being healthy
and sets `ANTHROPIC_BASE_URL=http://claude-redact:8888` in its
environment. The sidecar image is pulled from
`ghcr.io/kuco23/claude-redact:latest` (override the tag in
[docker-compose.yaml](.devcontainer/docker-compose.yaml) if you want to
pin a version or point at a local build).

**Open in VS Code.**

1. Install the "Dev Containers" extension (`ms-vscode-remote.remote-containers`).
2. `git clone` this repo and open the folder in VS Code.
3. When prompted, *Reopen in Container* — or run **Dev Containers: Reopen in Container** from the command palette.

On first start, [initialize.sh](.devcontainer/initialize.sh) runs on the
host and:

- creates `~/.claude/` and `~/.claude.json` if they don't exist (Claude
  Code's config is bind-mounted in, so your auth persists across rebuilds);
- writes `WORKSPACE_NAME=$(basename "$PWD")` to `.devcontainer/.env` so
  the bind-mount path matches whatever directory you cloned into.

After the container is up, `postCreateCommand` installs Claude Code and
runs `uv sync`. Open a terminal inside the container and run `claude` —
all traffic flows through the sidecar proxy automatically.

**Open from the CLI.** If you prefer the `devcontainer` CLI to VS Code:

```bash
npm install -g @devcontainers/cli
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . claude
```

**Verify the proxy is in the path.** Inside the container:

```bash
echo "$ANTHROPIC_BASE_URL"               # http://claude-redact:8888
curl -s http://claude-redact:8888/_health  # {"status":"ok"}
```

**Persistent secret bindings.** On first run, [initialize.sh](.devcontainer/initialize.sh)
mints a 256-bit hex `CLAUDE_REDACT_SEED` into `.devcontainer/.env` and
[docker-compose.yaml](.devcontainer/docker-compose.yaml) passes it through
to the sidecar. The proxy then derives every fake deterministically from
that seed, so the same real secret keeps mapping to the same decoy across
container rebuilds — Claude won't suddenly see "your API key" change
identity between sessions. To reset all bindings, delete the
`CLAUDE_REDACT_SEED=…` line from `.devcontainer/.env` and rebuild the
container; initialize.sh will mint a fresh seed.

**Rebuild after changing the proxy.** The sidecar runs a *published*
image; local changes to `src/claude_redact/` don't affect it. To test
changes against the live container, either rebuild and push the image,
or swap the sidecar's `image:` line for a local `build:` block pointing
at the repo's [Dockerfile](Dockerfile) and rerun *Rebuild Container*.

## Configuration

Settings come from environment variables; `.env` at the project root is
loaded automatically at startup. Copy [.env.template](.env.template) and
edit:

```bash
cp .env.template .env
```

| Variable | Default | Purpose |
|---|---|---|
| `CLAUDE_REDACT_LOG_LEVEL` | `INFO` | `DEBUG` enables protocol-flow tracing (no plaintext) |
| `CLAUDE_REDACT_LOG_VALUES` | `0` | `1` logs each fake ↔ plaintext pair via `claude_redact.values` |
| `CLAUDE_REDACT_AUDIT` | `0` | `1` exposes `GET /_audit/mappings` returning the live map as JSON |
| `CLAUDE_REDACT_SEED` | _(unset)_ | Keying material. When set, fakes are a deterministic function of `(seed, entity_type, original)` — same secret always maps to the same fake across processes. **Sensitive: treat as a password / API key.** See caveat below |
| `CLAUDE_REDACT_HOST` | `127.0.0.1` | Bind address for `python -m claude_redact` |
| `CLAUDE_REDACT_PORT` | `8888` | Bind port for `python -m claude_redact` |
| `CLAUDE_REDACT_UPSTREAM` | `https://api.anthropic.com` | Where to forward |

Quick offline sanity check (no API key, no network):

```bash
uv run python -c "
from claude_redact.masking import mask, unmask
t = 'Email alice@example.com re ETH 0x1234567890abcdef1234567890abcdef12345678 with sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGGhhhh1234'
m = mask(t); print('MASKED:', m); print('ROUND-TRIPS:', unmask(m) == t)
"
```

## Layout

```
src/claude_redact/
  detection.py      pattern table + regex/phone/entropy scanners
  generators.py     per-entity-type shape-matching fake producers
  masking.py        forward/reverse maps, splice, mask()/unmask() pipeline
  content.py        walks Anthropic Messages-API JSON bodies
  streaming.py      SSE delta buffering / unmask-while-streaming
  app.py            FastAPI app + routes + httpx client
```

Dependency direction is linear:
`detection`, `generators` ← `masking` ← {`content`, `streaming`} ← `app`.

## Extending

**Add a new regex recognizer.** Append a tuple `(entity_type, regex, validator)`
to `PATTERNS` in [detection.py](src/claude_redact/detection.py). The validator
is optional (`None` to keep every regex hit, or a callable that returns
`False` to reject a match — see `_luhn_ok` and `_valid_ipv4`). If the new
`entity_type` isn't already in `generators._GENERATORS`, add a matching
generator there too — without one the fallback emits same-length random
alnum, which works but isn't as realistic as a purpose-built shape.

**Tune the entropy scanner.** Edit `BASE64_ENTROPY_LIMIT` / `HEX_ENTROPY_LIMIT`
/ `ENTROPY_MIN_LEN` in [detection.py](src/claude_redact/detection.py). Raise the
limits if legitimate base64 (image data, signed URLs, CSP nonces) is being
masked; lower them to catch shorter / lower-entropy tokens at the cost of
more false positives.

**Target a different upstream API.** Replace [content.py](src/claude_redact/content.py)
— it's the only module that knows about Anthropic's message shape — and
update the route in [app.py](src/claude_redact/app.py).

## Caveats

- The forward/reverse fake maps live in process memory and are shared
  across all conversations the proxy sees. Restart the process to clear
  them. Inspect the live map at any time with
  `CLAUDE_REDACT_AUDIT=1 … && curl http://127.0.0.1:8888/_audit/mappings`.
  For multi-tenant use, swap the module-level dicts in
  [masking.py](src/claude_redact/masking.py) for a keyed/TTL'd store —
  otherwise session B can fetch fakes minted by session A by guessing
  or echoing them.
- `CLAUDE_REDACT_SEED` is the keying material for the fake generator.
  When set, the proxy guarantees that the same secret always produces the
  same fake — across restarts, conversations, and machines. This is what
  lets a conversation resumed days later still see "the user's wallet"
  bound to the same decoy the model already learned. Without a seed,
  bindings only live in process memory and a restart resets every fake.
  **The seed is sensitive.** Anyone who knows it can mount a known-
  plaintext attack: for any candidate original X, derive what fake X would
  produce, compare to a fake they observed on the wire, and confirm X
  matches. Use a high-entropy value (256-bit hex from `openssl rand -hex
  32` is the default the devcontainer mints), never commit it, never log
  it, and rotate it if you suspect exposure (which invalidates every
  in-memory binding from the previous seed — by design).
- Un-masking is a case-insensitive exact-string match. If the model
  paraphrases, truncates, or otherwise alters a fake in its response, the
  scanner can't restore the original — the mangled fake leaks through to
  the client as-is. (It's still a fake, so no secret leaks; the user just
  sees gibberish.) The previous tagged-placeholder design had the inverse
  failure mode: the model would sometimes split the marker with whitespace
  and break the round-trip entirely.
- **The proxy is not an adversarial-model defense.** The threat model is
  benign Claude + curious upstream operator: the proxy stops secrets from
  reaching Anthropic's wire and storage, and stops fakes from reaching the
  user's screen. It does *not* stop a Claude that actively wants to leak.
  Two channels remain open by construction:
  - **Fragmenting fakes** to bypass unmask. The scanner does an exact
    case-insensitive substring lookup against the reverse map. Splitting a
    fake (`pterc @uxzmpwu.com`, zero-width characters, char-per-line) is
    enough to defeat the match, so the fake reaches the user verbatim.
    Useful for *you* — it's how you inspect what fake Claude is holding
    without enabling the audit endpoint — but it also means an adversarial
    Claude can emit fakes that the user reads raw.
  - **Character-at-a-time exfiltration** of originals. Single characters
    don't match any entity regex, so a Claude that cooperates with the user
    (or with a prompt-injected instruction) can elicit the original value
    one char at a time and reconstruct it. Structure-preserving fakes did
    not close this channel; nothing in a forward-direction redactor can.
    The mitigation is the trust model — don't pipe secrets through a proxy
    that you're simultaneously asking the model to defeat.
- The `x-api-key` header passes through untouched. Headers are never masked,
  only request bodies.
- Un-masking covers both `text` blocks (so the user reads plaintext in
  chat) and `tool_use.input` (so local tools receive real values). The
  request leg re-masks every `text` block in the message history regardless
  of role, so plaintext that lands in Claude Code's local transcript is
  re-redacted before reaching Anthropic on the next turn. Net effect:
  plaintext is visible on your machine; only fakes cross the wire.
- Regex detection is best-effort. Over-masking is the safe failure mode;
  under-masking leaks. Tune entropy limits in `DS_PLUGINS` if legitimate
  base64 (image data, signed URLs, CSP nonces) is being masked.
- The proxy terminates TLS in plaintext on localhost. Don't expose it to a
  network you don't control.
- `CLAUDE_REDACT_LOG_VALUES=1` mirrors every secret the proxy sees (paired
  with its minted fake) into your log stream. Useful while debugging
  recognizers; treat the resulting log as sensitive (journald, file, tmux
  scrollback all inherit the trust level of the proxy's memory). It's
  gated independently of `CLAUDE_REDACT_LOG_LEVEL` so `DEBUG`-level
  protocol tracing stays safe to share.
