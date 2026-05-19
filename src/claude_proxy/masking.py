"""Placeholder substitution — the mask/unmask round trip.

Placeholder format: `<<MASK:ENTITY_TYPE:hex16>>` (default), or `<<MASK:hex16>>`
when `CLAUDE_PROXY_OPAQUE=1` — opaque mode strips the entity-type segment so
Anthropic can't infer the *kind* of secret from the placeholder shape, at
the cost of losing the entity-type cue for model reasoning.
  - 16-hex digest (64 bits) — birthday collision risk at ~4e9 unique values
  - deterministic per value — same secret gets the same token process-wide
  - bounded length (<= MAX_PLACEHOLDER_LEN) for streaming-buffer logic
  - distinctive enough that Claude's responses round-trip it back intact

The forward/reverse maps are module-globals on purpose: the proxy runs as a
single process and we want a single shared address space for the lifetime of
the conversation. For multi-tenant deployments, swap these for a keyed store.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from collections import Counter

from claude_proxy import detection
from claude_proxy.detection import Match

logger = logging.getLogger(__name__)
# Dedicated logger for plaintext ↔ placeholder pairs. Gated independently of
# the main logger by `CLAUDE_PROXY_LOG_VALUES` (see logging_config.py) so that
# `CLAUDE_PROXY_LOG_LEVEL=DEBUG` doesn't accidentally spill secrets to logs.
values_logger = logging.getLogger("claude_proxy.values")

_TRUTHY = {"1", "true", "yes", "on"}
OPAQUE = os.environ.get("CLAUDE_PROXY_OPAQUE", "").lower() in _TRUTHY

# Accept old 10-hex placeholders as well as new 16-hex ones, with or without
# the entity-type segment. Old format may still appear in conversation history
# after an upgrade or after toggling opaque mode; we want both `unmask` and
# the entropy scanner's skip-list to recognize them.
PLACEHOLDER_RE = re.compile(r"<<MASK:(?:[A-Z0-9_]+:)?[0-9a-f]{10,16}>>")
MAX_PLACEHOLDER_LEN = 64

_forward: dict[str, str] = {}
_reverse: dict[str, str] = {}


def placeholder_for(entity_type: str, value: str) -> str:
    """Return a stable placeholder for `value`, creating one on first use.
    Logs every application to `claude_proxy.values` (default suppressed; see
    CLAUDE_PROXY_LOG_VALUES) so the per-value pairs don't leak when the main
    logger is at DEBUG for protocol debugging."""
    ph = _forward.get(value)
    if ph is None:
        digest = hashlib.sha256(value.encode()).hexdigest()[:16]
        ph = f"<<MASK:{digest}>>" if OPAQUE else f"<<MASK:{entity_type}:{digest}>>"
        _forward[value] = ph
        _reverse[ph] = value
    values_logger.debug("masked %s: %r -> %s", entity_type, _short(value), ph)
    return ph


def snapshot() -> dict[str, str]:
    """Return a placeholder→plaintext copy of the live reverse map.
    Used by the audit route; callers should treat the result as sensitive."""
    return dict(_reverse)


def splice(text: str, matches: list[Match]) -> str:
    """Replace each match's range with its placeholder. Processes right-to-left
    so earlier offsets stay valid as the string shortens/grows. Overlapping
    matches are deduped (earliest, longest wins) — splicing two overlapping
    ranges corrupts the output."""
    out = text
    for m in sorted(_dedupe_overlaps(matches), key=lambda m: m.start, reverse=True):
        ph = placeholder_for(m.entity_type, out[m.start : m.end])
        out = out[: m.start] + ph + out[m.end :]
    return out


def _dedupe_overlaps(matches: list[Match]) -> list[Match]:
    if not matches:
        return matches
    # Sort by start asc; for ties, longer match first so it wins.
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept: list[Match] = [ordered[0]]
    for m in ordered[1:]:
        if m.start >= kept[-1].end:
            kept.append(m)
    return kept


def mask(text: str) -> str:
    """Two-pass detection + replacement pipeline.

    Pass 1: Presidio (built-in PII + custom regex recognizers).
    Pass 2: detect-secrets entropy detectors, skipping placeholder regions
            so we don't recursively mask `<<MASK:…:hex>>` as a hex secret.
    """
    if not text:
        return text
    entities = detection.find_entities(text)
    if entities:
        logger.info("presidio matched %s", dict(Counter(m.entity_type for m in entities)))
    text = splice(text, entities)
    masked_ranges = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]
    secrets = [
        m
        for m in detection.find_high_entropy(text)
        if not _overlaps_any(m, masked_ranges)
    ]
    if secrets:
        logger.info("entropy scanner matched %s", dict(Counter(m.entity_type for m in secrets)))
    return splice(text, secrets)


def unmask(text: str) -> str:
    """Restore every placeholder to its original value. Unknown placeholders
    are left untouched (they're harmless and may belong to another process).
    Each restoration is logged via `claude_proxy.values`."""
    if not text or "<<MASK:" not in text:
        return text
    debug = values_logger.isEnabledFor(logging.DEBUG)

    def _sub(m: re.Match[str]) -> str:
        ph = m.group(0)
        original = _reverse.get(ph)
        if original is None:
            return ph
        if debug:
            values_logger.debug("unmasked %s -> %r", ph, _short(original))
        return original

    return PLACEHOLDER_RE.sub(_sub, text)


def _overlaps_any(m: Match, ranges: list[tuple[int, int]]) -> bool:
    return any(m.start < end and m.end > start for start, end in ranges)


def _short(s: str, n: int = 40) -> str:
    return s if len(s) <= n else s[:n] + "…"
