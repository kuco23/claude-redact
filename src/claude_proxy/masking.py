"""Placeholder substitution — the mask/unmask round trip.

Placeholder format: `<<MASK:ENTITY_TYPE:hex10>>`
  - deterministic per (entity_type, value) — same secret gets the same token
    for the lifetime of the process
  - bounded length (<= MAX_PLACEHOLDER_LEN), needed by the streaming-buffer logic
  - distinctive enough that Claude's responses round-trip it back intact

The forward/reverse maps are module-globals on purpose: the proxy runs as a
single process and we want a single shared address space for the lifetime of
the conversation. For multi-tenant deployments, swap these for a keyed store.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter

from claude_proxy import detection
from claude_proxy.detection import Match

logger = logging.getLogger(__name__)

PLACEHOLDER_RE = re.compile(r"<<MASK:[A-Z0-9_]+:[0-9a-f]{10}>>")
MAX_PLACEHOLDER_LEN = 64

_forward: dict[str, str] = {}
_reverse: dict[str, str] = {}


def placeholder_for(entity_type: str, value: str) -> str:
    """Return a stable placeholder for `value`, creating one on first use.
    Logs each newly-minted mapping at DEBUG so you can see what got masked
    without having to dump the entire request body."""
    cached = _forward.get(value)
    if cached is not None:
        return cached
    digest = hashlib.sha256(value.encode()).hexdigest()[:10]
    ph = f"<<MASK:{entity_type}:{digest}>>"
    _forward[value] = ph
    _reverse[ph] = value
    logger.debug("masked %s: %r -> %s", entity_type, _short(value), ph)
    return ph


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
    Each restoration is logged at DEBUG."""
    if not text or "<<MASK:" not in text:
        return text
    debug = logger.isEnabledFor(logging.DEBUG)

    def _sub(m: re.Match[str]) -> str:
        ph = m.group(0)
        original = _reverse.get(ph)
        if original is None:
            return ph
        if debug:
            logger.debug("unmasked %s -> %r", ph, _short(original))
        return original

    return PLACEHOLDER_RE.sub(_sub, text)


def _overlaps_any(m: Match, ranges: list[tuple[int, int]]) -> bool:
    return any(m.start < end and m.end > start for start, end in ranges)


def _short(s: str, n: int = 40) -> str:
    return s if len(s) <= n else s[:n] + "…"
