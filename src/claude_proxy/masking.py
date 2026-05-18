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
import re

from claude_proxy import detection
from claude_proxy.detection import Match

PLACEHOLDER_RE = re.compile(r"<<MASK:[A-Z_]+:[0-9a-f]{10}>>")
MAX_PLACEHOLDER_LEN = 64

_forward: dict[str, str] = {}
_reverse: dict[str, str] = {}


def placeholder_for(entity_type: str, value: str) -> str:
    """Return a stable placeholder for `value`, creating one on first use."""
    cached = _forward.get(value)
    if cached is not None:
        return cached
    digest = hashlib.sha256(value.encode()).hexdigest()[:10]
    ph = f"<<MASK:{entity_type}:{digest}>>"
    _forward[value] = ph
    _reverse[ph] = value
    return ph


def splice(text: str, matches: list[Match]) -> str:
    """Replace each match's range with its placeholder. Processes right-to-left
    so earlier offsets stay valid as the string shortens/grows."""
    out = text
    for m in sorted(matches, key=lambda m: m.start, reverse=True):
        ph = placeholder_for(m.entity_type, out[m.start : m.end])
        out = out[: m.start] + ph + out[m.end :]
    return out


def mask(text: str) -> str:
    """Two-pass detection + replacement pipeline.

    Pass 1: Presidio (built-in PII + custom regex recognizers).
    Pass 2: detect-secrets entropy detectors, skipping placeholder regions
            so we don't recursively mask `<<MASK:…:hex>>` as a hex secret.
    """
    if not text:
        return text
    text = splice(text, detection.find_entities(text))
    masked_ranges = [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]
    secrets = [
        m
        for m in detection.find_high_entropy(text)
        if not _overlaps_any(m, masked_ranges)
    ]
    return splice(text, secrets)


def unmask(text: str) -> str:
    """Restore every placeholder to its original value. Unknown placeholders
    are left untouched (they're harmless and may belong to another process)."""
    if not text or "<<MASK:" not in text:
        return text
    return PLACEHOLDER_RE.sub(lambda m: _reverse.get(m.group(0), m.group(0)), text)


def _overlaps_any(m: Match, ranges: list[tuple[int, int]]) -> bool:
    return any(m.start < end and m.end > start for start, end in ranges)
