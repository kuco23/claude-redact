"""Structure-preserving substitution — the mask/unmask round trip.

Each detected secret is replaced with a freshly-randomized value of the
*same shape* (email→email, IPv4→IPv4, Luhn-valid CC→Luhn-valid CC, …)
rather than a tagged placeholder. The model sees plausible-looking data
and has no marker to "work around", which avoids the failure mode where
Claude breaks the marker apart with whitespace and the reverse map no
longer matches.

The forward/reverse maps are module-globals on purpose: the proxy runs as
a single process and we want a single shared address space for the lifetime
of the conversation. For multi-tenant deployments, swap these for a keyed
store.

Reverse map keys (the minted fakes) are matched **case-insensitively** on
the response leg — Claude sometimes case-normalizes quoted values, and
generated fakes are random enough that no two ever differ only by case.
"""
from __future__ import annotations

import logging
from collections import Counter

from claude_redact import detection, generators
from claude_redact.detection import Match

logger = logging.getLogger(__name__)
# Dedicated logger for plaintext ↔ fake pairs. Gated independently of the
# main logger by `CLAUDE_REDACT_LOG_VALUES` (see logging_config.py) so that
# `CLAUDE_REDACT_LOG_LEVEL=DEBUG` doesn't accidentally spill secrets to logs.
values_logger = logging.getLogger("claude_redact.values")

_forward: dict[str, str] = {}            # original → fake
_reverse: dict[str, str] = {}            # fake → original
_reverse_lower: dict[str, str] = {}      # fake.lower() → original (for unmask scan)

# Max length of any minted fake. The streaming buffer reads this to know how
# many trailing chars it must hold back across chunk boundaries.
_max_fake_len: int = 0

# Cap on regeneration attempts when a fake collides with an existing entry.
# With ~26^N entropy in random parts this should essentially never trip; the
# cap is just a defensive bound against pathological generators.
_MAX_REGEN_ATTEMPTS = 16


def fake_for(entity_type: str, value: str) -> str:
    """Return a stable fake for `value`, creating one on first use.
    Logs every application to `claude_redact.values` (default suppressed; see
    CLAUDE_REDACT_LOG_VALUES) so the per-value pairs don't leak when the
    main logger is at DEBUG for protocol debugging."""
    fake = _forward.get(value)
    if fake is None:
        fake = _mint(entity_type, value)
        _forward[value] = fake
        _reverse[fake] = value
        _reverse_lower[fake.lower()] = value
        global _max_fake_len
        if len(fake) > _max_fake_len:
            _max_fake_len = len(fake)
    values_logger.debug("masked %s: %r -> %r", entity_type, _short(value), _short(fake))
    return fake


def _mint(entity_type: str, value: str) -> str:
    """Generate a fake.

    In keyed mode (`CLAUDE_REDACT_SEED` set), the generator is a deterministic
    function of (seed, entity_type, value), so retrying would produce the
    same output — we just accept the result. Collisions (different originals
    mapping to the same fake) are negligible for HMAC-SHA256-seeded streams
    against fakes with hundreds of bits of entropy.

    In unkeyed mode the generator is random per call, so we retry on the
    rare case where a freshly minted fake collides with an existing reverse-
    map entry or happens to equal the original verbatim."""
    if generators._SEED is not None:
        return generators.generate(entity_type, value)
    for _ in range(_MAX_REGEN_ATTEMPTS):
        fake = generators.generate(entity_type, value)
        if fake != value and fake.lower() not in _reverse_lower:
            return fake
    # Fall through — accept whatever the last call returned. Practically
    # unreachable for the entity shapes we support.
    return generators.generate(entity_type, value)


def max_fake_len() -> int:
    """Return the longest fake currently in the reverse map. Used by the
    streaming buffer to size its hold-back window."""
    return _max_fake_len


def snapshot() -> dict[str, str]:
    """Return a fake → plaintext copy of the live reverse map. Used by the
    audit route; callers should treat the result as sensitive."""
    return dict(_reverse)


def splice(text: str, matches: list[Match]) -> tuple[str, list[tuple[int, int]]]:
    """Replace each match's range with its fake. Processes right-to-left so
    earlier offsets stay valid as the string shortens/grows. Overlapping
    matches are deduped (earliest, longest wins) — splicing two overlapping
    ranges corrupts the output.

    Returns `(new_text, ranges_in_new_text)` so the caller can avoid
    re-scanning the substituted regions (e.g. the entropy pass mustn't
    re-mask a HEX_SECRET-shaped fake it just minted)."""
    deduped = sorted(_dedupe_overlaps(matches), key=lambda m: m.start)
    if not deduped:
        return text, []
    # Build the output left-to-right, tracking each fake's range in the new text.
    out: list[str] = []
    new_ranges: list[tuple[int, int]] = []
    cursor = 0
    new_pos = 0
    for m in deduped:
        out.append(text[cursor : m.start])
        new_pos += m.start - cursor
        fake = fake_for(m.entity_type, text[m.start : m.end])
        out.append(fake)
        new_ranges.append((new_pos, new_pos + len(fake)))
        new_pos += len(fake)
        cursor = m.end
    out.append(text[cursor:])
    return "".join(out), new_ranges


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

    Pass 1: regex recognizers (built-in PII + custom patterns) and the
            phonenumbers scanner.
    Pass 2: entropy detectors, skipping the ranges we just spliced so we
            don't re-mask a freshly-minted HEX_SECRET-shaped fake.

    Both passes also skip any range that overlaps a substring already
    known to be a minted fake. Without this, mask is not idempotent —
    the fakes themselves are entity-shaped and the scanners would happily
    re-mask them (or their substrings — the entropy scanner can latch
    onto the high-entropy body of an API key fake) on a second pass,
    mutating substitutions across turns and breaking unmask.
    """
    if not text:
        return text
    skip = _find_known_fake_ranges(text)
    entities = [
        m for m in detection.find_entities(text)
        if not _overlaps_any(m, skip)
    ]
    if entities:
        logger.info("regex matched %s", dict(Counter(m.entity_type for m in entities)))
    text, masked_ranges = splice(text, entities)
    # Skip regions shift after splice; re-locate.
    skip = _find_known_fake_ranges(text)
    secrets = [
        m
        for m in detection.find_high_entropy(text)
        if not _overlaps_any(m, masked_ranges)
        and not _overlaps_any(m, skip)
    ]
    if secrets:
        logger.info("entropy scanner matched %s", dict(Counter(m.entity_type for m in secrets)))
    text, _ = splice(text, secrets)
    return text


def _find_known_fake_ranges(text: str) -> list[tuple[int, int]]:
    """Return non-overlapping ranges in `text` that exactly contain a
    minted fake. Case-insensitive (matches the unmask scan), longest-first
    so we never mark a substring of a longer fake as the "fake region"
    when the longer one was actually present."""
    if not _reverse_lower or not text:
        return []
    text_lower = text.lower()
    ranges: list[tuple[int, int]] = []
    for f in sorted(_reverse_lower.keys(), key=len, reverse=True):
        start = 0
        while True:
            i = text_lower.find(f, start)
            if i == -1:
                break
            r = (i, i + len(f))
            if not _overlaps_any_pair(r, ranges):
                ranges.append(r)
            start = i + len(f)
    return ranges


def _overlaps_any_pair(r: tuple[int, int], ranges: list[tuple[int, int]]) -> bool:
    rs, re_ = r
    return any(rs < e and re_ > s for s, e in ranges)


def unmask(text: str) -> str:
    """Restore every minted fake to its original value.

    Match is case-insensitive (Claude sometimes case-normalizes quoted
    values). Longest-first to handle the case where one fake is a prefix
    of another (vanishingly rare for random strings, but cheap to be safe).
    Each restoration is logged via `claude_redact.values`."""
    if not text or not _reverse_lower:
        return text
    flushed, _ = _scan(text, hold_partials=False)
    return flushed


def scan_with_hold(text: str) -> tuple[str, str]:
    """Streaming-aware scan. Returns `(flushed_text, held_raw_tail)`.

    Identical to `unmask` except that if the tail of `text` is a prefix
    of some known fake (i.e. a fake may still be arriving in a later
    chunk), the unmatched tail is returned in `held_raw_tail` instead
    of being emitted. The caller is expected to prepend `held_raw_tail`
    to the next chunk and call again. Use `flush_hold` at stream end."""
    if not text:
        return "", ""
    if not _reverse_lower:
        return text, ""
    return _scan(text, hold_partials=True)


def flush_hold(tail: str) -> str:
    """Unmask whatever's left over at `content_block_stop` time. No partial
    holding — the stream is over, anything that looked like an in-flight
    fake never finished arriving, so we emit it verbatim."""
    if not tail:
        return ""
    return unmask(tail)


def _scan(text: str, *, hold_partials: bool) -> tuple[str, str]:
    """Walk `text` left-to-right, replacing any fake whose lowercase form
    matches at the current offset. Longest-first per position.

    When `hold_partials` is True, stop at the first position where the
    remaining text is a non-empty prefix of some known fake — the rest is
    returned as `held` for the caller to prepend to the next chunk."""
    debug = values_logger.isEnabledFor(logging.DEBUG)
    text_lower = text.lower()
    n = len(text)
    # Sort fakes by length desc so the longest match at each position wins.
    fakes_lower = sorted(_reverse_lower.keys(), key=len, reverse=True)
    out: list[str] = []
    i = 0
    while i < n:
        # Full-match attempt: fake fully present in text starting at i.
        matched_len = 0
        matched_orig: str | None = None
        for f in fakes_lower:
            L = len(f)
            if i + L <= n and text_lower[i : i + L] == f:
                matched_len = L
                matched_orig = _reverse_lower[f]
                break
        if matched_orig is not None:
            out.append(matched_orig)
            if debug:
                values_logger.debug("unmasked %r -> %r",
                                    _short(text[i : i + matched_len]),
                                    _short(matched_orig))
            i += matched_len
            continue
        # Partial-match probe: if text[i:] is a strict prefix of any fake
        # longer than (n - i), we don't know yet whether that fake is
        # actually arriving. Hold from here.
        if hold_partials and i < n:
            remaining = text_lower[i:]
            if any(len(f) > len(remaining) and f.startswith(remaining) for f in fakes_lower):
                return "".join(out), text[i:]
        out.append(text[i])
        i += 1
    return "".join(out), ""


def _overlaps_any(m: Match, ranges: list[tuple[int, int]]) -> bool:
    return any(m.start < end and m.end > start for start, end in ranges)


def _short(s: str, n: int = 40) -> str:
    return s if len(s) <= n else s[:n] + "…"
