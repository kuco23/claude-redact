"""mask/unmask round-trip, placeholder format, dedup, opaque mode."""
from __future__ import annotations

import re

import pytest

from claude_proxy import masking
from claude_proxy.detection import Match
from claude_proxy.masking import (
    PLACEHOLDER_RE,
    _dedupe_overlaps,
    mask,
    placeholder_for,
    snapshot,
    splice,
    unmask,
)


# --- Round trip ----------------------------------------------------------

@pytest.mark.parametrize("text", [
    "",
    "no secrets here",
    "email alice@example.com",
    "key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "card 4111-1111-1111-1111 and ssn 123-45-6789",
    "ETH 0xAbCdEf0123456789AbCdEf0123456789AbCdEf01 followed by text",
])
def test_round_trip(text):
    assert unmask(mask(text)) == text


def test_unmask_unknown_placeholder_passes_through():
    """unmask() must not raise or strip placeholders it has no mapping for."""
    foreign = "<<MASK:API_KEY:0123456789abcdef>>"
    assert unmask(f"hello {foreign} world") == f"hello {foreign} world"


# --- Placeholder format --------------------------------------------------

def test_placeholder_shape_default():
    ph = placeholder_for("API_KEY", "secret-value-1")
    assert re.fullmatch(r"<<MASK:API_KEY:[0-9a-f]{16}>>", ph)


def test_placeholder_shape_opaque(monkeypatch):
    monkeypatch.setattr(masking, "OPAQUE", True)
    ph = placeholder_for("API_KEY", "secret-value-opaque")
    assert re.fullmatch(r"<<MASK:[0-9a-f]{16}>>", ph)


def test_placeholder_deterministic_for_same_value():
    a = placeholder_for("API_KEY", "shared-secret")
    b = placeholder_for("API_KEY", "shared-secret")
    assert a == b


def test_placeholder_differs_for_different_values():
    a = placeholder_for("API_KEY", "one")
    b = placeholder_for("API_KEY", "two")
    assert a != b


def test_placeholder_re_matches_both_lengths():
    # New 16-hex, legacy 10-hex, with and without entity-type segment.
    samples = [
        "<<MASK:API_KEY:0123456789abcdef>>",
        "<<MASK:0123456789abcdef>>",
        "<<MASK:API_KEY:0123456789>>",
        "<<MASK:0123456789>>",
    ]
    for s in samples:
        assert PLACEHOLDER_RE.fullmatch(s), s


# --- Splice + dedup ------------------------------------------------------

def test_splice_replaces_right_to_left():
    text = "ab CDEF gh IJKL mn"
    matches = [Match(3, 7, "X"), Match(11, 15, "Y")]
    out = splice(text, matches)
    # Both ranges replaced; the literal characters between/around are preserved.
    assert "ab " in out and " gh " in out and " mn" in out
    assert "CDEF" not in out and "IJKL" not in out


def test_dedupe_longest_wins_on_overlap():
    # A long match starting at the same offset as a short one — longest stays.
    long = Match(0, 10, "LONG")
    short = Match(0, 5, "SHORT")
    kept = _dedupe_overlaps([short, long])
    assert kept == [long]


def test_dedupe_keeps_disjoint_ranges():
    a = Match(0, 5, "A")
    b = Match(5, 10, "B")   # touching but not overlapping
    c = Match(11, 15, "C")
    kept = _dedupe_overlaps([a, b, c])
    assert kept == [a, b, c]


def test_dedupe_drops_inner_overlap():
    outer = Match(0, 20, "OUTER")
    inner = Match(5, 10, "INNER")
    kept = _dedupe_overlaps([outer, inner])
    assert kept == [outer]


# --- Pipeline integration -----------------------------------------------

def test_mask_entropy_pass_skips_placeholders():
    """The entropy scanner runs after the regex pass; it must not re-mask
    the hex inside an existing `<<MASK:…:hex>>` placeholder."""
    text = "api key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 done"
    masked = mask(text)
    # Exactly one placeholder (the API key), no nested HEX_SECRET re-mask.
    assert len(PLACEHOLDER_RE.findall(masked)) == 1


def test_mask_is_idempotent_on_known_values():
    """Masking already-masked text should not double-wrap (the placeholder
    body is itself hex+colons and the entropy scanner would otherwise grab
    parts of it)."""
    text = "ETH 0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
    once = mask(text)
    twice = mask(once)
    assert once == twice


def test_snapshot_returns_live_pairs():
    placeholder_for("API_KEY", "abc123")
    snap = snapshot()
    assert any(v == "abc123" for v in snap.values())
    # snapshot is a copy — mutating it must not affect the live map.
    snap.clear()
    assert snapshot() != {}


def test_mask_empty_string():
    assert mask("") == ""
    assert unmask("") == ""


def test_unmask_short_circuits_when_no_marker():
    """unmask returns the input unchanged when '<<MASK:' isn't present —
    cheap path that should not touch the regex."""
    s = "plain text with no placeholders"
    assert unmask(s) is s
