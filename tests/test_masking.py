"""mask/unmask round-trip, fake-shape invariants, dedup, streaming hold."""
from __future__ import annotations

import re

import pytest

from claude_redact import generators, masking
from claude_redact.detection import Match, _luhn_ok, _valid_ipv4
from claude_redact.masking import (
    _dedupe_overlaps,
    fake_for,
    flush_hold,
    mask,
    scan_with_hold,
    snapshot,
    splice,
    unmask,
)


# --- Round trip ----------------------------------------------------------

@pytest.mark.parametrize("text", [
    "",
    "no secrets here at all",
    "email me at jane.doe@example.com today",
    "API key sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGG1234 here",
    "card 4111-1111-1111-1111 and SSN 123-45-6789 together",
    "ETH 0xAbCdEf1234567890abcdef1234567890ABCDEF12 followed by text",
    "multiline\nemail one@two.com\nip 10.20.30.40\nend",
])
def test_round_trip(text):
    assert unmask(mask(text)) == text


def test_unmask_unknown_string_passes_through():
    """unmask() must leave text containing no known fake untouched."""
    assert unmask("hello world with no fakes") == "hello world with no fakes"


# --- Fake shape ----------------------------------------------------------

def test_email_fake_is_an_email():
    fake = fake_for("EMAIL_ADDRESS", "alice@example.com")
    assert "@" in fake and "." in fake.split("@", 1)[1]
    assert fake != "alice@example.com"


def test_ipv4_fake_is_valid_ipv4():
    fake = fake_for("IP_ADDRESS", "192.168.1.42")
    assert _valid_ipv4(fake)
    assert fake.count(".") == 3
    assert fake != "192.168.1.42"


def test_credit_card_fake_is_luhn_valid():
    fake = fake_for("CREDIT_CARD", "4111111111111111")
    assert _luhn_ok(fake)
    assert fake != "4111111111111111"


def test_credit_card_fake_preserves_separator_pattern():
    """A dashed CC input gets a dashed CC fake (and stays Luhn-valid)."""
    fake = fake_for("CREDIT_CARD", "4111-1111-1111-1111")
    assert fake.count("-") == 3
    assert _luhn_ok(fake)


def test_ssn_fake_passes_ssn_constraints():
    """Area not 000/666/9XX; group not 00; serial not 0000."""
    for orig in ["123-45-6789", "555-12-3456"]:
        fake = fake_for("US_SSN", orig)
        m = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", fake)
        assert m
        area, group, serial = m.groups()
        assert area != "000" and area != "666" and not area.startswith("9")
        assert group != "00"
        assert serial != "0000"


def test_uuid_fake_is_uuid_shape():
    fake = fake_for("UUID", "550e8400-e29b-41d4-a716-446655440000")
    assert re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", fake)


def test_eth_fake_keeps_0x_prefix():
    fake = fake_for("ETH_ADDRESS", "0x" + "a" * 40)
    assert fake.startswith("0x")
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", fake)


def test_eth_private_key_fake_is_0x_plus_64_hex():
    """Regression: 0x + 64 hex (canonical secp256k1 / EVM private key) is its
    own entity. Neither ETH_ADDRESS (only 40 hex) nor HASH (`\\b`-anchored,
    can't latch past the `0x` prefix since `x` is a word char) caught it
    before, so every EVM private key in a JSON blob passed through
    unmasked."""
    orig = "0x6fbbd4885827f6174c2b20176bca48099e23d6adbea7c05e6b9bf133041ef537"
    fake = fake_for("ETH_PRIVATE_KEY", orig)
    assert fake.startswith("0x")
    assert re.fullmatch(r"0x[0-9a-fA-F]{64}", fake)
    assert fake != orig


def test_mask_catches_0x_prefixed_private_key_in_context():
    """End-to-end: a private key embedded in JSON-like text must be redacted
    and the round trip must restore the original."""
    text = (
        '"private_key": '
        '"0x6fbbd4885827f6174c2b20176bca48099e23d6adbea7c05e6b9bf133041ef537"'
    )
    masked = mask(text)
    assert "0x6fbbd4885827f6174c2b20176bca48099e23d6adbea7c05e6b9bf133041ef537" not in masked
    assert unmask(masked) == text


def test_api_key_fake_keeps_provider_prefix():
    """The generator sniffs the provider prefix so the fake re-matches the
    same recognizer (and Claude still gets a hint that it's an Anthropic key,
    not a Stripe one)."""
    orig = "sk-ant-api03-AAAAbbbbCCCCddddEEEEffffGGGGhhhh1234"
    fake = fake_for("API_KEY", orig)
    assert fake.startswith("sk-ant-")
    assert len(fake) == len(orig)


def test_hex_fake_matches_length():
    orig = "abcdef" * 6 + "1234"  # 40 hex chars
    fake = fake_for("HASH", orig)
    assert len(fake) == len(orig)
    assert re.fullmatch(r"[0-9a-f]{40}", fake)


def test_fake_deterministic_for_same_value():
    a = fake_for("API_KEY", "sk-shared-secret-AAAAAAAAAAAAAAAA")
    b = fake_for("API_KEY", "sk-shared-secret-AAAAAAAAAAAAAAAA")
    assert a == b


def test_fake_differs_for_different_values():
    a = fake_for("API_KEY", "sk-one-AAAAAAAAAAAAAAAAAAAAAAAA")
    b = fake_for("API_KEY", "sk-two-AAAAAAAAAAAAAAAAAAAAAAAA")
    assert a != b


def test_fake_never_equals_original():
    """The generator never returns the input verbatim — that would mean the
    secret isn't actually being redacted."""
    for entity, val in [
        ("EMAIL_ADDRESS", "user@example.com"),
        ("IP_ADDRESS", "192.168.1.1"),
        ("UUID", "550e8400-e29b-41d4-a716-446655440000"),
        ("HASH", "deadbeef" * 5),
    ]:
        assert fake_for(entity, val) != val


def test_keyed_determinism_across_fresh_maps():
    """With a fixed seed (set by conftest), wiping the in-memory maps and
    re-minting the same secret must produce the same fake. This is the
    cross-process / cross-restart guarantee — a new process is functionally
    indistinguishable from "same process, maps cleared"."""
    first = fake_for("API_KEY", "sk-some-secret-XXXXXXXXXXXXXXXXXXXXXX")
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    masking._max_fake_len = 0
    second = fake_for("API_KEY", "sk-some-secret-XXXXXXXXXXXXXXXXXXXXXX")
    assert first == second


def test_keyed_different_seeds_produce_different_fakes():
    """Same value + different seed = different fake."""
    val = "alice@example.com"
    generators._SEED = b"seed-A"
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    fake_a = fake_for("EMAIL_ADDRESS", val)
    generators._SEED = b"seed-B"
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    fake_b = fake_for("EMAIL_ADDRESS", val)
    assert fake_a != fake_b


def test_unkeyed_mode_still_works_and_is_random():
    """When the seed is unset, the generator falls back to OS-random per
    process. Re-minting after a map wipe gives a different fake."""
    generators._SEED = None
    val = "bob@example.com"
    first = fake_for("EMAIL_ADDRESS", val)
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    second = fake_for("EMAIL_ADDRESS", val)
    # No determinism guarantee here — two random fakes are overwhelmingly
    # likely to differ. (If this flakes once in a generation, treat it as
    # a lottery win and rerun.)
    assert first != second


# --- Splice + dedup ------------------------------------------------------

def test_splice_replaces_matches():
    text = "ab CDEF gh IJKL mn"
    # Use entity types that have generators; values are just the matched substrings.
    matches = [Match(3, 7, "HEX_SECRET"), Match(11, 15, "HEX_SECRET")]
    out, ranges = splice(text, matches)
    assert "CDEF" not in out and "IJKL" not in out
    assert len(ranges) == 2


def test_splice_returns_post_substitution_ranges():
    """The entropy pass needs the ranges in the post-splice text, not in the
    input — fakes can change length."""
    text = "X" * 10  # placeholder, won't actually match
    matches = [Match(2, 5, "HEX_SECRET")]
    out, ranges = splice(text, matches)
    s, e = ranges[0]
    # The range in the new text points at the inserted fake.
    assert out[s:e] == fake_for("HEX_SECRET", text[2:5])


def test_dedupe_longest_wins_on_overlap():
    long = Match(0, 10, "LONG")
    short = Match(0, 5, "SHORT")
    kept = _dedupe_overlaps([short, long])
    assert kept == [long]


def test_dedupe_keeps_disjoint_ranges():
    a = Match(0, 5, "A")
    b = Match(5, 10, "B")
    c = Match(11, 15, "C")
    kept = _dedupe_overlaps([a, b, c])
    assert kept == [a, b, c]


def test_dedupe_drops_inner_overlap():
    outer = Match(0, 20, "OUTER")
    inner = Match(5, 10, "INNER")
    kept = _dedupe_overlaps([outer, inner])
    assert kept == [outer]


# --- Pipeline integration -----------------------------------------------

def test_mask_entropy_pass_skips_just_minted_fakes():
    """A HEX_SECRET-shaped fake minted in pass 1 looks like a HEX_SECRET to
    the entropy scanner — pass 2 must skip the ranges it just produced or
    the substitution would be unstable."""
    text = "api key abcdef1234567890abcdef1234567890abcdef done"
    masked = mask(text)
    # Re-running mask on the result should change nothing.
    assert mask(masked) == masked


def test_mask_is_idempotent_on_already_masked_text():
    text = "ETH 0xAbCdEf1234567890abcdef1234567890ABCDEF12 and email a@b.com"
    once = mask(text)
    twice = mask(once)
    assert once == twice


def test_unmask_is_case_insensitive():
    """Claude sometimes case-normalizes quoted values. The unmask scan should
    still restore the original even if the fake comes back uppercased."""
    fake = fake_for("EMAIL_ADDRESS", "alice@example.com")
    out = unmask(f"contact {fake.upper()} please")
    assert "alice@example.com" in out


def test_snapshot_returns_live_pairs():
    fake_for("API_KEY", "sk-some-secret-AAAAAAAAAAAAAAAAAAAAAA")
    snap = snapshot()
    assert any(v == "sk-some-secret-AAAAAAAAAAAAAAAAAAAAAA" for v in snap.values())
    # snapshot is a copy — mutating it must not affect the live map.
    snap.clear()
    assert snapshot() != {}


def test_mask_empty_string():
    assert mask("") == ""
    assert unmask("") == ""


def test_unmask_short_circuits_on_empty_reverse_map():
    """With no fakes minted, unmask is a no-op and returns the input by value
    equality (no full scan needed)."""
    masking._reverse.clear()
    masking._reverse_lower.clear()
    s = "plain text with no fakes"
    assert unmask(s) == s


# --- Streaming-aware scan -----------------------------------------------

def test_scan_with_hold_no_fakes_flushes_everything():
    """With an empty reverse map, scan_with_hold returns everything in flush."""
    flushed, held = scan_with_hold("just some text")
    assert flushed == "just some text"
    assert held == ""


def test_scan_with_hold_complete_fake_in_buffer_unmasks():
    fake = fake_for("EMAIL_ADDRESS", "alice@example.com")
    flushed, held = scan_with_hold(f"hi {fake} bye")
    assert "alice@example.com" in flushed
    assert held == ""


def test_scan_with_hold_partial_fake_tail_held():
    """If the tail of the buffer is a strict prefix of a known fake, hold it."""
    fake = fake_for("EMAIL_ADDRESS", "alice@example.com")
    # Cut the fake roughly in half — the tail half should be held.
    half = len(fake) // 2
    flushed, held = scan_with_hold(f"prefix {fake[:half]}")
    # The held portion is exactly what was the tail of the input.
    assert held == fake[:half]
    assert "alice@example.com" not in flushed


def test_scan_with_hold_then_completion_unmasks():
    """Two-step: hold a partial fake, then feed the rest — the combined
    buffer must round-trip."""
    fake = fake_for("EMAIL_ADDRESS", "bob@example.com")
    half = len(fake) // 2
    flushed1, held = scan_with_hold(f"hi {fake[:half]}")
    flushed2, held2 = scan_with_hold(held + fake[half:] + " bye")
    assert "bob@example.com" in (flushed1 + flushed2)
    assert held2 == ""


def test_flush_hold_emits_verbatim_on_orphan_tail():
    """If the stream ends mid-fake-prefix, flush_hold returns the tail
    unchanged (no fake to substitute since it never finished arriving)."""
    fake = fake_for("EMAIL_ADDRESS", "carol@example.com")
    half = len(fake) // 2
    assert flush_hold(fake[:half]) == fake[:half]
