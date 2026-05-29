"""Pattern, validator, and entropy-scanner tests for detection.py."""
from __future__ import annotations

import pytest

from claude_redact.detection import (
    _luhn_ok,
    _shannon,
    _valid_ipv4,
    find_entities,
    find_high_entropy,
)


def _types(text: str) -> set[str]:
    return {m.entity_type for m in find_entities(text)}


def _spans(text: str, entity: str) -> list[str]:
    return [text[m.start : m.end] for m in find_entities(text) if m.entity_type == entity]


# --- Built-in PII --------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("contact alice@example.com today", "alice@example.com"),
    ("bob.smith@sub.example.co.uk", "bob.smith@sub.example.co.uk"),
])
def test_email_match(text, expected):
    assert _spans(text, "EMAIL_ADDRESS") == [expected]


@pytest.mark.parametrize("text", [
    "not.an.email",
    "@example.com",
    "missing@tld",
])
def test_email_no_match(text):
    assert "EMAIL_ADDRESS" not in _types(text)


def test_ipv4_valid_and_invalid():
    text = "good 192.168.1.1 bad 256.0.0.1 also good 10.20.30.40"
    spans = _spans(text, "IP_ADDRESS")
    assert "192.168.1.1" in spans
    assert "10.20.30.40" in spans
    assert "256.0.0.1" not in spans


def test_ipv6_basic():
    text = "addr 2001:db8::1 here"
    assert "IP_ADDRESS" in _types(text)


@pytest.mark.parametrize("ssn,should_match", [
    ("123-45-6789", True),
    ("000-12-3456", False),   # area 000 reserved
    ("666-12-3456", False),   # area 666 reserved
    ("900-12-3456", False),   # 9XX reserved
    ("123-00-6789", False),   # group 00 reserved
    ("123-45-0000", False),   # serial 0000 reserved
])
def test_ssn_validation(ssn, should_match):
    assert ("US_SSN" in _types(f"SSN {ssn} here")) is should_match


@pytest.mark.parametrize("card", [
    "4242424242424242",       # Visa test
    "4242 4242 4242 4242",    # space-separated
    "5555555555554444",       # Mastercard test
])
def test_credit_card_luhn_valid(card):
    assert "CREDIT_CARD" in _types(f"card {card}")


def test_credit_card_luhn_invalid():
    # Single-digit flip breaks Luhn.
    assert "CREDIT_CARD" not in _types("card 4111-1111-1111-1112")


def test_credit_card_no_trailing_space_eaten():
    """Regression: an earlier regex `{13,19}\\b` greedily consumed the trailing
    separator, leaving placeholders like `<<MASK:CC>>and` with no whitespace."""
    matches = find_entities("Card 4242424242424242 done")
    cc = [m for m in matches if m.entity_type == "CREDIT_CARD"]
    assert len(cc) == 1
    assert cc[0].end == len("Card 4242424242424242")  # ends on the last digit


# --- Custom patterns -----------------------------------------------------

@pytest.mark.parametrize("token,entity", [
    ("550e8400-e29b-41d4-a716-446655440000", "UUID"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT"),
    ("sk-ant-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "API_KEY"),
    ("github_pat_" + "A" * 82, "API_KEY"),
    ("AKIAIOSFODNN7EXAMPLE", "API_KEY"),
    ("0xAbCdEf1234567890abcdef1234567890ABCDEF12", "ETH_ADDRESS"),
    ("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ETH_PRIVATE_KEY"),
    # 0x-prefixed digests at the other HASH lengths (32 = MD5, 128 = SHA-512).
    # The 0x + 40 case is owned by ETH_ADDRESS; 0x + 64 by ETH_PRIVATE_KEY.
    ("0x9e107d9d372bb6826bd81d3542a419d6", "HASH"),
    ("0x" + "abcdef0123456789" * 8, "HASH"),
    # Telegram bot token: 8-12 digits, colon, 35-char URL-safe base64 body.
    ("1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "API_KEY"),
    # XRP family seed: secp256k1 (`s` + base58) and Ed25519 (`sEd` + base58).
    # Length varies slightly (28-31) depending on the encoded leading bytes.
    ("snoPBrXtMeMyMHUVTgbuqAfg1SUTb", "XRP_SEED"),
    ("sEdTESTaabbccddeeffgghhiijjkkmm1", "XRP_SEED"),
    # BIP39 12-word mnemonic — every word must be in the canonical English list.
    # (`legal winner thank …` is a published BIP39 test vector.)
    ("legal winner thank year wave sausage worth useful legal winner thank yellow", "BIP39_MNEMONIC"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "BTC_ADDRESS"),
    ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "BTC_ADDRESS"),
])
def test_provider_patterns(token, entity):
    assert entity in _types(f"value is {token} here")


def test_pem_private_key_block():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n"
        "MNOPQRSTUVWXYZ0987654321\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert "CRYPTO_PRIVATE_KEY" in _types(f"key:\n{pem}\n")


def test_bip39_rejects_non_dictionary_words():
    """A 12-word phrase whose words aren't in the BIP39 list must not match.
    Otherwise any 12-short-word run of prose gets redacted."""
    not_bip39 = "hello world this sentence has twelve regular english words right now okay"
    assert "BIP39_MNEMONIC" not in _types(not_bip39)


def test_bip39_accepts_24_word_phrase():
    """24-word mnemonics are also valid — same validator, just longer."""
    twenty_four = (
        "abandon ability able about above absent absorb abstract absurd abuse "
        "access accident account accuse achieve acid acoustic acquire across act "
        "action actor actress actual"
    )
    assert "BIP39_MNEMONIC" in _types(twenty_four)


def test_xrp_seed_rejects_plain_word_starting_with_s():
    """An ordinary 28-30 char identifier starting with `s` (no digits) must
    not match — the digit-required lookahead is what distinguishes a real
    base58-encoded family seed from camelCase identifiers."""
    assert "XRP_SEED" not in _types("submitTransactionWithRetryHelper data")


def test_xrp_rejects_camelcase_identifier():
    """XRP requires at least one digit — `redeemedAggregateTimeSeries`-style
    identifiers should not match."""
    assert "XRP_ADDRESS" not in _types("redeemedAggregateTimeSeries data")


def test_phone_number_international():
    text = "call me at +14155552671 when ready"
    assert "PHONE_NUMBER" in _types(text)


# --- Validators ----------------------------------------------------------

@pytest.mark.parametrize("digits,ok", [
    ("4242424242424242", True),
    ("5555555555554444", True),
    ("4111111111111112", False),
    ("0", False),                          # too short
    ("9" * 20, False),                     # too long
])
def test_luhn(digits, ok):
    assert _luhn_ok(digits) is ok


def test_luhn_strips_separators():
    assert _luhn_ok("4242 4242 4242 4242") is True
    assert _luhn_ok("4242-4242-4242-4242") is True


@pytest.mark.parametrize("ip,ok", [
    ("0.0.0.0", True),
    ("255.255.255.255", True),
    ("192.168.1.1", True),
    ("256.0.0.1", False),
    ("999.0.0.1", False),
])
def test_valid_ipv4(ip, ok):
    assert _valid_ipv4(ip) is ok


# --- Entropy scanner -----------------------------------------------------

def test_entropy_catches_hex_secret():
    # 40-char hex with broad alphabet distribution.
    secret = "a1b2c3d4e5f6789012345abcdef9876543210fedc"
    matches = find_high_entropy(f"token {secret} here")
    assert any(m.entity_type == "HEX_SECRET" for m in matches)


def test_entropy_catches_base64_secret():
    secret = "aB3kLmN9pQrStUvWxYz0123456789AbCdEfGhIjKlMnOp"
    matches = find_high_entropy(f"token {secret}")
    assert any(m.entity_type == "BASE64_SECRET" for m in matches)


def test_entropy_catches_url_safe_base64_with_dash_or_underscore():
    """URL-safe base64 swaps `+/` for `-_`. Real tokens (JWT segments,
    Telegram bot bodies, many provider keys) use this variant — the
    standard-alphabet entropy regex used to miss them entirely because
    the first `-` or `_` would terminate the candidate run."""
    # Synthetic alphabet-spanning value: every char unique, contains `-` and
    # `_` (the URL-safe-specific chars), entropy well above the 4.5 bits/char
    # threshold. Obviously not anyone's real token.
    secret = "Abcdefghijklmnopqrstuvwxyz0123456789_-XYZ"
    matches = find_high_entropy(f"token {secret}")
    assert any(m.entity_type == "BASE64_SECRET" for m in matches), (
        f"URL-safe token {secret!r} not caught by entropy pass"
    )


def test_entropy_rejects_english_prose():
    """Ordinary text — even long runs — falls below the entropy threshold."""
    text = "the quick brown fox jumps over the lazy dog repeatedly"
    assert find_high_entropy(text) == []


def test_entropy_ignores_short_runs():
    # 19 chars — below ENTROPY_MIN_LEN = 20.
    short = "a1b2c3d4e5f67890123"  # 19 chars
    matches = find_high_entropy(f"token {short} here")
    assert all(m.end - m.start >= 20 for m in matches)


def test_shannon_zero_on_empty():
    assert _shannon("") == 0.0


def test_shannon_higher_for_random_than_repeated():
    assert _shannon("aaaaaaaaaa") < _shannon("abcdefghij")
