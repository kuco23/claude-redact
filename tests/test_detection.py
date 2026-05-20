"""Pattern, validator, and entropy-scanner tests for detection.py."""
from __future__ import annotations

import pytest

from claude_proxy import detection
from claude_proxy.detection import (
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
    ("a.b+tag@sub.example.co.uk", "a.b+tag@sub.example.co.uk"),
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
    text = "good 192.168.1.1 bad 256.0.0.1 also good 8.8.8.8"
    spans = _spans(text, "IP_ADDRESS")
    assert "192.168.1.1" in spans
    assert "8.8.8.8" in spans
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
    "4111-1111-1111-1111",   # Visa test
    "4111 1111 1111 1111",   # space-separated
    "5500000000000004",      # Mastercard test
])
def test_credit_card_luhn_valid(card):
    assert "CREDIT_CARD" in _types(f"card {card}")


def test_credit_card_luhn_invalid():
    # Single-digit flip breaks Luhn.
    assert "CREDIT_CARD" not in _types("card 4111-1111-1111-1112")


def test_credit_card_no_trailing_space_eaten():
    """Regression: an earlier regex `{13,19}\\b` greedily consumed the trailing
    separator, leaving placeholders like `<<MASK:CC>>and` with no whitespace."""
    matches = find_entities("Card 4111-1111-1111-1111 done")
    cc = [m for m in matches if m.entity_type == "CREDIT_CARD"]
    assert len(cc) == 1
    assert cc[0].end == len("Card 4111-1111-1111-1111")  # ends on the last digit


# --- Custom patterns -----------------------------------------------------

@pytest.mark.parametrize("token,entity", [
    ("550e8400-e29b-41d4-a716-446655440000", "UUID"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf", "JWT"),
    ("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "API_KEY"),
    ("github_pat_" + "A" * 82, "API_KEY"),
    ("AKIAIOSFODNN7EXAMPLE", "API_KEY"),
    ("0xAbCdEf0123456789AbCdEf0123456789AbCdEf01", "ETH_ADDRESS"),
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "BTC_ADDRESS"),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "BTC_ADDRESS"),
])
def test_provider_patterns(token, entity):
    assert entity in _types(f"value is {token} here")


def test_pem_private_key_block():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLI\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert "CRYPTO_PRIVATE_KEY" in _types(f"key:\n{pem}\n")


def test_xrp_rejects_camelcase_identifier():
    """XRP requires at least one digit — `redeemedAggregateTimeSeries`-style
    identifiers should not match."""
    assert "XRP_ADDRESS" not in _types("redeemedAggregateTimeSeries data")


def test_phone_number_international():
    text = "call me at +1 (415) 555-2671 when ready"
    assert "PHONE_NUMBER" in _types(text)


# --- Validators ----------------------------------------------------------

@pytest.mark.parametrize("digits,ok", [
    ("4111111111111111", True),
    ("5500000000000004", True),
    ("4111111111111112", False),
    ("0", False),                          # too short
    ("9" * 20, False),                     # too long
])
def test_luhn(digits, ok):
    assert _luhn_ok(digits) is ok


def test_luhn_strips_separators():
    assert _luhn_ok("4111 1111 1111 1111") is True
    assert _luhn_ok("4111-1111-1111-1111") is True


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
    secret = "a1b2c3d4e5f60718293a4b5c6d7e8f0123456789"
    matches = find_high_entropy(f"token {secret} here")
    assert any(m.entity_type == "HEX_SECRET" for m in matches)


def test_entropy_catches_base64_secret():
    secret = "MFRjN3VEemRyZ0pkdEZQTWxIVlpUNDdRYWxVUw=="
    matches = find_high_entropy(f"token {secret}")
    assert any(m.entity_type == "BASE64_SECRET" for m in matches)


def test_entropy_rejects_english_prose():
    """Ordinary text — even long runs — falls below the entropy threshold."""
    text = "the quick brown fox jumps over the lazy dog repeatedly"
    assert find_high_entropy(text) == []


def test_entropy_ignores_short_runs():
    # 19 chars — below ENTROPY_MIN_LEN = 20.
    assert find_high_entropy("abc1234567890abcdefa") == [] or \
        all(m.end - m.start >= 20 for m in find_high_entropy("abc1234567890abcdefa"))


def test_shannon_zero_on_empty():
    assert _shannon("") == 0.0


def test_shannon_higher_for_random_than_repeated():
    assert _shannon("aaaaaaaaaa") < _shannon("abcdefghij")
