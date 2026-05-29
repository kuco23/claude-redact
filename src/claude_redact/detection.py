"""Detection: regex + validator dispatch, plus a small entropy scanner.

Both scanners return a list of `Match` tuples (start, end, entity_type) in
character offsets within the input string. The masking module is responsible
for ordering, overlap resolution, and splicing — this module just answers
"what looks suspicious in this text?".

Regex patterns live in `PATTERNS` as (entity_type, regex, validator?) tuples.
The validator is an optional callable that receives the matched substring and
returns False to reject the match (e.g. Luhn check for credit cards, octet
range check for IPv4). Phone numbers use `phonenumbers.PhoneNumberMatcher`
directly because a single regex can't capture all valid international forms.

The entropy scanner catches opaque base64/hex tokens that have no recognizable
provider prefix. Tuned to reject typical English while admitting real-world
API keys and session tokens of 20+ chars.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Callable, NamedTuple

import phonenumbers


class Match(NamedTuple):
    start: int
    end: int
    entity_type: str


# --- Validators ----------------------------------------------------------

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _valid_ipv4(s: str) -> bool:
    return all(0 <= int(p) <= 255 for p in s.split("."))


def _valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def _valid_bip39_phrase(s: str) -> bool:
    """Every space-separated token must appear in the canonical BIP39 English
    wordlist. Without this gate the recognizer would match any 12 or 24
    consecutive short lowercase words — most English prose redacted away."""
    from claude_redact.bip39_wordlist import BIP39_WORDS
    return all(w in BIP39_WORDS for w in s.split())


# --- Patterns ------------------------------------------------------------

Validator = Callable[[str], bool]

# (entity_type, regex, optional validator). Order matters only for tie-breaks
# inside the same offset range; masking._dedupe_overlaps picks longest-wins.
PATTERNS: list[tuple[str, str, Validator | None]] = [
    # Built-in PII (replaces Presidio's default recognizers).
    ("EMAIL_ADDRESS",
     r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", None),
    # SSN: reject area codes 000, 666, 9XX; group 00; serial 0000.
    ("US_SSN",
     r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", None),
    # 13-19 digits with optional space/dash separators. The final digit has no
    # trailing separator so the match doesn't eat a following whitespace char.
    ("CREDIT_CARD",
     r"\b(?:\d[ \-]?){12,18}\d\b", _luhn_ok),
    ("IP_ADDRESS",
     r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _valid_ipv4),
    # IPv6: broad regex (any hex-and-colon run with ≥2 colons) gated by the
    # stdlib validator, which handles the full set of legal forms including
    # `::` shorthand. Lookarounds avoid latching onto adjacent word chars.
    ("IP_ADDRESS",
     r"(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}(?![:\w])",
     _valid_ipv6),

    # UUID / GUID (8-4-4-4-12), commonly used as API keys, tenant IDs, secrets.
    ("UUID",
     r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
     None),

    # JSON Web Token: three base64url segments joined by dots, header starts with eyJ.
    ("JWT",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     None),

    # PEM-encoded private keys: RSA, EC, DSA, PKCS#8, OpenSSH, encrypted variants.
    ("CRYPTO_PRIVATE_KEY",
     r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
     None),

    # Hex digests: MD5 / SHA1 / SHA256 / SHA512. Also catches raw 64-hex secp256k1 keys.
    ("HASH", r"\b[a-f0-9]{32}\b", None),
    ("HASH", r"\b[a-f0-9]{40}\b", None),
    ("HASH", r"\b[a-f0-9]{64}\b", None),
    ("HASH", r"\b[a-f0-9]{128}\b", None),
    # Same digests written in `0x` wire form. The `\b` in the bare-hex
    # variants can't anchor between `0x` and the hex body (both are word
    # chars), so a 0x-prefixed digest slips past — same root cause as the
    # ETH_PRIVATE_KEY gap. 0x + 40 is owned by ETH_ADDRESS and 0x + 64 by
    # ETH_PRIVATE_KEY; this entry covers the 32 (MD5) and 128 (SHA-512)
    # lengths plus any other 0x-prefixed digest the caller emits.
    ("HASH", r"\b0x[a-fA-F0-9]{32}\b", None),
    ("HASH", r"\b0x[a-fA-F0-9]{128}\b", None),

    # Ethereum (and EVM-compatible chains): 0x + 40 hex.
    ("ETH_ADDRESS", r"\b0x[a-fA-F0-9]{40}\b", None),

    # EVM (secp256k1) private key: 0x + 64 hex. Distinct entity from HASH
    # because the HASH regex anchors on `\b` and a `0x` prefix has no word
    # boundary between the `x` and the hex body — so a bare 64-hex digest
    # gets caught, but a 0x-prefixed key (the canonical wallet format) does
    # not. Also covers 32-byte transaction hashes / SHA-256 digests written
    # in 0x form.
    ("ETH_PRIVATE_KEY", r"\b0x[a-fA-F0-9]{64}\b", None),

    # Bitcoin: legacy P2PKH (1...) / P2SH (3...) and bech32 SegWit (bc1...).
    # Base58 alphabet excludes 0, O, I, l. Length 26-35 incl. prefix.
    ("BTC_ADDRESS", r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b", None),
    ("BTC_ADDRESS", r"\bbc1[ac-hj-np-z02-9]{39,59}\b", None),

    # Bitcoin Cash CashAddr.
    ("BCH_ADDRESS", r"\bbitcoincash:[qp][ac-hj-np-z02-9]{40,42}\b", None),

    # Litecoin: legacy (L.../M...) and bech32 (ltc1...).
    ("LTC_ADDRESS", r"\b[LM][1-9A-HJ-NP-Za-km-z]{26,33}\b", None),
    ("LTC_ADDRESS", r"\bltc1[ac-hj-np-z02-9]{39,59}\b", None),

    # Dogecoin: P2PKH starts with D, 34 chars total.
    ("DOGE_ADDRESS", r"\bD[1-9A-HJ-NP-Za-km-z]{33}\b", None),

    # Ripple (XRP): lowercase `r`, base58, 25-35 chars, must contain a digit
    # (real XRP addresses have a base58 checksum that virtually always
    # includes digits, while camelCase identifiers do not).
    ("XRP_ADDRESS",
     r"\b(?-i:r)(?=[1-9A-HJ-NP-Za-km-z]*[0-9])[1-9A-HJ-NP-Za-km-z]{24,34}\b",
     None),

    # XRP family seed (the canonical wallet secret): base58, 28-31 chars,
    # `s` prefix for secp256k1 or `sEd` for Ed25519. Same digit-required
    # lookahead as XRP_ADDRESS so plain `s…` identifiers (`submitRequest`,
    # etc.) don't get caught.
    ("XRP_SEED",
     r"\bs(?:Ed)?(?=[1-9A-HJ-NP-Za-km-z]*[0-9])[1-9A-HJ-NP-Za-km-z]{25,30}\b",
     None),

    # BIP39 mnemonic: 12 or 24 lowercase words from the canonical English
    # wordlist, separated by single spaces. Each word is 3-8 chars. The
    # validator is the gate — the regex alone would match any 12/24
    # consecutive short lowercase words.
    ("BIP39_MNEMONIC",
     r"\b(?:[a-z]{3,8} ){11}[a-z]{3,8}\b",
     _valid_bip39_phrase),
    ("BIP39_MNEMONIC",
     r"\b(?:[a-z]{3,8} ){23}[a-z]{3,8}\b",
     _valid_bip39_phrase),

    # Tron (TRX): starts with T, 34 chars total.
    ("TRX_ADDRESS", r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", None),

    # Monero (XMR): base58, 95 chars, starts with 4 (standard) or 8 (subaddress).
    ("XMR_ADDRESS", r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", None),

    # Cardano (ADA) Shelley-era bech32 addresses.
    ("ADA_ADDRESS", r"\baddr1[ac-hj-np-z02-9]{50,}\b", None),

    # Provider-prefixed API keys.
    ("API_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", None),           # Anthropic
    ("API_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", None),          # OpenAI project key
    ("API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b", None),                  # OpenAI generic
    ("API_KEY", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", None),  # Stripe
    ("API_KEY", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", None),            # GitHub classic
    ("API_KEY", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", None),          # GitHub fine-grained
    ("API_KEY",                                                      # GitLab (PAT, deploy,
     r"\bgl(?:pat|dt|rt|ptt|ft|agent|oas|cbt|soat|imt)-[A-Za-z0-9_\-]{20,}\b",
     None),                                                          # runner, trigger, etc.)
    ("API_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", None),            # AWS access key id
    ("API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b", None),               # Google API key
    ("API_KEY", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", None),        # Slack token
    # Telegram bot token: 8-12 digit bot ID, colon, 35-char URL-safe base64
    # auth token. The colon would otherwise split it into two runs that
    # neither the API_KEY recognizers nor the entropy scanner catch.
    ("API_KEY", r"\b\d{8,12}:[A-Za-z0-9_\-]{35}\b", None),           # Telegram bot

    # Patterns adapted from gitleaks (github.com/gitleaks/gitleaks) — covering
    # the SaaS providers most likely to show up in dev traffic.
    ("API_KEY", r"\bAC[a-f0-9]{32}\b", None),                                              # Twilio Account SID
    ("API_KEY", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", None),                  # SendGrid
    ("API_KEY", r"\bkey-[a-f0-9]{32}\b", None),                                            # Mailgun private API key
    ("API_KEY", r"\b[a-f0-9]{32}-us\d{1,2}\b", None),                                      # Mailchimp API key
    ("API_KEY", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", None),                              # Postman API key
    ("API_KEY", r"\blin_(?:api|oauth)_[A-Za-z0-9]{40}\b", None),                           # Linear API / OAuth
    ("API_KEY", r"\bATATT[A-Za-z0-9_\-=]{52,}\b", None),                                   # Atlassian Cloud API token
    ("API_KEY", r"\bdp\.pt\.[A-Za-z0-9]{43}\b", None),                                     # Doppler personal token
    ("API_KEY", r"\bdp\.st\.[A-Za-z0-9_\-]+\.[A-Za-z0-9]{43}\b", None),                    # Doppler service token
    ("API_KEY", r"\b(?:secret_[A-Za-z0-9]{40,}|ntn_[A-Za-z0-9]{40,})\b", None),            # Notion integration token
    ("API_KEY", r"\bfigd_[A-Za-z0-9_\-]{40,}\b", None),                                    # Figma personal access token
    ("API_KEY", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", None),                     # PyPI upload token
    ("API_KEY", r"\bnpm_[A-Za-z0-9]{36}\b", None),                                         # npm publish token
    ("API_KEY", r"\brubygems_[a-f0-9]{48}\b", None),                                       # RubyGems API key
    ("API_KEY", r"\bhf_[A-Za-z0-9]{34,}\b", None),                                         # Hugging Face token
    ("API_KEY", r"\bdop_v1_[a-f0-9]{64}\b", None),                                         # DigitalOcean personal access
    ("API_KEY", r"\bdoo_v1_[a-f0-9]{64}\b", None),                                         # DigitalOcean OAuth
    ("API_KEY", r"\bEAAA[A-Za-z0-9_\-]{60}\b", None),                                      # Square access token
    ("API_KEY", r"\bsq0csp-[A-Za-z0-9_\-]{43}\b", None),                                   # Square OAuth secret
    ("API_KEY", r"\bsntr(?:ys|yu)_[A-Za-z0-9_\-]{40,}\b", None),                           # Sentry user/service token

    # Slack incoming-webhook URL — the path tokens are the credential.
    ("API_KEY",
     r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b",
     None),
]

_COMPILED: list[tuple[str, re.Pattern[str], Validator | None]] = [
    (et, re.compile(rx), val) for et, rx, val in PATTERNS
]


def find_entities(text: str) -> list[Match]:
    """Run all regex recognizers plus the phonenumbers scanner."""
    out: list[Match] = []
    for entity_type, rx, validator in _COMPILED:
        for m in rx.finditer(text):
            if validator and not validator(m.group(0)):
                continue
            out.append(Match(m.start(), m.end(), entity_type))
    # Region-agnostic phone scan. PhoneNumberMatcher handles international
    # forms and embedded contexts a single regex can't express cleanly.
    for pm in phonenumbers.PhoneNumberMatcher(text, None):
        out.append(Match(pm.start, pm.end, "PHONE_NUMBER"))
    return out


# --- Entropy scanner -----------------------------------------------------

# Shortest candidate run we consider. Below 20 chars, hex/base64-shaped
# words are dominated by ordinary text and identifiers; above this, the
# entropy threshold cleanly separates random tokens from English.
ENTROPY_MIN_LEN = 20

# Shannon entropy (bits per char) above which a run is considered secret-like.
# Base64 alphabet is 64 chars (max ~6.0), hex is 16 (max ~4.0), so the
# thresholds differ. Tuned to reject typical English while admitting
# real-world API keys / session tokens of 20+ chars.
BASE64_ENTROPY_LIMIT = 4.5
HEX_ENTROPY_LIMIT = 3.0

_BASE64_RE = re.compile(rf"[A-Za-z0-9+/_\-]{{{ENTROPY_MIN_LEN},}}={{0,2}}")
_HEX_RE = re.compile(rf"\b[a-fA-F0-9]{{{ENTROPY_MIN_LEN},}}\b")


def find_high_entropy(text: str) -> list[Match]:
    """Find base64/hex-shaped runs whose Shannon entropy exceeds the
    configured limit. Catches opaque tokens that have no known provider
    prefix and would otherwise slip past the regex recognizers."""
    matches: list[Match] = []
    for m in _BASE64_RE.finditer(text):
        if _shannon(m.group(0)) > BASE64_ENTROPY_LIMIT:
            matches.append(Match(m.start(), m.end(), "BASE64_SECRET"))
    for m in _HEX_RE.finditer(text):
        if _shannon(m.group(0)) > HEX_ENTROPY_LIMIT:
            matches.append(Match(m.start(), m.end(), "HEX_SECRET"))
    return matches


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())
