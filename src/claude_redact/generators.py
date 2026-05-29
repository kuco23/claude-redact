"""Per-entity-type fake generators.

Each `gen_<entity>` returns a freshly-randomized value shaped like the original:
matching length where length is meaningful, matching prefix where the prefix
carries meaning (`sk-ant-`, `0x`, `bc1`, `+1`, …), and passing the same
validator the original passed (Luhn for credit cards, octet range for IPv4,
stdlib parse for IPv6).

The masking module is responsible for memoizing (same secret → same fake
within the process) and collision detection (a freshly minted fake that
collides with an existing reverse-map entry is regenerated). Generators
themselves are stateless.

For API keys the shape is selected by sniffing the original's prefix — a
`sk-ant-…` key gets a `sk-ant-…` fake, a `AIza…` Google key gets a Google
shape, and so on. Unknown shapes fall back to "preserve prefix up to the
first separator, randomize the rest at the same length".
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import random
import re
import string
import uuid

# When `CLAUDE_REDACT_SEED` is set, every fake is a deterministic function
# of (seed, entity_type, original_value): we HMAC-SHA256 those together,
# use the digest to seed a fresh `random.Random` for the call, and run the
# generator against that RNG. Same secret → same fake across processes,
# machines, and restarts — which is what lets a model keep referring to
# "the user's wallet" across sessions without confusion.
#
# When the seed is unset we fall back to an OS-seeded module-global RNG
# (per-process random, no persistence). Convenient for tests / demos.
#
# The seed becomes part of the security model: anyone who knows it can mount
# a known-plaintext attack — guess an original X, derive what fake X would
# produce, and compare against a fake they observed on the wire. Treat it
# like an API key (256-bit hex, never committed, never logged).
_SEED: bytes | None = None
_seed_env = os.environ.get("CLAUDE_REDACT_SEED")
if _seed_env:
    _SEED = _seed_env.encode()

# Module-global RNG used in the unkeyed fallback path. The keyed path swaps
# this out per call (safe because the masking pipeline is synchronous within
# a single request — no awaits between swap and restore).
_rng = random.Random()


# --- Character sets ------------------------------------------------------

_ALNUM_LOWER = string.ascii_lowercase + string.digits
_ALNUM = string.ascii_letters + string.digits
_HEX = string.hexdigits[:16]  # 0-9a-f
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # no 0, O, I, l
_BECH32 = "ac-hj-np-z02-9"  # not literal — see _BECH32_CHARS
_BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # the actual bech32 alphabet
_BASE64URL = string.ascii_letters + string.digits + "-_"
_BASE64 = string.ascii_letters + string.digits + "+/"


def _rand(alphabet: str, n: int) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


# --- Email ---------------------------------------------------------------

# Common-looking but obviously-fake TLDs we use when we can't preserve the original.
_TLD_BY_LEN: dict[int, list[str]] = {
    2: ["io", "co"],
    3: ["com", "net", "org", "dev"],
    4: ["info", "site", "test"],
    5: ["email"],
}


def gen_email(original: str) -> str:
    """Same local-part length, same TLD if recognized, random otherwise."""
    local, _, domain = original.partition("@")
    dparts = domain.split(".")
    tld = dparts[-1] if dparts else "com"
    dom_label_len = max(4, len(dparts[0]) if dparts else 6)
    new_local = _rand(string.ascii_lowercase, max(4, len(local)))
    new_dom = _rand(string.ascii_lowercase, dom_label_len)
    new_tld = tld if tld.isalpha() and 2 <= len(tld) <= 6 else "com"
    return f"{new_local}@{new_dom}.{new_tld}"


# --- SSN -----------------------------------------------------------------

def gen_ssn(original: str) -> str:
    """Random SSN that passes the area/group/serial constraints in detection.py."""
    # Area: 001-665 or 667-899 (skip 000, 666, 9XX).
    area = _rng.choice([n for n in range(1, 900) if n != 666])
    group = _rng.randint(1, 99)
    serial = _rng.randint(1, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"


# --- Credit card ---------------------------------------------------------

def gen_credit_card(original: str) -> str:
    """Luhn-valid card with the same digit count and separator pattern."""
    digits_only = [c for c in original if c.isdigit()]
    n = len(digits_only)
    if not 13 <= n <= 19:
        n = 16
    body = [_rng.randint(0, 9) for _ in range(n - 1)]
    body.append(_luhn_check_digit(body))
    new_digits = "".join(str(d) for d in body)
    # Re-insert the same separators where the original had them.
    out: list[str] = []
    j = 0
    for c in original:
        if c.isdigit():
            out.append(new_digits[j])
            j += 1
        else:
            out.append(c)
    # If the original had fewer non-digit chars than expected (or none), pad with new digits.
    while j < n:
        out.append(new_digits[j])
        j += 1
    return "".join(out)


def _luhn_check_digit(body: list[int]) -> int:
    """Pick the trailing digit that makes `body + [digit]` Luhn-valid."""
    s = 0
    for i, d in enumerate(reversed(body)):
        # body is everything except the check digit; positions shifted by 1
        # so the doubling alternates starting from the second-from-last digit.
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return (10 - s % 10) % 10


# --- IP addresses --------------------------------------------------------

def gen_ip(original: str) -> str:
    """IPv4 if it parses as one, IPv6 otherwise. Loopback / link-local /
    private blocks are not avoided — the goal is to look real, not be routable."""
    try:
        ipaddress.IPv4Address(original)
        return ".".join(str(_rng.randint(1, 254)) for _ in range(4))
    except (ValueError, ipaddress.AddressValueError):
        pass
    # IPv6 — generate 8 random hex groups, compress with stdlib for realism.
    addr = ipaddress.IPv6Address(_rng.getrandbits(128))
    return addr.compressed


# --- UUID ----------------------------------------------------------------

def gen_uuid(original: str) -> str:
    """Random UUID, same dashed 8-4-4-4-12 shape, same case as original.
    Original case is preserved because some downstream systems are case-sensitive
    about UUIDs (e.g. URL paths)."""
    new = str(uuid.uuid4())
    return new.upper() if any(c.isupper() for c in original) else new


# --- JWT -----------------------------------------------------------------

def gen_jwt(original: str) -> str:
    """Three base64url segments of the same lengths as the original.
    The header still starts with `eyJ` so the result re-matches the recognizer."""
    parts = original.split(".")
    if len(parts) != 3:
        return "eyJ" + _rand(_BASE64URL, 30) + "." + "eyJ" + _rand(_BASE64URL, 60) + "." + _rand(_BASE64URL, 43)
    h, p, s = parts
    new_h = "eyJ" + _rand(_BASE64URL, max(1, len(h) - 3))
    new_p = "eyJ" + _rand(_BASE64URL, max(1, len(p) - 3))
    new_s = _rand(_BASE64URL, max(1, len(s)))
    return f"{new_h}.{new_p}.{new_s}"


# --- PEM private key -----------------------------------------------------

_PEM_RE = re.compile(
    r"(-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----)([\s\S]+?)(-----END (?:[A-Z]+ )?PRIVATE KEY-----)"
)


def gen_pem_private_key(original: str) -> str:
    """Keep the BEGIN/END markers; replace the base64 body with random base64
    of approximately the same length, wrapped at 64 chars per line as PEM does."""
    m = _PEM_RE.search(original)
    if not m:
        return original  # shouldn't happen — caller already matched the pattern
    begin, body, end = m.group(1), m.group(2), m.group(3)
    body_chars = "".join(c for c in body if c in _BASE64 + "=")
    n = max(64, len(body_chars))
    new_body = _rand(_BASE64, n)
    wrapped = "\n".join(new_body[i : i + 64] for i in range(0, len(new_body), 64))
    return f"{begin}\n{wrapped}\n{end}"


# --- Hashes / hex / base64 -----------------------------------------------

def gen_hex(original: str) -> str:
    """Lowercase hex of the same length. Preserves a leading `0x` so
    digests emitted in EVM/wire form keep their prefix in the fake (and
    the fake re-matches the same recognizer on a second pass)."""
    if original[:2].lower() == "0x":
        return original[:2] + _rand(_HEX, len(original) - 2)
    return _rand(_HEX, len(original))


def gen_base64(original: str) -> str:
    """base64 (no padding distinction) of the same length."""
    return _rand(_BASE64, len(original))


# --- Crypto addresses ----------------------------------------------------

def gen_eth_address(original: str) -> str:
    """`0x` + 40 hex (lowercase). EIP-55 mixed-case checksum is not enforced —
    the recognizer accepts either case."""
    return "0x" + _rand(_HEX, 40)


def gen_eth_private_key(original: str) -> str:
    """`0x` + 64 hex (lowercase). Same shape as a raw secp256k1 private key
    or a 32-byte hash written in 0x form."""
    return "0x" + _rand(_HEX, 64)


def gen_btc_address(original: str) -> str:
    if original.startswith("bc1"):
        return "bc1" + _rand(_BECH32_CHARS, len(original) - 3)
    # Legacy P2PKH (1...) or P2SH (3...).
    return original[0] + _rand(_BASE58, len(original) - 1)


def gen_bch_address(original: str) -> str:
    # bitcoincash:q... or bitcoincash:p... — preserve the prefix + first body char.
    if ":" in original:
        prefix, body = original.split(":", 1)
        return f"{prefix}:{body[0]}{_rand(_BECH32_CHARS, len(body) - 1)}"
    return original


def gen_ltc_address(original: str) -> str:
    if original.startswith("ltc1"):
        return "ltc1" + _rand(_BECH32_CHARS, len(original) - 4)
    return original[0] + _rand(_BASE58, len(original) - 1)


def gen_doge_address(original: str) -> str:
    return "D" + _rand(_BASE58, len(original) - 1)


def gen_xrp_address(original: str) -> str:
    # Must contain at least one digit (the XRP detector enforces this).
    body = list(_rand(_BASE58, len(original) - 1))
    if not any(c.isdigit() for c in body):
        body[_rng.randint(0, len(body) - 1)] = _rng.choice("123456789")
    return "r" + "".join(body)


def gen_bip39_mnemonic(original: str) -> str:
    """Replace each word with a uniformly random BIP39 word. Same word count
    as the original, so a 12-word phrase masks to a 12-word phrase and the
    recognizer re-matches on a second pass. Both halves of the secret are
    replaced — the word order *is* the seed, so partial preservation would
    leak entropy."""
    from claude_redact.bip39_wordlist import BIP39_WORDLIST
    n = len(original.split())
    return " ".join(_rng.choice(BIP39_WORDLIST) for _ in range(n))


def gen_xrp_seed(original: str) -> str:
    """`s` (secp256k1) or `sEd` (Ed25519) + base58 of the same length, with
    at least one digit so the digit-required lookahead in the recognizer
    still matches on a second pass."""
    prefix = "sEd" if original.startswith("sEd") else "s"
    body_len = len(original) - len(prefix)
    body = list(_rand(_BASE58, body_len))
    if not any(c.isdigit() for c in body):
        body[_rng.randint(0, len(body) - 1)] = _rng.choice("123456789")
    return prefix + "".join(body)


def gen_trx_address(original: str) -> str:
    return "T" + _rand(_BASE58, len(original) - 1)


def gen_xmr_address(original: str) -> str:
    # First char is 4 or 8; second is 0-9 or A-B; rest is base58.
    return original[0] + _rng.choice("0123456789AB") + _rand(_BASE58, len(original) - 2)


def gen_ada_address(original: str) -> str:
    return "addr1" + _rand(_BECH32_CHARS, len(original) - 5)


# --- API keys ------------------------------------------------------------

# (regex on original, generator) — first match wins. The order matches
# the order of API_KEY patterns in detection.PATTERNS so the most-specific
# prefixes (sk-ant-, sk-proj-, gh*_, AKIA, AIza, …) are tried before the
# generic `sk-…` fallback.
_API_KEY_SHAPES: list[tuple[re.Pattern[str], "callable"]] = [
    (re.compile(r"^sk-ant-"),         lambda o: "sk-ant-" + _rand(_ALNUM + "_-", len(o) - 7)),
    (re.compile(r"^sk-proj-"),        lambda o: "sk-proj-" + _rand(_ALNUM + "_-", len(o) - 8)),
    (re.compile(r"^sk-"),             lambda o: "sk-" + _rand(_ALNUM, len(o) - 3)),
    (re.compile(r"^(sk|pk|rk)_(live|test)_"),
                                       lambda o: o[: o.index("_", o.index("_") + 1) + 1]
                                                + _rand(_ALNUM, len(o) - (o.index("_", o.index("_") + 1) + 1))),
    (re.compile(r"^gh[pousr]_"),      lambda o: o[:4] + _rand(_ALNUM, len(o) - 4)),
    (re.compile(r"^github_pat_"),     lambda o: "github_pat_" + _rand(_ALNUM + "_", len(o) - 11)),
    (re.compile(r"^gl[a-z]+-"),       lambda o: o[: o.index("-") + 1] + _rand(_ALNUM + "_-", len(o) - (o.index("-") + 1))),
    (re.compile(r"^(AKIA|ASIA)"),     lambda o: o[:4] + _rand(string.digits + string.ascii_uppercase, len(o) - 4)),
    (re.compile(r"^AIza"),            lambda o: "AIza" + _rand(_ALNUM + "_-", len(o) - 4)),
    (re.compile(r"^xox[baprs]-"),     lambda o: o[:5] + _rand(_ALNUM + "-", len(o) - 5)),
    # Telegram bot token: random digits (same count) + ":" + random URL-safe body.
    # Both halves are randomized — the bot ID is itself an identifier worth redacting.
    (re.compile(r"^\d{8,12}:"),       lambda o: _rand(string.digits, o.index(":"))
                                                 + ":" + _rand(_ALNUM + "_-", len(o) - o.index(":") - 1)),
    (re.compile(r"^AC[a-f0-9]{32}$"), lambda o: "AC" + _rand(_HEX, 32)),
    (re.compile(r"^SG\."),            lambda o: "SG." + _rand(_BASE64URL, 22) + "." + _rand(_BASE64URL, 43)),
    (re.compile(r"^key-[a-f0-9]"),    lambda o: "key-" + _rand(_HEX, len(o) - 4)),
    (re.compile(r"-us\d{1,2}$"),      lambda o: _rand(_HEX, 32) + o[o.index("-us"):]),
    (re.compile(r"^PMAK-"),           lambda o: "PMAK-" + _rand(_HEX, 24) + "-" + _rand(_HEX, 34)),
    (re.compile(r"^lin_(api|oauth)_"), lambda o: o[: o.index("_", 4) + 1] + _rand(_ALNUM, 40)),
    (re.compile(r"^ATATT"),           lambda o: "ATATT" + _rand(_ALNUM + "_-=", len(o) - 5)),
    (re.compile(r"^dp\.pt\."),        lambda o: "dp.pt." + _rand(_ALNUM, 43)),
    (re.compile(r"^dp\.st\."),        lambda o: "dp.st." + _rand(_ALNUM + "_-", max(8, len(o) - 56)) + "." + _rand(_ALNUM, 43)),
    (re.compile(r"^secret_"),         lambda o: "secret_" + _rand(_ALNUM, max(40, len(o) - 7))),
    (re.compile(r"^ntn_"),            lambda o: "ntn_" + _rand(_ALNUM, max(40, len(o) - 4))),
    (re.compile(r"^figd_"),           lambda o: "figd_" + _rand(_ALNUM + "_-", max(40, len(o) - 5))),
    (re.compile(r"^pypi-AgEIcHlwaS5vcmc"),
                                       lambda o: "pypi-AgEIcHlwaS5vcmc" + _rand(_BASE64URL, max(50, len(o) - 19))),
    (re.compile(r"^npm_"),            lambda o: "npm_" + _rand(_ALNUM, 36)),
    (re.compile(r"^rubygems_"),       lambda o: "rubygems_" + _rand(_HEX, 48)),
    (re.compile(r"^hf_"),             lambda o: "hf_" + _rand(_ALNUM, max(34, len(o) - 3))),
    (re.compile(r"^dop_v1_"),         lambda o: "dop_v1_" + _rand(_HEX, 64)),
    (re.compile(r"^doo_v1_"),         lambda o: "doo_v1_" + _rand(_HEX, 64)),
    (re.compile(r"^EAAA"),            lambda o: "EAAA" + _rand(_ALNUM + "_-", 60)),
    (re.compile(r"^sq0csp-"),         lambda o: "sq0csp-" + _rand(_ALNUM + "_-", 43)),
    (re.compile(r"^sntr(ys|yu)_"),    lambda o: o[: o.index("_") + 1] + _rand(_ALNUM + "_-", max(40, len(o) - 7))),
    (re.compile(r"^https://hooks\.slack\.com/services/"),
                                       lambda o: "https://hooks.slack.com/services/T"
                                                + _rand(string.ascii_uppercase + string.digits, 10)
                                                + "/B" + _rand(string.ascii_uppercase + string.digits, 10)
                                                + "/" + _rand(_ALNUM, 24)),
]


def gen_api_key(original: str) -> str:
    """Sniff the original's prefix, pick the matching sub-shape, generate."""
    for pat, fn in _API_KEY_SHAPES:
        if pat.match(original):
            try:
                return fn(original)
            except (ValueError, IndexError):
                continue
    # Fallback: preserve the prefix up to the first non-alnum sep, randomize rest.
    sep = next((i for i, c in enumerate(original) if c in "_-."), -1)
    if sep != -1 and sep < len(original) - 1:
        return original[: sep + 1] + _rand(_ALNUM, len(original) - sep - 1)
    return _rand(_ALNUM, len(original))


# --- Phone -------------------------------------------------------------

def gen_phone(original: str) -> str:
    """North American number in `+1NPANXXXXXX` form. `phonenumbers` parses
    this region-free. Original separators are not preserved — international
    formats vary too much to reconstruct, and the matcher tolerates none."""
    # NPA: 2-9 then two 0-9. NXX: 2-9 then two 0-9. Subscriber: 4 digits.
    npa = f"{_rng.randint(2, 9)}{_rng.randint(0, 9)}{_rng.randint(0, 9)}"
    nxx = f"{_rng.randint(2, 9)}{_rng.randint(0, 9)}{_rng.randint(0, 9)}"
    sub = f"{_rng.randint(0, 9999):04d}"
    return f"+1{npa}{nxx}{sub}"


# --- Dispatch -----------------------------------------------------------

_GENERATORS = {
    "EMAIL_ADDRESS": gen_email,
    "US_SSN": gen_ssn,
    "CREDIT_CARD": gen_credit_card,
    "IP_ADDRESS": gen_ip,
    "UUID": gen_uuid,
    "JWT": gen_jwt,
    "CRYPTO_PRIVATE_KEY": gen_pem_private_key,
    "HASH": gen_hex,
    "ETH_ADDRESS": gen_eth_address,
    "ETH_PRIVATE_KEY": gen_eth_private_key,
    "BTC_ADDRESS": gen_btc_address,
    "BCH_ADDRESS": gen_bch_address,
    "LTC_ADDRESS": gen_ltc_address,
    "DOGE_ADDRESS": gen_doge_address,
    "XRP_ADDRESS": gen_xrp_address,
    "XRP_SEED": gen_xrp_seed,
    "BIP39_MNEMONIC": gen_bip39_mnemonic,
    "TRX_ADDRESS": gen_trx_address,
    "XMR_ADDRESS": gen_xmr_address,
    "ADA_ADDRESS": gen_ada_address,
    "API_KEY": gen_api_key,
    "PHONE_NUMBER": gen_phone,
    "BASE64_SECRET": gen_base64,
    "HEX_SECRET": gen_hex,
}


def generate(entity_type: str, original: str) -> str:
    """Dispatch to the per-type generator. Unknown types fall back to
    same-length random alnum — safer than returning the original.

    In keyed mode (CLAUDE_REDACT_SEED set), the module-global `_rng` is
    swapped with one seeded from HMAC-SHA256(seed, entity_type \\x00 original)
    for the duration of the call, so the result is deterministic across
    processes. The swap is safe because the masking pipeline never `await`s
    between dispatch and return.
    """
    if _SEED is not None:
        msg = entity_type.encode() + b"\x00" + original.encode()
        digest = hmac.new(_SEED, msg, hashlib.sha256).digest()
        keyed = random.Random()
        keyed.seed(int.from_bytes(digest, "big"))
        global _rng
        saved, _rng = _rng, keyed
        try:
            return _dispatch(entity_type, original)
        finally:
            _rng = saved
    return _dispatch(entity_type, original)


def _dispatch(entity_type: str, original: str) -> str:
    fn = _GENERATORS.get(entity_type)
    return fn(original) if fn else _rand(_ALNUM, len(original))
