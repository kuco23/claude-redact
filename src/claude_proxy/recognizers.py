"""Custom Presidio PatternRecognizers.

`CUSTOM_PATTERNS` is the canonical (entity, regex, score) data; `register()`
folds entries that share an entity type into one `PatternRecognizer` with
multiple `Pattern`s. Score breaks ties when ranges overlap — more specific
patterns get higher scores so they win over generic ones.
"""
from __future__ import annotations

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

# Entity types we ask Presidio to surface. Built-in PII types live in the
# analyzer's default registry; the rest are added by `register()`. The
# *_SECRET types are emitted by detect-secrets (see `detection.py`) and
# listed here so callers have one canonical taxonomy.
ENTITY_TYPES = [
    # Built-in PII
    "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "IP_ADDRESS",
    # Custom regex recognizers (below)
    "UUID", "JWT", "API_KEY", "CRYPTO_PRIVATE_KEY", "HASH",
    "ETH_ADDRESS", "BTC_ADDRESS", "LTC_ADDRESS", "DOGE_ADDRESS",
    "XRP_ADDRESS", "TRX_ADDRESS", "XMR_ADDRESS", "ADA_ADDRESS", "BCH_ADDRESS",
    # Emitted by the entropy scanner in detection.py
    "BASE64_SECRET", "HEX_SECRET",
]

CUSTOM_PATTERNS: list[tuple[str, str, float]] = [
    # UUID / GUID (8-4-4-4-12), commonly used as API keys, tenant IDs, secrets.
    ("UUID",
     r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
     0.85),

    # JSON Web Token: three base64url segments joined by dots, header starts with eyJ.
    ("JWT",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     0.95),

    # PEM-encoded private keys: RSA, EC, DSA, PKCS#8, OpenSSH, encrypted variants.
    ("CRYPTO_PRIVATE_KEY",
     r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
     0.99),

    # Hex digests: MD5 / SHA1 / SHA256 / SHA512. Also catches raw 64-hex secp256k1 keys.
    ("HASH", r"\b[a-f0-9]{32}\b", 0.4),
    ("HASH", r"\b[a-f0-9]{40}\b", 0.5),
    ("HASH", r"\b[a-f0-9]{64}\b", 0.5),
    ("HASH", r"\b[a-f0-9]{128}\b", 0.6),

    # Ethereum (and EVM-compatible chains): 0x + 40 hex.
    ("ETH_ADDRESS", r"\b0x[a-fA-F0-9]{40}\b", 0.85),

    # Bitcoin: legacy P2PKH (1...) / P2SH (3...) and bech32 SegWit (bc1...).
    # Base58 alphabet excludes 0, O, I, l. Length 26-35 incl. prefix.
    ("BTC_ADDRESS", r"\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b", 0.75),
    ("BTC_ADDRESS", r"\bbc1[ac-hj-np-z02-9]{39,59}\b", 0.95),

    # Bitcoin Cash CashAddr (`bitcoincash:q...`/`...p...`).
    ("BCH_ADDRESS", r"\bbitcoincash:[qp][ac-hj-np-z02-9]{40,42}\b", 0.95),

    # Litecoin: legacy (L.../M...) and bech32 (ltc1...).
    ("LTC_ADDRESS", r"\b[LM][1-9A-HJ-NP-Za-km-z]{26,33}\b", 0.75),
    ("LTC_ADDRESS", r"\bltc1[ac-hj-np-z02-9]{39,59}\b", 0.95),

    # Dogecoin: P2PKH starts with D, 34 chars total.
    ("DOGE_ADDRESS", r"\bD[1-9A-HJ-NP-Za-km-z]{33}\b", 0.75),

    # Ripple (XRP): starts with r, base58, 25-35 chars.
    ("XRP_ADDRESS", r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", 0.65),

    # Tron (TRX): starts with T, 34 chars total.
    ("TRX_ADDRESS", r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", 0.75),

    # Monero (XMR): base58, 95 chars, starts with 4 (standard) or 8 (subaddress).
    ("XMR_ADDRESS", r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", 0.95),

    # Cardano (ADA) Shelley-era bech32 addresses.
    ("ADA_ADDRESS", r"\baddr1[ac-hj-np-z02-9]{50,}\b", 0.95),

    # Provider-prefixed API keys.
    ("API_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", 0.99),           # Anthropic
    ("API_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b", 0.95),          # OpenAI project key
    ("API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b", 0.80),                  # OpenAI generic
    ("API_KEY", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", 0.95),  # Stripe
    ("API_KEY", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", 0.95),            # GitHub classic
    ("API_KEY", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", 0.99),          # GitHub fine-grained
    ("API_KEY",                                                      # GitLab (PAT, deploy,
     r"\bgl(?:pat|dt|rt|ptt|ft|agent|oas|cbt|soat|imt)-[A-Za-z0-9_\-]{20,}\b",
     0.97),                                                          # runner, trigger, etc.)
    ("API_KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0.95),            # AWS access key id
    ("API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.95),               # Google API key
    ("API_KEY", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", 0.90),        # Slack
]


def register(engine: AnalyzerEngine) -> None:
    """Add a `PatternRecognizer` per distinct entity type to `engine`."""
    by_entity: dict[str, list[Pattern]] = {}
    for entity, regex, score in CUSTOM_PATTERNS:
        lst = by_entity.setdefault(entity, [])
        lst.append(Pattern(name=f"{entity}_{len(lst)}", regex=regex, score=score))
    for entity, patterns in by_entity.items():
        engine.registry.add_recognizer(
            PatternRecognizer(supported_entity=entity, patterns=patterns)
        )
