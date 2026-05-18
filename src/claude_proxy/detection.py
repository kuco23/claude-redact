"""Detection: Presidio analyzer + a small custom entropy scanner.

Both scanners return a list of `Match` tuples (start, end, entity_type)
in character offsets within the input string. The masking module is
responsible for ordering, overlap resolution, and splicing — this module
just answers "what looks suspicious in this text?".

The entropy scanner replaces detect-secrets, whose high-entropy plugins
were designed for quoted string literals in source code and either miss
unquoted prose tokens entirely or, via the no-quote fallback, disable
the entropy threshold and flood on plain English.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple

from presidio_analyzer import AnalyzerEngine

from claude_proxy import recognizers


class Match(NamedTuple):
    start: int
    end: int
    entity_type: str


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

_BASE64_RE = re.compile(rf"[A-Za-z0-9+/]{{{ENTROPY_MIN_LEN},}}={{0,2}}")
_HEX_RE = re.compile(rf"\b[a-fA-F0-9]{{{ENTROPY_MIN_LEN},}}\b")


analyzer = AnalyzerEngine()
recognizers.register(analyzer)


def find_entities(text: str) -> list[Match]:
    """Run Presidio's analyzer (built-in + custom recognizers)."""
    results = analyzer.analyze(
        text=text, entities=recognizers.ENTITY_TYPES, language="en"
    )
    return [Match(r.start, r.end, r.entity_type) for r in results]


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
