"""Detection: Presidio analyzer + detect-secrets entropy scanners.

Both scanners return a list of `Match` tuples (start, end, entity_type)
in character offsets within the input string. The masking module is
responsible for ordering, overlap resolution, and splicing — this module
just answers "what looks suspicious in this text?".
"""
from __future__ import annotations

from typing import NamedTuple

from detect_secrets.settings import get_plugins, transient_settings
from presidio_analyzer import AnalyzerEngine

from claude_proxy import recognizers


class Match(NamedTuple):
    start: int
    end: int
    entity_type: str


# Entropy-only detect-secrets plugins. Provider-specific patterns are
# already covered by `recognizers.CUSTOM_PATTERNS`; the entropy detectors
# fill the gap for opaque tokens with no known prefix.
#
# Known limitation: detect-secrets' high-entropy plugins were designed for
# scanning source code, where secrets appear inside quoted string literals.
# Their default `analyze_line` only matches quoted runs; the `scan_line`
# fallback that matches unquoted runs disables the entropy threshold and
# floods on plain prose. So in practice these catch `password = "<hex>"`
# but not unquoted opaque tokens in chat-style text. See `find_high_entropy`.
DS_PLUGINS = [
    {"name": "Base64HighEntropyString", "limit": 4.5},
    {"name": "HexHighEntropyString", "limit": 3.0},
]


analyzer = AnalyzerEngine()
recognizers.register(analyzer)


def find_entities(text: str) -> list[Match]:
    """Run Presidio's analyzer (built-in + custom recognizers)."""
    results = analyzer.analyze(
        text=text, entities=recognizers.ENTITY_TYPES, language="en"
    )
    return [Match(r.start, r.end, r.entity_type) for r in results]


def find_high_entropy(text: str) -> list[Match]:
    """Run detect-secrets entropy detectors and reproject hits to char offsets.

    Calls each plugin's `analyze_line` directly rather than going through
    `detect_secrets.core.scan.scan_line`, because the latter passes
    `enable_eager_search=True`, which bypasses the entropy-threshold filter
    on no-quote fallback paths and produces a flood of false positives on
    plain English.
    """
    matches: list[Match] = []
    offset = 0
    with transient_settings({"plugins_used": DS_PLUGINS}):
        plugins = list(get_plugins())
        for line in text.splitlines(keepends=True):
            for plugin in plugins:
                for secret in plugin.analyze_line(
                    filename="adhoc", line=line, line_number=0
                ):
                    value = getattr(secret, "secret_value", None)
                    if not value:
                        continue
                    idx = line.find(value)
                    if idx == -1:
                        continue
                    start = offset + idx
                    matches.append(
                        Match(start, start + len(value), _entropy_entity_type(secret.type))
                    )
            offset += len(line)
    return matches


def _entropy_entity_type(detect_secrets_type: str) -> str:
    if "Base64" in detect_secrets_type:
        return "BASE64_SECRET"
    if "Hex" in detect_secrets_type:
        return "HEX_SECRET"
    return "HIGH_ENTROPY_SECRET"
