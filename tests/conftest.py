"""Shared fixtures.

The mask/reverse maps in `claude_redact.masking` are module-level and
process-wide on purpose (see the module docstring). Tests must reset
them between cases so minted fakes don't leak across tests.
"""
from __future__ import annotations

import pytest

from claude_redact import generators, masking


@pytest.fixture(autouse=True)
def _reset_mask_maps():
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    masking._max_fake_len = 0
    # Pin the seed so tests exercise the deterministic (keyed) path and
    # produce identical fakes on every run, regardless of the user's host
    # env. Also reset the unkeyed-fallback RNG state in case any individual
    # test temporarily clears `_SEED` to test the random path.
    generators._SEED = b"test-seed-fixed"
    generators._rng.seed(0)
    yield
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    masking._max_fake_len = 0
