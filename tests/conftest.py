"""Shared fixtures.

The mask/reverse maps in `claude_redact.masking` are module-level and
process-wide on purpose (see the module docstring). Tests must reset
them between cases so minted fakes don't leak across tests.
"""
from __future__ import annotations

import random

import pytest

from claude_redact import masking


@pytest.fixture(autouse=True)
def _reset_mask_maps():
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    masking._max_fake_len = 0
    # Seed the RNG so generator outputs are deterministic across a test run —
    # makes failures bisectable and keeps `pytest -x` reproducible.
    random.seed(0)
    yield
    masking._forward.clear()
    masking._reverse.clear()
    masking._reverse_lower.clear()
    masking._max_fake_len = 0
