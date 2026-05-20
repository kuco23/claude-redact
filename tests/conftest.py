"""Shared fixtures.

The mask/reverse maps in `claude_proxy.masking` are module-level and
process-wide on purpose (see the module docstring). Tests must reset
them between cases so placeholder digests don't leak across tests.
"""
from __future__ import annotations

import pytest

from claude_proxy import masking


@pytest.fixture(autouse=True)
def _reset_mask_maps():
    masking._forward.clear()
    masking._reverse.clear()
    yield
    masking._forward.clear()
    masking._reverse.clear()
