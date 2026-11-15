"""Fixtures shared by the pytest forms of the inherited script tests."""

import typing as typ

import pytest
from capture_support import Harness

if typ.TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    """Provide a fresh scratch directory and plan builder.

    Returns
    -------
    Harness
        One rooted at the test's temporary directory.
    """
    return Harness(tmp_path)
