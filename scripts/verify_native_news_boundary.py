#!/usr/bin/env python3
"""Verify the native child append limit without hiding indexed orphan articles."""

import json
from pathlib import Path

from script_cli import run
from verify_native_news_boundary_checks import body, navigation, title, traversal
from verify_native_news_boundary_steps import verify
from verify_native_news_boundary_storage import storage

# The checks live in verify_native_news_boundary_checks (traversal, navigation,
# title and body), verify_native_news_boundary_storage (storage),
# verify_native_news_boundary_capture (the case captures) and
# verify_native_news_boundary_steps (verify and its phases). The names below stay
# importable from this module. test_native_news_boundary imports body, storage,
# traversal and verify.
__all__ = [
    "body",
    "main",
    "navigation",
    "show",
    "storage",
    "title",
    "traversal",
    "verify",
]


def show(directory: str) -> None:
    """Print the JSON summary of the native child append boundary corpus.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native child append boundary corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
