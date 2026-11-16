"""Describe the owned article-deletion trees and the specifications of their cases.

The planner in ``native_news_delete_cases`` re-exports these names, which the
preparation script, the verifier, the test and the executed run scripts import
through that module.
"""

import typing as typ

from native_folder_cases import path

ROOT = b"mothra-news24"
BASE = path((ROOT,))
NODES = [
    (1, b"L", 0),
    (2, b"A", 0),
    (3, b"R", 0),
    (4, b"B", 2),
    (5, b"C", 2),
    (6, b"F", 2),
    (7, b"D", 4),
    (8, b"E", 4),
]


def specs() -> list[dict[str, typ.Any]]:
    """Describe the owned categories: the parent cases, then the article cases.

    Returns
    -------
    list[dict[str, typing.Any]]
    """
    result: list[dict[str, typ.Any]] = []
    for label, value, recursive in [
        ("absent", None, False),
        ("empty", b"", False),
        ("one-zero", b"\0", False),
        ("two-zero", bytes(2), False),
        ("four-zero", bytes(4), False),
        ("one-one", b"\1", True),
        ("one-two", b"\2", True),
        ("one-ff", b"\xff", True),
        ("two-one", b"\0\1", True),
        ("two-high", b"\x80\0", True),
        ("four-high", b"\0\1\0\0", True),
        ("three-one", b"\0\0\1", False),
        ("five-one", b"\0\0\0\1\xff", True),
        ("five-zero", b"\0\0\0\0\xff", False),
    ]:
        result.append({
            "case": "parent-" + label,
            "article": 2,
            "value_hex": None if value is None else value.hex(),
            "mode": "recursive-parent" if recursive else "promote-parent",
            "role": "admin",
            "missing_category": False,
            "repeat": False,
        })
    for label, article, value, mode, role, missing, repeat in [
        ("leaf-zero", 7, b"\0", "leaf", "admin", False, False),
        ("leaf-one", 7, b"\1", "leaf", "admin", False, False),
        ("middle-zero", 4, b"\0", "promote-middle", "admin", False, False),
        ("middle-one", 4, b"\1", "recursive-middle", "admin", False, False),
        ("root-head", 1, b"\0", "head", "admin", False, False),
        ("root-tail", 3, b"\0", "tail", "admin", False, False),
        ("missing-id", 99, b"\1", "unchanged", "admin", False, False),
        ("denied", 2, b"\1", "unchanged", "low", False, False),
        ("missing-category", 2, b"\1", "unchanged", "admin", True, False),
        ("missing-id-field", None, b"\1", "unchanged", "admin", False, False),
        ("repeat-delete", 2, b"\0", "promote-parent", "admin", False, True),
    ]:
        result.append({
            "case": label,
            "article": article,
            "value_hex": value.hex(),
            "mode": mode,
            "role": role,
            "missing_category": missing,
            "repeat": repeat,
        })
    return result
