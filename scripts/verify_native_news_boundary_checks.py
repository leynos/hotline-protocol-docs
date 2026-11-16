"""Check the sibling traversal and the direct bodies of the boundary articles."""

from native_news_decode import articles
from verify_native_core import require
from verify_native_news_boundary_data import (
    BODY_FIELD,
    BYPASSED_ID,
    DATE_FIELD,
    FIRST_CHILD_ID,
    FLAVOUR_FIELD,
    NAVIGATION_FIELDS,
    PARENT_ID,
    POSTER_FIELD,
    PRE_BYPASS_ID,
    REACHABLE_CHILD_COUNT,
    REPLACEMENT_ID,
    TITLE_FIELD,
)
from verify_native_shx import fields


def title(identifier: int) -> bytes:
    """Return the title that the article ``identifier`` was posted with.

    Parameters
    ----------
    identifier : int
        The article identifier; the parent is ``PARENT_ID``.

    Returns
    -------
    bytes
        ``b"parent"`` for the parent, otherwise ``child-`` and the child number.
    """
    if identifier == PARENT_ID:
        return b"parent"
    return f"child-{identifier - 1:03}".encode()


def traversal(value: bytes, children: int, dates: dict[int, bytes]) -> None:
    """Check the sibling list in ``value`` and the metadata of every article in it.

    Parameters
    ----------
    value : bytes
        The reply that carries the sibling list.
    children : int
        The number of children that the list was expected to reach.
    dates : dict[int, bytes]
        The date that each article was first seen with; it is updated in place.
    """
    expected = list(range(1, children + 2))
    if children == REACHABLE_CHILD_COUNT:
        expected.remove(BYPASSED_ID)
    rows = articles(value)
    require([r["id"] for r in rows] == expected, "Sibling boundary traversal differs")
    for row in rows:
        identifier = row["id"]
        name = title(identifier)
        require(
            row["title"] == name
            and row["poster"] == b"framing-fixture"
            and row["parent"] == (0 if identifier == PARENT_ID else 1)
            and row["flags"] == 0
            and row["flavours"] == [(b"text/plain", 5 + len(name))],
            "Boundary article metadata differs",
        )
        require(
            row["date"][:4] == b"\x07p\0\0" and row["date"][4:] != bytes(4),
            "Boundary date representation differs",
        )
        if identifier in dates:
            require(
                row["date"] == dates[identifier],
                "Boundary append changed existing date",
            )
        dates[identifier] = row["date"]


def navigation(identifier: int) -> tuple[int, int, int, int]:
    """Return the expected links of the article ``identifier``.

    Parameters
    ----------
    identifier : int
        The article identifier.

    Returns
    -------
    tuple[int, int, int, int]
        The four links that the corpus expects, in the order of
        ``NAVIGATION_FIELDS``.
    """
    if identifier == PARENT_ID:
        return 0, 0, 0, 2
    previous = (
        0
        if identifier == FIRST_CHILD_ID
        else PRE_BYPASS_ID
        if identifier == REPLACEMENT_ID
        else identifier - 1
    )
    following = (
        REPLACEMENT_ID
        if identifier == PRE_BYPASS_ID
        else 0
        if identifier in {BYPASSED_ID, REPLACEMENT_ID}
        else identifier + 1
    )
    return previous, following, 1, 0


def body(frame: dict, identifier: int, dates: dict[int, bytes]) -> None:
    """Check the direct body reply of the article ``identifier``.

    Parameters
    ----------
    frame : dict
        The reply that carries the article fields.
    identifier : int
        The article identifier.
    dates : dict[int, bytes]
        The date that each article was first seen with.
    """
    expected = {
        TITLE_FIELD: title(identifier),
        POSTER_FIELD: b"framing-fixture",
        FLAVOUR_FIELD: b"text/plain",
        BODY_FIELD: b"body-" + title(identifier),
        DATE_FIELD: dates[identifier],
        **{
            k: v.to_bytes(2, "big")
            for k, v in zip(NAVIGATION_FIELDS, navigation(identifier), strict=True)
        },
    }
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Boundary direct body/navigation differs",
    )
