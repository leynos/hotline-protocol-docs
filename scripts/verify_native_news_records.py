"""Check the article and category records decoded from the news list replies."""

from native_news_decode import articles, categories
from verify_native_core import require
from verify_native_news_data import (
    CATEGORY_KIND,
    FOLDER_KIND,
    LEGACY_CATEGORY_FIELD,
    LEGACY_CATEGORY_KIND,
    LEGACY_FOLDER_KIND,
    MODERN_CATEGORY_FIELD,
    MODERN_VERSION,
    RECORDS,
)


def article_records(value: bytes, order: list[int]) -> list[dict]:
    """Decode an article list and check each record against the fixture.

    Returns
    -------
    list[dict]
        The decoded article rows, in traversal order.
    """
    rows = articles(value)
    require(
        [r["id"] for r in rows] == order, "Article traversal order/public IDs differ"
    )
    for row in rows:
        title, parent, flags, body = RECORDS[row["id"]]
        require(
            row["title"] == title
            and row["poster"] == b"framing-fixture"
            and row["parent"] == parent
            and row["flags"] == flags,
            "Article title/poster/parent/flags differ",
        )
        require(
            row["flavours"] == ([] if body is None else [(b"text/plain", len(body))]),
            "Article flavour cardinality/name/size differs",
        )
        require(
            row["date"][:4] == b"\x07p\0\0" and row["date"][4:] != bytes(4),
            "Article native date representation differs",
        )
    return rows


def category_view(
    frame: dict, version: int, expected: list[tuple[bytes, bool, int]]
) -> list[dict]:
    """Decode a category list and check each entry's layout and kind.

    Returns
    -------
    list[dict]
        The decoded category rows, in listing order.
    """
    rows = categories(frame)
    require(
        [r["name"] for r in rows] == [e[0] for e in expected],
        "Category order/name bytes differ",
    )
    for row, (_, folder, count) in zip(rows, expected, strict=False):
        require(
            row["field"]
            == (
                LEGACY_CATEGORY_FIELD
                if version < MODERN_VERSION
                else MODERN_CATEGORY_FIELD
            ),
            "Category version branch differs",
        )
        require(
            row["kind"]
            == (
                (LEGACY_FOLDER_KIND if folder else LEGACY_CATEGORY_KIND)
                if version < MODERN_VERSION
                else (FOLDER_KIND if folder else CATEGORY_KIND)
            ),
            "Category target kind differs",
        )
        if version >= MODERN_VERSION:
            require(row["aux"] == count, "Category count/valence differs")
    return rows
