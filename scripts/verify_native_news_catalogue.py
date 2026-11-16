"""Check the stored news catalogue and the cleanup that moved its objects."""

import json
import typing as typ

from native_news_cases import ROOT
from verify_native_core import require
from verify_native_news_data import (
    BLOCK_SIZE,
    CATEGORY_LIST_ID,
    FINAL_RECORD_COUNT,
    HLNZ_HEADER_BYTES,
    NESTED_LIST_ID,
    PUBLISHED_RECORD_COUNT,
    ZERO_LIST_ID,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

# (suffix, article count, cached list identifier or None) for each stored category
CATEGORY_OBJECTS = (
    ("category", 6, CATEGORY_LIST_ID),
    ("zero-articles", 0, ZERO_LIST_ID),
    ("bundle/nested", 1, NESTED_LIST_ID),
    ("bundle/child/deep", 0, None),
)


def catalogue(
    directory: Path, reference: dict[int, bytes], listing_rows: dict[bytes, dict]
) -> dict:
    """Check the final catalogue and its cleanup, and return their summary.

    Returns
    -------
    dict
        The summary written to the corpus report.
    """
    final = directory / "native-final"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(
        len(rows) == FINAL_RECORD_COUNT,
        "News positive final catalogue inventory differs",
    )
    objects = {r["catalog"]: r for r in rows}
    check_category_storage(final, rows, listing_rows, reference)
    moved = check_publication(directory, objects)
    check_moves(final, directory / "native-published", objects, moved)
    return {
        "positive_before": 10,
        "initial_positive_cleanup": 0,
        "positive_original_objects_after_upload_flush": 10,
        "separate_publisher": 1,
        "scope": (
            "Publisher removed by wire ACK/listing; "
            "no post-removal disk/restart durability claim"
        ),
    }


def check_category_storage(
    final: Path,
    rows: list[dict],
    listing_rows: dict[bytes, dict],
    reference: dict[int, bytes],
) -> None:
    """Check the stored HLNZ header and the cached list of each category."""
    for suffix, count, cache_id in CATEGORY_OBJECTS:
        row = next(
            r
            for r in rows
            if r["path"] == "/Hotline19/News/" + ROOT.decode() + "/" + suffix
        )
        data = (final / (row["key"] + ".data")).read_bytes()
        stat = (final / (row["key"] + ".stat.txt")).read_text()
        require(
            not row["directory"]
            and "484c4e5a  HLNZ" in stat
            and "48544c53  HTLS" in stat
            and data[:8] == b"HLNZ\0\0\0\2",
            "Native category storage kind/header differs",
        )
        require(
            int.from_bytes(data[44:48], "big") == count, "HLNZ article count differs"
        )
        name = suffix.rsplit("/", maxsplit=1)[-1].encode()
        wire = listing_rows[name]
        require(
            wire["metadata"] == data[8:24]
            and wire["aux"] == int.from_bytes(data[44:48], "big") & 65535
            and wire["word20"] == int.from_bytes(data[24:28], "big")
            and wire["word24"] == int.from_bytes(data[28:32], "big"),
            "Modern category metadata does not match native header",
        )
        if cache_id is not None:
            check_cached_list(data, reference, cache_id)


def check_cached_list(data: bytes, reference: dict[int, bytes], cache_id: int) -> None:
    """Check that the cached block of an HLNZ object holds the reference list."""
    block, index, length = (
        int.from_bytes(data[n : n + 4], "big") for n in [32, 36, 40]
    )
    offset = HLNZ_HEADER_BYTES + (index - 1) * block
    require(
        block == BLOCK_SIZE
        and index > 0
        and length == len(reference[cache_id])
        and data[offset : offset + length] == reference[cache_id],
        "HLNZ cached list does not match wire/rebuilt list",
    )


def check_publication(directory: Path, objects: dict[str, dict]) -> dict[str, dict]:
    """Check the cleanup probe and the published inventory, and index the moves.

    Returns
    -------
    dict[str, dict]
        The published rows, by catalogue identity.
    """
    initial = json.loads((directory / "native-cleanup/extraction.json").read_text())
    require(initial["records"] == [], "Initial inconclusive cleanup probe differs")
    published = directory / "native-published"
    published_rows = json.loads((published / "extraction.json").read_text())["records"]
    require(
        len(published_rows) == PUBLISHED_RECORD_COUNT,
        "Published cleanup inventory differs",
    )
    moved = {r["catalog"]: r for r in published_rows}
    require(
        set(objects) < set(moved),
        "Published cleanup lost original catalogue identities",
    )
    publisher = moved[next(iter(set(moved) - set(objects)))]
    require(
        publisher["path"] == "/Hotline19/Files/m-news23-publish"
        and (published / (publisher["key"] + ".data")).read_bytes() == b"metadata-data",
        "Separate publisher object differs",
    )
    return moved


def check_moves(
    final: Path, published: Path, objects: dict[str, dict], moved: dict[str, dict]
) -> None:
    """Check the Trash path and the stored forks of each moved object."""
    for identifier, row in objects.items():
        target = moved[identifier]
        expected_path = (
            row["path"]
            .replace("/Hotline19/News/", "/Trash/")
            .replace("/Hotline19/Files/", "/Trash/")
        )
        require(
            target["path"] == expected_path,
            "Published Trash path/subtree identity differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (final / (row["key"] + "." + fork)).read_bytes()
                    == (published / (target["key"] + "." + fork)).read_bytes(),
                    "News cleanup changed stored forks/cache",
                )
