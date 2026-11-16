"""Check the retained native news cache of the boundary corpus."""

import json
import typing as typ

from native_news_decode import articles
from verify_native_core import require
from verify_native_news_boundary_checks import navigation, title
from verify_native_news_boundary_data import (
    ARTICLE_COUNT,
    BLOCK_BYTES,
    BUCKET_LIMIT,
    DATA_START,
    HEADER_WORD_32,
    INDEX_MASK,
    INITIAL_PROBE_COUNT,
    LINK_OFFSETS,
    PUBLISHED_RECORD_COUNT,
    PUBLISHER_CATALOG_ID,
    REACHABLE_CHILD_COUNT,
    SLOT_BYTES,
    WORD_BYTES,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def _word(data: bytes, offset: int) -> int:
    """Read the big-endian word that starts at ``offset`` in ``data``.

    Parameters
    ----------
    data : bytes
        The cache file.
    offset : int
        The byte offset of the word.

    Returns
    -------
    int
        The value of the word; a short read yields the bytes that exist.
    """
    return int.from_bytes(data[offset : offset + WORD_BYTES], "big")


def storage(directory: Path, wire: bytes, dates: dict[int, bytes]) -> None:
    """Check the stored catalogue, cache, index and cleanup of the corpus.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    wire : bytes
        The sibling list reply that the cache must preserve.
    dates : dict[int, bytes]
        The date that each article was first seen with.
    """
    final = directory / "native-final-positive"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(
        {r["path"] for r in rows}
        == {
            "/Hotline19/News/mothra-news25",
            "/Hotline19/News/mothra-news25/siblings",
            "/Hotline19/Files/m-nb25-flush",
        },
        "Boundary positive catalogue differs",
    )
    category = next(r for r in rows if r["path"].endswith("/siblings"))
    data = (final / (category["key"] + ".data")).read_bytes()
    require(
        data[:8] == b"HLNZ\0\0\0\2"
        and _word(data, 32) == HEADER_WORD_32
        and _word(data, 44) == ARTICLE_COUNT,
        "Boundary stored article count/header differs",
    )
    offset = DATA_START + (_word(data, 36) - 1) * BLOCK_BYTES
    require(
        _word(data, 36) > 0
        and _word(data, 40) == len(wire)
        and data[offset : offset + len(wire)] == wire
        and len(articles(wire)) == REACHABLE_CHILD_COUNT,
        "Boundary cache must preserve count mismatch",
    )
    records = _stored_records(data)
    require(
        set(records) == set(range(1, ARTICLE_COUNT + 1)),
        "Stored orphan article record missing",
    )
    _check_index(data, records)
    _check_links(records, dates)
    _check_probes(directory)
    initial = _check_cleanup_probe(directory, rows)
    _check_published(final, directory / "native-published", rows, initial)


def _stored_records(data: bytes) -> dict[int, tuple[int, bytes]]:
    """Collect the stored article records of the cache.

    Parameters
    ----------
    data : bytes
        The cache file.

    Returns
    -------
    dict[int, tuple[int, bytes]]
        Each article identifier with its block number and the block.
    """
    records = {}
    for start in range(DATA_START, len(data) - (BLOCK_BYTES - 1), BLOCK_BYTES):
        block = data[start : start + BLOCK_BYTES]
        if block[4:8] == b"\0\0\0\xc0":
            identifier = int.from_bytes(block[36:40], "big")
            require(identifier not in records, "Duplicate native article record")
            records[identifier] = (1 + (start - DATA_START) // BLOCK_BYTES, block)
    return records


def _check_index(data: bytes, records: dict[int, tuple[int, bytes]]) -> None:
    """Check that the native ID index holds every stored article exactly once.

    Parameters
    ----------
    data : bytes
        The cache file.
    records : dict[int, tuple[int, bytes]]
        The stored article records, from ``_stored_records``.
    """
    indexed = {}
    index_base = DATA_START + (_word(data, 72) - 1) * BLOCK_BYTES
    require(_word(data, 76) == INDEX_MASK, "Boundary native index mask differs")
    for bucket in range(INDEX_MASK + 1):
        start = index_base + bucket * SLOT_BYTES
        first, count = _word(data, start), _word(data, start + WORD_BYTES)
        require(count <= BUCKET_LIMIT, "Boundary index bucket cardinality differs")
        for i in range(count):
            entry = DATA_START + (first - 1) * BLOCK_BYTES + i * SLOT_BYTES
            identifier = _word(data, entry)
            native_block = _word(data, entry + WORD_BYTES)
            require(
                identifier not in indexed and (identifier & INDEX_MASK) == bucket,
                "Boundary index entry differs",
            )
            indexed[identifier] = native_block
    require(
        indexed == {i: b for i, (b, _) in records.items()},
        "Native ID index does not preserve all 103 articles",
    )


def _check_links(
    records: dict[int, tuple[int, bytes]], dates: dict[int, bytes]
) -> None:
    """Check the stored links, title and date of every stored article.

    Parameters
    ----------
    records : dict[int, tuple[int, bytes]]
        The stored article records, from ``_stored_records``.
    dates : dict[int, bytes]
        The date that each article was first seen with.
    """
    by_block = {block: identifier for identifier, (block, _) in records.items()}
    for identifier, (_, block) in records.items():
        links = tuple(
            int.from_bytes(block[n : n + WORD_BYTES], "big") for n in LINK_OFFSETS
        )
        require(
            tuple(by_block[n] if n else 0 for n in links) == navigation(identifier),
            "Stored sibling/parent links differ",
        )
        length = block[68]
        require(
            block[69 : 69 + length] == title(identifier)
            and block[56:64] == dates[identifier],
            "Stored title/date differs",
        )


def _check_probes(directory: Path) -> None:
    """Check that the two out-of-range probes found nothing.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    """
    # The two initial probes addressed catalogue IDs beyond the actual maximum.
    for name in ["native-final", "native-final-wide"]:
        require(
            json.loads((directory / name / "extraction.json").read_text())["records"]
            == [],
            "Out-of-range probe changed",
        )


def _check_cleanup_probe(directory: Path, rows: list[dict]) -> list[dict]:
    """Check the initial cleanup probe, which must not claim the owned objects.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    rows : list[dict]
        The positive catalogue records.

    Returns
    -------
    list[dict]
        The records that the initial cleanup probe returned.
    """
    initial = json.loads((directory / "native-cleanup/extraction.json").read_text())[
        "records"
    ]
    require(
        len(initial) == INITIAL_PROBE_COUNT
        and not ({r["catalog"] for r in initial} & {r["catalog"] for r in rows}),
        "Initial cleanup probe must remain inconclusive for owned objects",
    )
    return initial


def _check_published(
    final: Path, published: Path, rows: list[dict], initial: list[dict]
) -> None:
    """Check the published catalogue and the cleaned forks of the owned articles.

    Parameters
    ----------
    final : pathlib.Path
        The positive catalogue directory, whose forks are the originals.
    published : pathlib.Path
        The published catalogue directory.
    rows : list[dict]
        The positive catalogue records.
    initial : list[dict]
        The records that the initial cleanup probe returned.
    """
    after = {
        r["catalog"]: r
        for r in json.loads((published / "extraction.json").read_text())["records"]
    }
    require(
        len(after) == PUBLISHED_RECORD_COUNT
        and set(after)
        == {r["catalog"] for r in rows + initial} | {PUBLISHER_CATALOG_ID},
        "Boundary published catalogue inventory differs",
    )
    require(
        after[PUBLISHER_CATALOG_ID]["path"] == "/Hotline19/Files/m-nb25-publish",
        "Separate boundary publisher differs",
    )
    for row in rows:
        moved = after[row["catalog"]]
        require(
            moved["path"]
            == row["path"]
            .replace("/Hotline19/News/", "/Trash/")
            .replace("/Hotline19/Files/", "/Trash/"),
            "Boundary Trash identity/path differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (final / (row["key"] + "." + fork)).read_bytes()
                    == (published / (moved["key"] + "." + fork)).read_bytes(),
                    "Boundary cleanup changed original fork/cache",
                )
