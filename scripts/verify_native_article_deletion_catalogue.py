"""Check the stored catalogue, its physical caches and the trash after deletion.

This is the storage part of article deletion. It is re-exported by
``verify_native_article_deletion``, which the tests import by name.
"""

import json
import typing as typ

from native_news_decode import articles
from verify_native_article_deletion_data import (
    CACHE_BLOCK_BYTES,
    CATALOGUE_ROWS,
    PUBLISHED_ROWS,
)
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path


def _named_row(rows: list[dict], name: str) -> dict:
    """Find the catalogue record of one owned News category.

    Parameters
    ----------
    rows : list[dict]
        The records of the final native extraction.
    name : str
        The category name below the owned News root.

    Returns
    -------
    dict
        The first record whose path names the category.
    """
    return next(r for r in rows if r["path"] == "/Hotline19/News/mothra-news24/" + name)


def _check_reference(final: Path, row: dict, value: bytes) -> None:
    """Check the stored fork, the cache header and the cached list of a category.

    Parameters
    ----------
    final : pathlib.Path
        The directory of the final native extraction.
    row : dict
        The catalogue record of the category.
    value : bytes
        The article-list field that the deletion left for the category.
    """
    data = (final / (row["key"] + ".data")).read_bytes()
    stat = (final / (row["key"] + ".stat.txt")).read_text()
    block, index, length, count = (
        int.from_bytes(data[n : n + 4], "big") for n in [32, 36, 40, 44]
    )
    offset = 512 + (index - 1) * block
    require(
        not row["directory"]
        and data[:8] == b"HLNZ\0\0\0\2"
        and "484c4e5a  HLNZ" in stat
        and "48544c53  HTLS" in stat
        and count == len(articles(value))
        and block == CACHE_BLOCK_BYTES
        and index > 0
        and length == len(value)
        and data[offset : offset + length] == value,
        "Deletion storage count/cache differs",
    )


def _check_trash(final: Path, published: Path, row: dict, target: dict) -> None:
    """Check that a trashed category keeps its stored forks.

    Parameters
    ----------
    final : pathlib.Path
        The directory of the final native extraction.
    published : pathlib.Path
        The directory of the published native extraction.
    row : dict
        The catalogue record of the category before the trash.
    target : dict
        The catalogue record of the same category after the trash.
    """
    require(
        target["path"]
        == row["path"]
        .replace("/Hotline19/News/", "/Trash/")
        .replace("/Hotline19/Files/", "/Trash/"),
        "Trash identity/path differs",
    )
    if not row["directory"]:
        for fork in ["data", "rsrc"]:
            require(
                (final / (row["key"] + "." + fork)).read_bytes()
                == (published / (target["key"] + "." + fork)).read_bytes(),
                "Trash changed stored fork/cache",
            )


def _check_publication(directory: Path, final: Path, rows: list[dict]) -> None:
    """Check the published catalogue: its identities, its publisher and the trash.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    final : pathlib.Path
        The directory of the final native extraction.
    rows : list[dict]
        The records of the final native extraction.
    """
    published = directory / "native-published"
    moved = {
        r["catalog"]: r
        for r in json.loads((published / "extraction.json").read_text())["records"]
    }
    originals = {r["catalog"]: r for r in rows}
    require(
        len(moved) == PUBLISHED_ROWS and set(originals) < set(moved),
        "Published catalogue identities differ",
    )
    publisher = moved[next(iter(set(moved) - set(originals)))]
    require(
        publisher["path"] == "/Hotline19/Files/m-nd24-publish",
        "Separate publisher differs",
    )
    for identifier, row in originals.items():
        _check_trash(final, published, row, moved[identifier])


def catalogue(directory: Path, references: dict[str, bytes]) -> None:
    """Check the stored catalogue of the deleted categories and their trash.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    references : dict[str, bytes]
        The article-list field that each deletion left, keyed by category.
    """
    final = directory / "native-final"
    rows = json.loads((final / "extraction.json").read_text())["records"]
    require(
        len(rows) == CATALOGUE_ROWS,
        "Deletion positive catalogue inventory differs",
    )
    for name, value in references.items():
        _check_reference(final, _named_row(rows, name), value)
    require(
        json.loads((directory / "native-cleanup/extraction.json").read_text())[
            "records"
        ]
        == [],
        "Initial inconclusive probe differs",
    )
    _check_publication(directory, final, rows)
