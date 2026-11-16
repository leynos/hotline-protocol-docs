"""Check the final listings, the cleanups, the catalogue and the oracle queries.

These checks run after every category has been seeded and deleted. They are the
last part of article deletion before the aggregate counts.
"""

import json
import typing as typ

from native_news_decode import categories
from protocol_capture import ORACLE_SHA256
from verify_native_article_deletion_catalogue import catalogue
from verify_native_article_deletion_checks import body, list_records
from verify_native_article_deletion_data import (
    FILES_BASELINE_ENTRIES,
    ORACLE_QUERY_COUNT,
    TITLES,
)
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_finalization(
    directory: Path,
    reports: dict[str, dict],
    references: dict[str, bytes],
) -> None:
    """Check the denied bodies, the baseline, the cleanups and the catalogue.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    reports : dict[str, dict]
        The verified report of each capture.
    references : dict[str, bytes]
        The article-list field that each deletion left, keyed by category.
    """
    denied_rows = list_records(references["denied"], "unchanged")
    for identifier in TITLES:
        body(
            reply(reports["final"], 500 + identifier),
            identifier,
            denied_rows,
            "unchanged",
        )
    baseline = listing(reply(reports["initial/preflight"], 11))
    require(len(baseline) == FILES_BASELINE_ENTRIES, "Files baseline inventory differs")
    for key in ["final", "cleanup", "publish", "remove-publisher"]:
        require(
            all(f["error"] == 0 for f in reports[key]["frames"]),
            "Finalization/cleanup failed",
        )
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            not categories(reply(reports[key], 90))
            and listing(reply(reports[key], 91))
            == (
                baseline
                if key != "publish"
                else {
                    **baseline,
                    b"m-nd24-publish": listing(reply(reports[key], 91))[
                        b"m-nd24-publish"
                    ],
                }
            ),
            "Owned cleanup listing differs",
        )
    catalogue(directory, references)


def check_oracles(directory: Path) -> None:
    """Check the oracle queries: their inventory, program identity and code.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    """
    addresses = {
        "100108a0",
        "10023830",
        "100249f0",
        "10025060",
        "10024620",
        "10025120",
        "10024280",
        "10024150",
        "10023180",
        "10056b90",
        "10008ad0",
        "10005ac0",
        "100233e0",
        "100248a0",
        "1000acf0",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERY_COUNT
        and {p.stem.removeprefix("ND-D-") for p in queries} == addresses,
        "Deletion oracle inventory differs",
    )
    for p in queries:
        query = json.loads(p.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"].get("isError", False)
            and query["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Deletion oracle identity/code differs",
        )
