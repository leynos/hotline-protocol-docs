"""Check the post, listing, cleanup and oracle replies of the news corpus."""

import datetime as dt
import json
import typing as typ
from itertools import pairwise

from native_news_cases import VERSIONS, bodies, structures
from native_news_decode import articles, categories
from native_wire_names import FIELD_ERROR_TEXT
from protocol_capture import ORACLE_SHA256
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_news_catalogue import catalogue
from verify_native_news_data import (
    ARTICLE_LIST_FIELD,
    BUNDLE_LIST_ID,
    CATEGORY_KIND,
    CATEGORY_LIST_ID,
    CHILD_LIST_ID,
    COMPLETED_REPORT_COUNT,
    EMPTY_ARTICLE_LIST,
    EMPTY_LIST_ID,
    FILES_BASELINE_COUNT,
    LIST_AFTER_POST_20,
    LIST_AFTER_POST_21,
    LIST_AFTER_POST_23,
    LIVENESS_ID,
    MISSING_BODY_POST_ID,
    MODERN_VERSION,
    NESTED_LIST_ID,
    ORACLE_ADDRESSES,
    ORACLE_QUERY_COUNT,
    PAIRED_CONNECTION_COUNT,
    PUBLISHER_LIST_ID,
    ROOT_ENTRIES,
    ROOT_LIST_ID,
    VALID_POST_IDS,
    ZERO_LIST_ID,
)
from verify_native_news_records import article_records, category_view
from verify_native_news_replies import body_reply, structure
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_start(reports: dict[str, dict]) -> None:
    """Check the owned preflight and seed, then the order of the fixture runs."""
    require(
        not categories(reply(reports["preflight"], ROOT_LIST_ID))
        and all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "News owned preflight/seed failed",
    )
    chronology = (
        ["preflight", "seed", "posts", "children", "grandchild"]
        + [f"listings/version-{v}" for v in VERSIONS]
        + ["structures/" + name for name in structures()]
        + ["bodies/" + name for name in bodies()]
        + [
            "files-preflight",
            "final",
            "cleanup",
            "files-after",
            "publish",
            "remove-publisher",
        ]
    )
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(chronology)
        ),
        "News fixture chronology differs",
    )


def check_posts(reports: dict[str, dict]) -> tuple[bytes, list[dict], dict[int, dict]]:
    """Check the threaded article lists and the posts that built them.

    Returns
    -------
    tuple[bytes, list[dict], dict[int, dict]]
        The article list rebuilt by the grandchild read, its decoded rows, and
        those rows indexed by public identifier.
    """
    require(
        fields(reply(reports["posts"], EMPTY_LIST_ID))
        == {ARTICLE_LIST_FIELD: EMPTY_ARTICLE_LIST},
        "Initial empty article-list differs",
    )
    for identifier, order in [
        (LIST_AFTER_POST_20, [1]),
        (LIST_AFTER_POST_21, [1, 2]),
        (LIST_AFTER_POST_23, [1, 2, 3]),
    ]:
        article_records(
            fields(reply(reports["posts"], identifier))[ARTICLE_LIST_FIELD], order
        )
    require(
        all(
            reply(reports["posts"], i)["error"] == 0
            and fields(reply(reports["posts"], i)) == {}
            for i in VALID_POST_IDS
        ),
        "Valid initial posts failed",
    )
    require(
        reply(reports["posts"], MISSING_BODY_POST_ID)["error"] == 1
        and fields(reply(reports["posts"], MISSING_BODY_POST_ID))
        == {
            FIELD_ERROR_TEXT: b"Cannot post article because invalid data was specified."
        },
        "Missing-body post error differs",
    )
    article_records(
        fields(reply(reports["children"], LIST_AFTER_POST_21))[ARTICLE_LIST_FIELD],
        [1, 4, 5, 2, 3],
    )
    rebuilt = fields(reply(reports["grandchild"], LIST_AFTER_POST_20))[
        ARTICLE_LIST_FIELD
    ]
    rows = article_records(rebuilt, [1, 4, 6, 5, 2, 3])
    by_id = {r["id"]: r for r in rows}
    return rebuilt, rows, by_id


def check_version(
    report: dict, version: int, rebuilt: bytes, references: dict[int, bytes]
) -> list[dict]:
    """Check the category and article-list replies of one listing version.

    Returns
    -------
    list[dict]
        The root, nested and deep category rows of the version.
    """
    root_rows = category_view(reply(report, ROOT_LIST_ID), version, ROOT_ENTRIES)
    require(
        not categories(reply(report, EMPTY_LIST_ID)), "Empty bundle listing differs"
    )
    nested_rows = category_view(
        reply(report, BUNDLE_LIST_ID),
        version,
        [(b"child", True, 1), (b"nested", False, 1)],
    )
    deep_rows = category_view(
        reply(report, CHILD_LIST_ID), version, [(b"deep", False, 0)]
    )
    for identifier in (CATEGORY_LIST_ID, ZERO_LIST_ID, NESTED_LIST_ID):
        value = fields(reply(report, identifier))[ARTICLE_LIST_FIELD]
        if identifier in references:
            require(
                value == references[identifier],
                "Cached/version article-list bytes differ",
            )
        references[identifier] = value
    require(
        references[CATEGORY_LIST_ID] == rebuilt
        and references[ZERO_LIST_ID] == EMPTY_ARTICLE_LIST,
        "Rebuilt/cached/empty article list differs",
    )
    nested = articles(references[NESTED_LIST_ID])
    require(
        len(nested) == 1
        and nested[0]["id"] == 1
        and nested[0]["title"] == b"Nested root"
        and nested[0]["flavours"] == [(b"text/plain", 11)],
        "Nested-category list differs",
    )
    return root_rows + nested_rows + deep_rows


def check_versions(
    reports: dict[str, dict], rebuilt: bytes
) -> tuple[dict[bytes, dict], set[str], dict[int, bytes]]:
    """Check every listing version and collect its opaque tails and modern rows.

    Returns
    -------
    tuple[dict[bytes, dict], set[str], dict[int, bytes]]
        The modern rows by name, the hexadecimal tails, and the article-list
        bytes of each cached identifier.
    """
    all_modern: dict[bytes, dict] = {}
    tails: set[str] = set()
    references: dict[int, bytes] = {}
    for version in VERSIONS:
        rows = check_version(
            reports[f"listings/version-{version}"], version, rebuilt, references
        )
        if version >= MODERN_VERSION:
            for row in rows:
                tails.add(row["tail"].hex())
                if row["kind"] == CATEGORY_KIND:
                    all_modern[row["name"]] = row
    return all_modern, tails, references


def check_tails(tails: set[str]) -> None:
    """Check that at least one opaque category tail is nonzero."""
    require(
        any(bytes.fromhex(v) != bytes(len(bytes.fromhex(v))) for v in tails),
        "Nonzero opaque category tails not retained",
    )


def check_structures(reports: dict[str, dict]) -> None:
    """Check the reply to every structure change."""
    for label, (_, expectation) in structures().items():
        structure(reports["structures/" + label], expectation)


def check_bodies(reports: dict[str, dict], by_id: dict[int, dict]) -> None:
    """Check the reply to every article-body read."""
    for label, (_, expectation) in bodies().items():
        body_reply(reports["bodies/" + label], expectation, by_id)


def check_cleanup(reports: dict[str, dict]) -> None:
    """Check that the cleanup operations succeeded and removed the owned tree."""
    for key in ["final", "cleanup", "publish", "remove-publisher"]:
        require(
            all(f["error"] == 0 for f in reports[key]["frames"]),
            "News final/cleanup operation failed",
        )
    baseline = listing(reply(reports["files-preflight"], ROOT_LIST_ID))
    require(
        len(baseline) == FILES_BASELINE_COUNT
        and b"m-news23-flush" not in baseline
        and b"m-news23-publish" not in baseline
        and listing(reply(reports["files-after"], ROOT_LIST_ID))
        == listing(reply(reports["remove-publisher"], LIVENESS_ID))
        == baseline,
        "News helper cleanup did not restore Files",
    )
    require(
        not categories(reply(reports["cleanup"], LIVENESS_ID))
        and not categories(reply(reports["publish"], LIVENESS_ID))
        and not categories(reply(reports["remove-publisher"], PUBLISHER_LIST_ID)),
        "Owned News hierarchy remains after cleanup",
    )


def check_aggregates(
    manifest: dict, reports: dict[str, dict], connections: int
) -> None:
    """Check the report and connection totals against the manifest."""
    require(
        manifest["completed_reports"] == len(reports) == COMPLETED_REPORT_COUNT
        and manifest["paired_connections"] == connections == PAIRED_CONNECTION_COUNT,
        "News aggregate counts differ",
    )


def check_oracle(directory: Path) -> None:
    """Check the oracle query inventory and the identity of each query."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERY_COUNT
        and {p.stem.removeprefix("NW-D-") for p in queries} == ORACLE_ADDRESSES,
        "News oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "News oracle identity/code differs",
        )


def check_results(
    directory: Path, manifest: dict, reports: dict[str, dict], connections: int
) -> dict:
    """Run the reply checks in order and return the corpus summary.

    Returns
    -------
    dict
        The summary that the command line prints.
    """
    check_start(reports)
    rebuilt, rows, by_id = check_posts(reports)
    all_modern, tails, references = check_versions(reports, rebuilt)
    check_tails(tails)
    check_structures(reports)
    check_bodies(reports, by_id)
    check_cleanup(reports)
    check_aggregates(manifest, reports, connections)
    check_oracle(directory)
    return {
        "completed_reports": COMPLETED_REPORT_COUNT,
        "paired_connections": connections,
        "controlled_versions": VERSIONS,
        "threaded_public_id_order": [r["id"] for r in rows],
        "structure_errors": 14,
        "body_successes": 5,
        "body_errors": 4,
        "opaque_tail_hex": sorted(tails),
        "oracle_queries": ORACLE_QUERY_COUNT,
        "catalogue": catalogue(directory, references, all_modern),
        "scope": (
            "Native category/list fixtures, not identified modern peer coverage; "
            "broader navigation/date/flavour/sibling limits, "
            "posting/deletion/partial storage failures and restart durability "
            "remain open"
        ),
    }
