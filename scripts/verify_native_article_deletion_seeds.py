"""Check the inspected prefix, the resumed seed and the deletion of each category.

For each owned category, in order, the checks are: the recovered prefix, the
bounded resume that completes it, the deletion that follows, and the independent
final list that shows the result.
"""

import dataclasses as dc
import typing as typ

from native_news_decode import articles, categories
from verify_native_article_deletion_checks import (
    deletion,
    error,
    graph,
    list_records,
    measured_wait,
)
from verify_native_article_deletion_data import (
    EXISTING_CATEGORY_CASES,
    FULL_PREFIX_ARTICLES,
    FULL_PREFIX_CASES,
    PARTIAL_PREFIX_ARTICLES,
    PARTIAL_PREFIX_INDEX,
    TITLES,
)
from verify_native_auth import reply
from verify_native_core import require
from verify_native_shx import fields


@dc.dataclass(frozen=True, slots=True)
class _Inspection:
    """The recovered prefix of one category.

    Attributes
    ----------
    count : int
        The number of articles that the prefix holds.
    frame : dict[str, typing.Any]
        The reply that listed the prefix.
    rows : list[dict[str, typing.Any]]
        The articles of the prefix, empty when the category is absent.
    """

    count: int
    frame: dict[str, typ.Any]
    rows: list[dict[str, typ.Any]]


def _check_inspection(
    recovered: dict,
    index: int,
    name: str,
    inventory: dict[str, dict[str, typ.Any]],
) -> _Inspection:
    """Check the recovered prefix of one category against the inventory.

    Parameters
    ----------
    recovered : dict
        The parsed ``report.json`` of the inventory recovery.
    index : int
        The position of the category in ``specs``.
    name : str
        The category name.
    inventory : dict[str, dict[str, typing.Any]]
        The resume inventory of the corpus, keyed by category.

    Returns
    -------
    _Inspection
        The prefix count, the listing reply and the articles of the prefix.
    """
    prefix = inventory[name]
    count = (
        FULL_PREFIX_ARTICLES
        if index < FULL_PREFIX_CASES
        else PARTIAL_PREFIX_ARTICLES
        if index == PARTIAL_PREFIX_INDEX
        else 0
    )
    require(
        prefix == {"completed": count, "exists": index < EXISTING_CATEGORY_CASES},
        "Recovered prefix inventory differs",
    )
    frame = reply(recovered, 100 + index)
    if count:
        rows = articles(fields(frame)[321])
        require(
            {r["id"] for r in rows} == set(range(1, count + 1)),
            "Recovered public IDs differ",
        )
        for row in rows:
            require(
                row["title"] == TITLES[row["id"]]
                and row["parent"] == graph("unchanged")[1][row["id"]][2],
                "Recovered prefix identity differs",
            )
    else:
        rows = []
        error(
            frame,
            b"Cannot get article list because the specified category "
            b"could not be found.",
        )
    return _Inspection(count=count, frame=frame, rows=rows)


def _check_resumed(
    reports: dict[str, dict],
    index: int,
    spec: dict[str, typ.Any],
    inspection: _Inspection,
) -> bytes:
    """Check the bounded resume and the deletion of one category.

    Parameters
    ----------
    reports : dict[str, dict]
        The verified report of each capture.
    index : int
        The position of the category in ``specs``.
    spec : dict[str, typing.Any]
        The specification of the category.
    inspection : _Inspection
        The prefix that was recovered for the category.

    Returns
    -------
    bytes
        The article-list field that the deletion left for the category.
    """
    name = spec["case"]
    resumed = reports["resumed/" + name]
    require(all(f["error"] == 0 for f in resumed["frames"]), "Bounded seed failed")
    seeded = list_records(fields(reply(resumed, 20))[321], "unchanged")
    if inspection.count:
        require(
            fields(reply(resumed, 10)) == fields(inspection.frame),
            "Prefix changed between inspection and resume",
        )
        require(
            all(seeded[row["id"]] == row for row in inspection.rows),
            "Resume changed existing article metadata",
        )
    require(
        fields(reply(reports["deletions/" + name], 10)) == fields(reply(resumed, 20)),
        "Deletion did not start from verified seed",
    )
    measured_wait(resumed, "pause")
    value = deletion(reports["deletions/" + name], spec)
    require(
        fields(reply(reports["final"], 100 + index)) == {321: value},
        "Independent final list differs",
    )
    return value


def check_seeds(
    reports: dict[str, dict],
    specifications: list[dict[str, typ.Any]],
    inventory: dict[str, dict[str, typ.Any]],
) -> dict[str, bytes]:
    """Check the recovered prefix, the resume and the deletion of every category.

    Parameters
    ----------
    reports : dict[str, dict]
        The verified report of each capture.
    specifications : list[dict[str, typing.Any]]
        The specifications from ``native_news_delete_cases.specs``.
    inventory : dict[str, dict[str, typing.Any]]
        The resume inventory of the corpus, keyed by category.

    Returns
    -------
    dict[str, bytes]
        The article-list field that each deletion left, keyed by category.
    """
    recovered = reports["inventory-recovery"]
    require(
        not categories(reply(reports["initial/preflight"], 10)),
        "Owned initial News root not empty",
    )
    references: dict[str, bytes] = {}
    for index, spec in enumerate(specifications):
        inspection = _check_inspection(recovered, index, spec["case"], inventory)
        references[spec["case"]] = _check_resumed(reports, index, spec, inspection)
    return references
