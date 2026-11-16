"""Classify the measured parents of the 212/325 path matrix.

Part of the path-fields runner (``native_path_fields_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. The checks run in a fixed order, so a fault is reported by the first
check that finds it. A move is classified only from the measured parents, never
from an acknowledgement.
"""

import collections
import dataclasses as dc
import typing as typ

import native_path_fields_cases as cases
from native_path_fields_control_frames import (
    MARKERS,
    PARENTS,
    Report,
    exact_transition,
    location,
    need,
    news_view,
    one,
)

FILE_CASES = 6
CASE_COUNT = 12
MAX_UID = 65535
ORIGINAL_ACCOUNTS = 2
MUTATIONS = 20
REQUESTS = 82
NEWS_HIGH = {"field": 323, "kind": 3}
NEWS_PARENTS = frozenset({"news-root", "news-high", "empty"})
WRAPPER_NAMES = (b"S".hex(), b"H-\x9a".hex())


@dc.dataclass(slots=True)
class Prior:
    """Where each marker was, and what each parent held, before the case."""

    parents: dict[str, str]
    views: dict[str, list[str]]
    types: dict[str, dict[str, str]]


def _setup(by_label: dict[str, Report]) -> list[Report]:
    """Require the owned names to be new, the accounts and the setup views right.

    Returns
    -------
    list[dict[str, typing.Any]]
        The initial news root names.
    """
    pre_files = by_label["initial-files-root"]["names"]
    pre_news = by_label["initial-news-root"]["names"]
    need(
        cases.FILES.hex() not in pre_files
        and cases.NEWS.hex() not in {v["name_hex"] for v in pre_news},
        "Owned names preexist",
    )
    initial_accounts = by_label["initial-accounts"]["accounts"]
    need(
        len(initial_accounts) == ORIGINAL_ACCOUNTS
        and by_label["final-accounts"]["accounts"] == initial_accounts,
        "Original accounts differ",
    )
    own_uid = by_label["initial-roster"]["uid"]
    need(
        1 <= own_uid <= MAX_UID and by_label["final-roster"]["uid"] == own_uid,
        "Own UID differs",
    )
    need(
        collections.Counter(by_label["setup-view-S"]["names"])
        == collections.Counter(m.hex() for m in MARKERS)
        and collections.Counter(by_label["setup-view-wrapper"]["names"])
        == collections.Counter(WRAPPER_NAMES)
        and by_label["setup-view-H"]["names"] == [],
        "Owned setup parent views differ",
    )
    high = by_label["setup-news-high"]["names"]
    need(
        high == [{**NEWS_HIGH, "name_hex": cases.CATEGORY.hex()}],
        "Owned News high differs",
    )
    baseline_news = {v["name_hex"] for v in pre_news}
    if "setup-news-root" in by_label:
        setup_news = by_label["setup-news-root"]["names"]
        need(
            {v["name_hex"] for v in setup_news} == baseline_news | {cases.NEWS.hex()},
            "Owned News root differs",
        )
    return pre_news


def _file_case(
    plan: Report,
    report: Report,
    case: tuple[int, Report],
    prior: Prior,
) -> None:
    """Classify one move of a marker out of the source parent."""
    i, result = case
    by_label = {v["label"]: v for v in report["views"]}
    marker = bytes.fromhex(plan["cells"][i]["marker_hex"])
    expected_before = (
        by_label["setup-view-S"]["names"]
        if i == 0
        else by_label[f"after-view-{i - 1}-S"]["names"]
    )
    need(
        result["before_parent"] == "S" and result["before_views"] == expected_before,
        "Before S view not cached",
    )
    views = {p: by_label[f"after-view-{i}-{p}"]["names"] for p in PARENTS}
    types = {p: by_label[f"after-view-{i}-{p}"]["types"] for p in PARENTS}
    found = location(views, marker)
    need(
        found is not None and result["selected_parent"] == found,
        "Missing/foreign selected marker",
    )
    found = typ.cast("str", found)
    exact_transition(prior.views, views, (marker, found), (prior.types, types))
    for other, old_parent in prior.parents.items():
        if other != marker.hex():
            need(
                location(views, bytes.fromhex(other)) == old_parent,
                "Other owned marker moved",
            )
    need(
        result["after_views"] == views
        and result["after_info_parent_hex"] == PARENTS[str(found)].hex(),
        "Selected parent/readback differs",
    )
    prior.parents[marker.hex()] = found
    prior.views = views
    prior.types = types
    reply = one(report["frames"], "main", result["request_id"])
    need(result["status"] == reply["error"], "Move status receipt differs")
    if found == "S":
        need(reply["error"] != 0, "Successful move without effect ambiguous")
    else:
        need(reply["error"] == 0, "Failed move changed selected parent")


def _news_parent(actual: list[Report], pre_news: list[Report]) -> str:
    """Name the parent that a successful news reply shows.

    Returns
    -------
    str
        ``news-root``, ``news-high`` or ``empty``.

    Raises
    ------
    ValueError
        If the reply matches none of them.
    """
    names = collections.Counter(v["name_hex"] for v in actual)
    expected = collections.Counter(v["name_hex"] for v in pre_news)
    expected[cases.NEWS.hex()] += 1
    if names == expected:
        return "news-root"
    if names == collections.Counter([cases.CATEGORY.hex()]):
        return "news-high"
    if not names:
        return "empty"
    message = "Foreign News selected parent"
    raise ValueError(message)


def _news_case(report: Report, result: Report, pre_news: list[Report]) -> None:
    """Classify one news request against what its reply shows."""
    reply = one(report["frames"], "main", result["request_id"])
    need(result["status"] == reply["error"], "News status receipt differs")
    if reply["error"] == 0:
        actual = news_view(reply)
        need(
            result["names"] == actual and result["selected_parent"] in NEWS_PARENTS,
            "News readback differs",
        )
        need(
            result["selected_parent"] == _news_parent(actual, pre_news),
            "News selected parent differs",
        )
    else:
        need(
            result["selected_parent"] == "error" and result["names"] == [],
            "News error selection differs",
        )


def _restored(by_label: dict[str, Report], pre_news: list[Report]) -> None:
    """Require the Files and News roots to be as they began."""
    pre_files = by_label["initial-files-root"]["names"]
    need(
        collections.Counter(by_label["final-files-root"]["names"])
        == collections.Counter(pre_files),
        "Files root not restored",
    )
    final_news = by_label["final-news-root"]["names"]
    need(
        collections.Counter((v["field"], v["kind"], v["name_hex"]) for v in final_news)
        == collections.Counter(
            (v["field"], v["kind"], v["name_hex"]) for v in pre_news
        ),
        "News root not restored",
    )


def classify_views(plan: Report, report: Report) -> None:
    """Classify only measured selected parents; never derive a move from ACK.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The run's report.
    """
    records = report["views"]
    by_label = {v["label"]: v for v in records}
    need(len(by_label) == len(records), "Duplicate view label")
    pre_news = _setup(by_label)
    prior = Prior(
        {marker.hex(): "S" for marker in MARKERS},
        {
            "S": by_label["setup-view-S"]["names"],
            "wrapper": by_label["setup-view-wrapper"]["names"],
            "H": by_label["setup-view-H"]["names"],
        },
        {parent: by_label[f"setup-view-{parent}"]["types"] for parent in PARENTS},
    )
    results = report["results"]
    need(len(results) == CASE_COUNT, "Twelve field outcomes required")
    for i, result in enumerate(results):
        need(
            result["index"] == i
            and result["field"] == plan["cells"][i]["field"]
            and result["value_hex"] == plan["cells"][i]["value_hex"],
            "Field cell identity differs",
        )
        if i < FILE_CASES:
            _file_case(plan, report, (i, result), prior)
        else:
            _news_case(report, result, pre_news)
    _restored(by_label, pre_news)
    need(
        report["mutation_count"] == MUTATIONS and report["request_count"] == REQUESTS,
        "Request/mutation ceiling differs",
    )
