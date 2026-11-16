"""Gates on the observed outcome of each of the twelve tested values."""

import typing as typ

from verify_native_path_fields_constants import (
    CASE_EVENTS,
    CASE_FRAMES,
    CASE_REQUESTS,
    CASE_RESULTS,
    CASE_VIEWS,
    CATEGORY_FIELD,
    CATEGORY_KIND,
    DATA,
    EMPTY_TEXT,
    FILE_CELLS,
    MUTATION_COUNT,
    PROGRESS_ENTRIES,
)
from verify_native_path_fields_core import need, read

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path


def _results(cases: types.ModuleType, results: list[dict]) -> None:
    """Check each observed cell against its planned value and its location."""
    for index, result in enumerate(results):
        cell = cases.cells()[index]
        need(
            result["index"] == index
            and result["field"] == cell["field"]
            and result["value_hex"] == cell["value_hex"]
            and result["status"] == 0
            and result["selected_parent"]
            == ("H" if index < FILE_CELLS else "news-high"),
            f"Observed cell {index} differs",
        )
        if index < FILE_CELLS:
            need(
                result["after_info_parent_hex"] == cases.HIGH.hex()
                and result["error_fields"] == [],
                f"Move location/error {index} differs",
            )
        else:
            need(
                result["names"]
                == [
                    {
                        "field": CATEGORY_FIELD,
                        "kind": CATEGORY_KIND,
                        "name_hex": cases.CATEGORY.hex(),
                    }
                ],
                f"News folder {index} differs",
            )


def _summary(corpus: Path, report: dict) -> None:
    """Check that the manifest repeats the outcome of each result."""
    manifest = read(corpus / "manifest.json")
    summaries = [
        {key: value for key, value in result.items() if key != "same_parent_noop"}
        for result in report["results"]
    ]
    need(
        manifest["twelve_tested_values_and_observations"] == summaries,
        "Manifest outcome summary differs",
    )


def outcomes(
    corpus: Path, plan: dict, report: dict, modules: tuple[types.ModuleType, ...]
) -> None:
    """Gate the case report, its results and the manifest that repeats them."""
    control, cases, _, _, _ = modules
    need(
        report["status"] == "completed"
        and report["error"] == EMPTY_TEXT
        and report["request_count"] == CASE_REQUESTS
        and report["mutation_count"] == MUTATION_COUNT
        and len(report["actions"]) == CASE_REQUESTS
        and len(report["frames"]) == CASE_FRAMES
        and len(report["events"]) == CASE_EVENTS
        and len(report["views"]) == CASE_VIEWS
        and len(report["results"]) == CASE_RESULTS
        and len(report["progress"]) == PROGRESS_ENTRIES
        and report["terminals"] == {"main": "eof"}
        and report["unparsed_hex"] == {"main": ""}
        and report["oracle_sha256"] == DATA,
        "Case count/status/tail differs",
    )
    control.verify_report(plan, report)
    need(
        report["own_uid"]
        == next(v["uid"] for v in report["views"] if v["label"] == "initial-roster")
        and report["current_case_index"] is None,
        "Dynamic UID/progress differs",
    )
    _results(cases, report["results"])
    _summary(corpus, report)
