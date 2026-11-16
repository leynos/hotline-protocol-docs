#!/usr/bin/env python3
"""Check isolated native article deletion, paired packets and physical caches."""

import json
from pathlib import Path

import native_news_delete_cases as cases
from native_news_decode import articles, categories
from script_cli import run
from verify_native_article_deletion_captures import (
    check_captures,
    check_phases,
    read_capture_inputs,
)
from verify_native_article_deletion_catalogue import catalogue
from verify_native_article_deletion_checks import (
    body,
    deletion,
    error,
    graph,
    list_records,
    measured_wait,
    scalar_controls,
)
from verify_native_article_deletion_data import (
    BODY_ERROR,
    CASE_COUNT,
    CATEGORY_ERROR,
    COMPLETED_REPORT_COUNT,
    FAILED_REPORT_COUNT,
    ID_ERROR,
    ORACLE_QUERY_COUNT,
    PAIRED_CONNECTION_COUNT,
    POSITIVE_CATEGORY_COUNT,
    REPORT_COUNT,
    TITLES,
    TREES,
)
from verify_native_article_deletion_final import check_finalization, check_oracles
from verify_native_article_deletion_plans import expected_plans
from verify_native_article_deletion_seeds import check_seeds
from verify_native_core import require

# The names below are importable from this module as before. The tests import
# catalogue, deletion, graph, measured_wait, scalar_controls and verify.
# verify_native_news_boundary and verify_native_account_update_runs import
# measured_wait. articles and categories stay imported here, as before.
__all__ = [
    "BODY_ERROR",
    "CATEGORY_ERROR",
    "ID_ERROR",
    "TITLES",
    "TREES",
    "articles",
    "body",
    "catalogue",
    "categories",
    "deletion",
    "error",
    "graph",
    "list_records",
    "main",
    "measured_wait",
    "scalar_controls",
    "show",
    "verify",
]


def verify(directory: Path) -> dict:
    """Verify an article-deletion corpus and summarise what was checked.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict
        The counts that were verified, and the scope of the claim.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    inventory = json.loads((directory / "resume-inventory.json").read_text())
    specifications = cases.specs()
    scalar_controls(specifications)
    require(
        len(specifications) == CASE_COUNT and len(inventory) == CASE_COUNT,
        "Deletion case inventory differs",
    )
    expected = expected_plans(specifications, inventory)
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Deletion report inventory differs",
    )
    inputs = read_capture_inputs(directory, manifest)
    reports, connections = check_captures(inputs, expected)
    check_phases(reports, specifications)
    references = check_seeds(reports, specifications, inventory)
    check_finalization(directory, reports, references)
    check_oracles(directory)
    require(
        len(reports) == REPORT_COUNT
        and connections == manifest["paired_connections"] == PAIRED_CONNECTION_COUNT
        and manifest["completed_reports"] == COMPLETED_REPORT_COUNT
        and manifest["failed_reports"] == FAILED_REPORT_COUNT
        and manifest["host_kernel_drops"] == 0,
        "Deletion aggregate counts differ",
    )
    return {
        "reports": REPORT_COUNT,
        "completed": COMPLETED_REPORT_COUNT,
        "retained_failures": FAILED_REPORT_COUNT,
        "paired_connections": connections,
        "deletion_cases": CASE_COUNT,
        "positive_categories": POSITIVE_CATEGORY_COUNT,
        "oracle_queries": ORACLE_QUERY_COUNT,
        "scope": (
            "These native fixtures; no natural ban expiry, interrupted-storage "
            "atomicity, restart durability or historical-client claim"
        ),
    }


def show(directory: str) -> None:
    """Print the verification summary of the corpus in ``directory`` as JSON.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify an article-deletion corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
