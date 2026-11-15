#!/usr/bin/env python3
"""Verify native207 presence, permission and partial-effect observations."""

import json
from pathlib import Path

from native_metadata_cases import specs
from script_cli import run
from verify_native_core import require
from verify_native_metadata_checks import (
    comment_boundaries,
    expected_comment,
    info,
    mutation,
)
from verify_native_metadata_corpus import (
    BOUNDARY_WRITE_COUNT,
    COMBINED_EMPTY_CASE_COUNT,
    MUTATION_CASE_COUNT,
    ORACLE_QUERY_COUNT,
    REPORT_COUNT,
    Report,
    check_accounts,
    check_aggregates,
    check_baseline,
    check_combined,
    check_finals,
    check_inventory,
    check_merged_capture,
    check_oracle,
    check_plans,
    check_restored,
    expected_plans,
    read_recordings,
)

# test_native_metadata imports comment_boundaries, info, mutation and verify from
# this module. The other names are re-exported so that every public name of the
# original module still imports from here; main is the command-line entry point.
__all__ = [
    "comment_boundaries",
    "expected_comment",
    "info",
    "main",
    "mutation",
    "verify",
]

SCOPE = (
    "Native207 metadata effects and bounded silence; no all-or-nothing guarantee, "
    "restart durability, portable comment storage capacity or complete "
    "error/notification coverage"
)


def verify(directory: Path) -> Report:
    """Verify every capture and record of a retained native metadata corpus.

    Returns
    -------
    dict[str, typing.Any]
        The aggregate counts, the observation of each account-write case, and
        the scope that the corpus supports.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = expected_plans()
    check_inventory(directory, manifest, expected)
    check_merged_capture(directory)
    recordings = read_recordings(directory, manifest)
    reports, connections = check_plans(directory, expected, recordings)
    observed = [mutation(reports["mutations/" + s["case"]], s) for s in specs()]
    for label in ["file", "dir"]:
        comment_boundaries(reports["boundaries/" + label])
    baseline = check_baseline(reports)
    check_combined(directory, reports, baseline)
    check_accounts(reports)
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Native metadata seed failed",
    )
    check_finals(reports)
    check_restored(reports, baseline)
    check_aggregates(manifest, reports, connections)
    check_oracle(directory)
    return {
        "completed_reports": REPORT_COUNT,
        "paired_connections": connections,
        "mutation_cases": MUTATION_CASE_COUNT,
        "combined_empty_cases": COMBINED_EMPTY_CASE_COUNT,
        "boundary_writes": BOUNDARY_WRITE_COUNT,
        "oracle_queries": ORACLE_QUERY_COUNT,
        "observations": observed,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native metadata corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
