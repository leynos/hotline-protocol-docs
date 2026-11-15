#!/usr/bin/env python3
"""Verify native alias observations against plans, paired TCP and positive forks."""

import json
import typing as typ
from pathlib import Path

from script_cli import run
from verify_native_alias_checks import (
    creation,
    download,
    listing_views,
    metadata,
    transfer_quiet,
)
from verify_native_alias_corpus import (
    COMPLETED_REPORTS,
    FAILED_REPORTS,
    Corpus,
    catalogue,
    check_inventory,
    check_recorder,
    check_reports,
    check_totals,
    expected_plans,
    read_captures,
)
from verify_native_alias_outcomes import (
    ORACLE_QUERIES,
    check_baseline,
    check_comments,
    check_oracle,
    check_repeat,
    check_resolutions,
    check_runtime,
    check_unattached,
)
from verify_native_shx import sha

type Report = dict[str, typ.Any]

# test_native_aliases imports creation, download, listing_views, metadata,
# transfer_quiet and verify from this module; main is the command line.
__all__ = [
    "creation",
    "download",
    "listing_views",
    "main",
    "metadata",
    "transfer_quiet",
    "verify",
]

COLLISION_CASE = "supplementary/collision-alias-download"
SCOPE = (
    "Native alias observations; no genuine deleted-target fixture, exhaustive "
    "filter/order policy, restart durability or mxd conformance proof"
)


def verify(directory: Path) -> Report:
    """Verify every capture and record of a retained native alias corpus.

    Returns
    -------
    dict[str, typing.Any]
        The aggregate counts, the catalogue observation and the scope.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = expected_plans()
    check_inventory(directory, manifest, expected)
    host, guest = read_captures(directory)
    check_recorder(manifest, host)
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = check_reports(
        Corpus(directory, manifest, expected, host, guest, sources)
    )
    check_totals(manifest, connections)
    download(reports[COLLISION_CASE], collision=True)
    transfer_quiet(
        reports[COLLISION_CASE],
        json.loads((directory / COLLISION_CASE / "plan.json").read_text()),
    )
    listing_views(reports)
    check_resolutions(reports)
    check_repeat(reports)
    check_unattached(reports)
    check_comments(reports)
    check_baseline(reports)
    check_runtime(directory)
    check_oracle(directory)
    return {
        "completed_reports": COMPLETED_REPORTS,
        "failed_reports": FAILED_REPORTS,
        "paired_connections": connections,
        "metadata_kinds": 11,
        "creation_successes": 13,
        "creation_failures": 6,
        "oracle_queries": ORACLE_QUERIES,
        "catalogue": catalogue(directory),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native alias corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
