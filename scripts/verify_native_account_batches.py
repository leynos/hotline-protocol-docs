#!/usr/bin/env python3
"""Verify sequential batch outcomes, credential collisions and native storage."""

import copy
import dataclasses as dc
import json
import typing as typ
from pathlib import Path

import native_account_batch_model as model
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
)
from script_cli import run
from verify_native_account_batch_catalogue import catalogue
from verify_native_account_batch_checks import (
    ERRORS,
    SAVE_ERROR,
    batch_result,
    inspect,
)
from verify_native_account_batch_oracle import check_oracle_queries
from verify_native_account_batch_replay import (
    Corpus,
    check_report_inventory,
    open_corpus,
    read_captures,
    replay,
)
from verify_native_account_updates import enumeration
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Plan = tuple[list[Report], Report]

# The batch checks live in verify_native_account_batch_checks, the catalogue
# checks in verify_native_account_batch_catalogue and the oracle checks in
# verify_native_account_batch_oracle; the names below stay importable from this
# module. batch_result, catalogue and verify are imported by
# test_native_account_batches; ERRORS, SAVE_ERROR and inspect are kept because
# the original module defined them publicly.
__all__ = [
    "ERRORS",
    "SAVE_ERROR",
    "batch_result",
    "catalogue",
    "inspect",
    "main",
    "verify",
]

FILES_BASELINE = 41
CLEANUP_INVENTORY = 29
BASELINE_ACCOUNTS = 2
REPORT_COUNT = 70
CONNECTION_COUNT = 75
ORIGINAL_TRASHED = 64
MAIN_CASES = 18
SEEDED = 14  # the actors and targets that the seed creates
FIRST_ID = 100  # the reads of the owned accounts are numbered from here
SEED_FIRST_ID = 200
LIVENESS_ID = 90
LISTING_ID = 11
LISTING_AFTER_ID = 91
LOGIN_REPORTS = [
    "nul-password-login",
    "distinct-login-source",
    "distinct-login-destination-source",
    "distinct-login-destination-old",
]
LOGIN_FRAMES = [(0, 0), (354, 0), (109, 0), (0, 0)]  # type and error of each frame
DISTINCT_STATES = {
    "clash2-old": (
        b"Distinct28-clash2-old",
        b"source-pass28",
        bytes(8),
        b"distinct28",
    ),
    "clash2-new": (
        b"Distinct28-clash2-new",
        b"target-pass28",
        bytes(8),
        b"distinct28",
    ),
}
SCOPE = (
    "Owned 349 framing/default/permission/mixed-outcome fixtures; rename "
    "collision overwrites destination and continues, without rollback. No "
    "protected/self-delete, arbitrary I/O, all-exception translation or "
    "historical-client claim."
)


@dc.dataclass(slots=True)
class Matrix:
    """The expected account states as the batches are replayed in order."""

    states: dict[str, model.State]
    baseline: list[str]
    snapshots: dict[str, dict[str, model.State]]


def check_main_matrix(reports: dict[str, Report], corpus: Corpus) -> Matrix:
    """Replay the main batch matrix against the model, case by case.

    Returns
    -------
    Matrix
        The states after the last case, the baseline and the first snapshots.
    """
    baseline = enumeration(reply(reports["preflight"], 10))
    require(
        len(baseline) == BASELINE_ACCOUNTS, "Batch original account baseline differs"
    )
    for identifier, label in enumerate(model.OWNED, FIRST_ID):
        model.account_reply(reply(reports["preflight"], identifier), label, {})
    states = model.seed_states()
    snapshots = {"native-seed": copy.deepcopy(states)}
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Batch owned seed failed",
    )
    for identifier, label in enumerate(model.OWNED[:SEEDED], SEED_FIRST_ID):
        model.account_reply(reply(reports["seed"], identifier), label, states)
    for spec in corpus.specifications:
        label = spec["case"]
        inspect(reports["before-" + label], spec["names"], states, baseline)
        batch_result(reports["batch-" + label], spec)
        model.apply(states, model.effects()[label])
        inspect(reports["after-" + label], spec["names"], states, baseline)
    snapshots["native-final"] = copy.deepcopy(states)
    for identifier, label in enumerate(model.OWNED, FIRST_ID):
        model.account_reply(reply(reports["final"], identifier), label, states)
    require(
        enumeration(reply(reports["final"], LIVENESS_ID))
        == model.enumeration(states, baseline),
        "Main batch final enumeration differs",
    )
    return Matrix(states, baseline, snapshots)


def check_distinct(reports: dict[str, Report], corpus: Corpus, matrix: Matrix) -> None:
    """Replay the distinct-password collision against the model."""
    states, baseline = matrix.states, matrix.baseline
    inspect(reports["distinct-preflight"], model.EXTRA, states, baseline)
    inspect(
        reports["distinct-before"],
        model.EXTRA,
        {**states, **DISTINCT_STATES},
        baseline,
    )
    for identifier, label in enumerate(model.EXTRA, FIRST_ID):
        model.account_reply(reply(reports["distinct-seed"], identifier), label, states)
    model.distinct_seed(states)
    matrix.snapshots["native-distinct-seed"] = copy.deepcopy(states)
    batch_result(reports["distinct-batch"], corpus.distinct)
    model.distinct_effects(states)
    inspect(reports["distinct-after"], model.EXTRA, states, baseline)
    matrix.snapshots["native-distinct-final"] = copy.deepcopy(states)
    for identifier, label in enumerate(model.OWNED + model.EXTRA, FIRST_ID):
        model.account_reply(reply(reports["distinct-final"], identifier), label, states)
    require(
        enumeration(reply(reports["distinct-final"], LIVENESS_ID))
        == model.enumeration(states, baseline),
        "Distinct collision final enumeration differs",
    )


def check_logins(reports: dict[str, Report]) -> None:
    """Check the credential logins that follow the collisions."""
    for key in LOGIN_REPORTS:
        report = reports[key]
        if key.endswith("-destination-old"):
            require(
                len(report["frames"]) == 1
                and reply(report, 1)["error"] == 1
                and fields(reply(report, 1)) == {FIELD_ERROR_TEXT: b"Incorrect login."},
                "Collision destination retained old password",
            )
        else:
            require(
                [(f["type"], f["error"]) for f in report["frames"]] == LOGIN_FRAMES
                and fields(report["frames"][1]) == {FIELD_ACCESS_BITMAP: bytes(8)},
                "NUL/source collision credential login differs",
            )


def check_cleanup(reports: dict[str, Report], corpus: Corpus, matrix: Matrix) -> None:
    """Check the owned inventory, and that cleanup restored accounts and files."""
    require(
        corpus.inventory
        == [name for name in model.OWNED + model.EXTRA if name in matrix.states]
        and len(corpus.inventory) == CLEANUP_INVENTORY,
        "Observed batch cleanup inventory differs",
    )
    files = listing(reply(reports["preflight"], LISTING_ID))
    require(len(files) == FILES_BASELINE, "Batch Files baseline differs")
    for key in ["cleanup", "publish", "remove-publisher"]:
        report = reports[key]
        require(
            all(f["error"] == 0 for f in report["frames"])
            and enumeration(reply(report, LIVENESS_ID)) == matrix.baseline,
            "Batch cleanup account baseline differs",
        )
        after = listing(reply(report, LISTING_AFTER_ID))
        if key == "publish":
            require(b"m-b28-publish" in after, "Batch publisher missing")
            after.pop(b"m-b28-publish")
        require(after == files, "Batch cleanup Files baseline differs")


def verify(directory: Path) -> Report:
    """Verify the retained account-batch corpus.

    Returns
    -------
    dict[str, typing.Any]
        The counts of what was verified and the scope of the claim.
    """
    corpus = open_corpus(directory)
    check_report_inventory(corpus)
    packets = read_captures(directory)
    reports, connections = replay(corpus, packets)
    matrix = check_main_matrix(reports, corpus)
    check_distinct(reports, corpus, matrix)
    check_logins(reports)
    check_cleanup(reports, corpus, matrix)
    catalogue(directory, matrix.snapshots)
    check_oracle_queries(directory)
    manifest = corpus.manifest
    require(
        len(reports) == manifest["completed_reports"] == REPORT_COUNT
        and connections == manifest["paired_connections"] == CONNECTION_COUNT,
        "Batch aggregate counts differ",
    )
    return {
        "completed_reports": REPORT_COUNT,
        "paired_connections": connections,
        "main_batch_cases": MAIN_CASES,
        "distinct_password_collision": 1,
        "terminal_batch_successes": 8,
        "terminal_batch_errors": 11,
        "owned_accounts_present_before_cleanup": CLEANUP_INVENTORY,
        "original_objects_in_trash": ORIGINAL_TRASHED,
        "oracle_queries": 12,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native account-batch corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
