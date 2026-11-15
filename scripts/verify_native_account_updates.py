#!/usr/bin/env python3
"""Verify account replacement, password sentinels and native record bytes."""

import json
import typing as typ
from pathlib import Path

import native_account_update_cases as cases
from native_wire_names import ACCOUNT_RECORD_BYTES
from script_cli import run
from verify_native_account_update_checks import (
    ACCESS,
    BASE_PASSWORD,
    LABELS,
    PASSWORDS,
    account_record,
    account_reply,
    enumeration,
    storage,
    username,
    values,
)
from verify_native_account_update_outcomes import (
    COMPLETED_REPORTS,
    check_labels,
    check_outcomes,
    check_restoration,
    check_totals,
)
from verify_native_account_update_runs import (
    ORACLE_QUERIES,
    check_cases,
    check_chronology,
    check_identity,
    check_inventory,
    check_oracle,
    expected_plans,
    open_corpus,
)

type Report = dict[str, typ.Any]

# test_native_account_updates imports account_reply, storage and verify. The
# evidence-held verifiers and the native_*_cases and verify_native_* scripts
# import enumeration. The planner's names remain reachable through cases, as
# prepare_native_cases and the evidence-held run scripts use them.
__all__ = [
    "ACCESS",
    "BASE_PASSWORD",
    "LABELS",
    "PASSWORDS",
    "account_record",
    "account_reply",
    "cases",
    "enumeration",
    "main",
    "show",
    "storage",
    "username",
    "values",
    "verify",
]


def verify(directory: Path) -> Report:
    """Verify an account-update corpus and summarise what it establishes.

    Returns
    -------
    dict[str, typing.Any]
        The counts of the corpus and the scope that it does not establish.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    check_identity(runtime)
    expected = expected_plans()
    check_inventory(directory, manifest, expected)
    corpus = open_corpus(directory, manifest, runtime)
    reports, connections = check_cases(corpus, expected)
    check_chronology(reports, list(expected))
    check_labels(reports)
    check_outcomes(reports)
    check_restoration(reports)
    storage(directory)
    check_oracle(directory)
    check_totals(reports, manifest, connections)
    return {
        "completed_reports": COMPLETED_REPORTS,
        "paired_connections": connections,
        "owned_accounts": 8,
        "positive_logins": 9,
        "negative_logins": 8,
        "native_record_bytes": ACCOUNT_RECORD_BYTES,
        "positive_original_trash_objects": 18,
        "oracle_queries": ORACLE_QUERIES,
        "scope": (
            "Sentinel/replacement/default/width fixtures only; opaque111 meaning, "
            "live-edit propagation, conflicts/protected deletion, forced write "
            "failures and restart persistence remain open"
        ),
    }


def show(directory: str) -> None:
    """Print the verification of the account-update corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify an account-update corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
