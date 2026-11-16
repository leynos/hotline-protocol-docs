#!/usr/bin/env python3
"""Replay the A46 legacy and A48 planned-EOF control-only persistence corpus."""

import json
import sys
from pathlib import Path

from native_control_readiness import readiness
from protocol_capture import verify_capture
from script_cli import run
from verify_native_settings_persistence_core import (
    A46_SOURCES,
    A48_SOURCES,
    FORKS,
    Json,
    load_frozen,
    read_json,
    require,
)
from verify_native_settings_persistence_lifecycle import lifecycle
from verify_native_settings_persistence_packets import paired_packets
from verify_native_settings_persistence_reports import legacy_report, planned_report
from verify_native_settings_persistence_sources import inventory, source_identity
from verify_native_settings_persistence_storage import stopped_storage

# The constants and readers live in verify_native_settings_persistence_core, the
# inventory and source checks in _sources, the phase replays in _reports, the packet
# pairing in _packets, the stopped storage in _storage and the lifecycle in
# _lifecycle. The names that this module defined before they moved stay importable
# from here; tests/test_pinned_comparisons.py calls ``source_identity``.
__all__ = [
    "A46_SOURCES",
    "A48_SOURCES",
    "FORKS",
    "controls",
    "inventory",
    "legacy_report",
    "lifecycle",
    "load_frozen",
    "login_vectors",
    "main",
    "paired_packets",
    "planned_report",
    "read_json",
    "require",
    "source_identity",
    "stopped_storage",
    "verify",
]

FIXED_LOGIN_PREFIX = "0000006b"  # a 107 request
FIXED_LOGINS = 2  # one for the main connection and one for the subject
OPERATIONAL_DEVIATION = (
    "A48 oracle.lock was not held; exclusive lease and zero primary SYN "
    "independently retained"
)
PERSISTENCE_SCOPE = (
    "same-image operator-observed orderly shutdown and fresh-login control; "
    "no power-loss or all-storage claim"
)


def controls(corpus: Path) -> None:
    """Replay the readiness capture of each phase and check its plan.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    for phase in (1, 2):
        directory = corpus / f"phase{phase}"
        report = verify_capture(directory / "readiness")
        readiness(report)
        plan = read_json(directory / "readiness/plan.json")
        require(
            plan == read_json(directory / "plans/readiness.json"),
            "Readiness as-run plan differs",
        )


def sent_logins(plan: Json) -> list[str]:
    """List the 107 requests that a plan sends.

    Returns
    -------
    list[str]
        The hex of each.
    """
    return [
        step["hex"]
        for step in plan["steps"]
        if step["op"] == "send" and step["hex"].startswith(FIXED_LOGIN_PREFIX)
    ]


def login_vectors(first: Json, second: Json) -> None:
    """Check that both phases send the same two fixed 107 logins.

    Parameters
    ----------
    first : dict[str, typing.Any]
        The first phase's plan.
    second : dict[str, typing.Any]
        The second phase's plan.
    """
    require(
        len(sent_logins(first)) == FIXED_LOGINS
        and sent_logins(first) == sent_logins(second),
        "Fixed login 107 vectors differ",
    )


def verify(corpus: Path) -> Json:
    """Replay the whole corpus offline.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The status, the gates of each phase and the storage and flow summaries.
    """
    inventory(corpus)
    source_identity(corpus)
    controls(corpus)
    first, _first_report, first_semantic = legacy_report(corpus)
    second, _second_report, second_semantic = planned_report(corpus)
    login_vectors(first, second)
    flows = {f"phase{phase}": paired_packets(corpus, phase) for phase in (1, 2)}
    storage = stopped_storage(corpus)
    lifecycle(corpus)
    return {
        "status": "verified_control_only",
        "legacy_phase1": "verified_original_64_plus_2_not_generic_capture",
        "planned_phase2": "generic_and_semantic_verified_28",
        "gates": {
            "phase1": first_semantic["gates"],
            "phase2": second_semantic["gates"],
        },
        "paired_flows": {name: len(value) for name, value in flows.items()},
        "stored": storage,
        "operational_deviation": OPERATIONAL_DEVIATION,
        "persistence_scope": PERSISTENCE_SCOPE,
    }


def show(corpus: str) -> None:
    """Print the JSON result of replaying a corpus.

    Parameters
    ----------
    corpus
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(show, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
