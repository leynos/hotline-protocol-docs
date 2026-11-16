#!/usr/bin/env python3
"""Verify bounded native move/Trash effects without asserting untested failures."""

import json
import typing as typ
from pathlib import Path

from native_move_cases import (
    COMMENT,
    ROOT,
    cleanup,
    deletion_specs,
    deletions,
    finalization,
    move_specs,
    moves,
    preflight,
    seed,
)
from native_packet_evidence import reconcile
from native_wire_names import FIELD_ACCESS_BITMAP
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing
from verify_native_moves_captures import (
    check_inventory,
    expected_cases,
    read_corpus_packets,
    run_captures,
)
from verify_native_moves_catalogue import catalogue
from verify_native_moves_checks import ACCESS_BYTES, FAILED_MOVES, deletion, move
from verify_native_shx import fields, sha

# The names below stay importable from this module. The checks live in
# verify_native_moves_checks, the catalogue in verify_native_moves_catalogue and the
# capture loop in verify_native_moves_captures. catalogue, deletion, move and verify
# are imported by test_native_moves; the others are kept because the original module
# defined them publicly.
__all__ = [
    "ADMIN",
    "COMMENT",
    "FAILED_MOVES",
    "ORACLE_SHA256",
    "ROOT",
    "catalogue",
    "cleanup",
    "creation_quiet",
    "deletion",
    "deletion_specs",
    "deletions",
    "fields",
    "finalization",
    "listing",
    "main",
    "move",
    "move_specs",
    "moves",
    "preflight",
    "read_packets",
    "reconcile",
    "reply",
    "require",
    "seed",
    "sha",
    "show",
    "verify",
    "verify_capture",
]

type Report = dict[str, typ.Any]

# The runtime check of the emulator that ran the corpus.
EMULATOR_PID = 881007
EMULATOR_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
# The Files names before the move cases; none of them may be an owned name.
PREFLIGHT_NAMES = 41
COMPLETED_REPORTS = 39
PAIRED_CONNECTIONS = 75
ORACLE_QUERIES = 11
MOVE_SUCCESSES = 12
MOVE_ERRORS = 14
DELETE_SUCCESSES = 6
DELETE_ERRORS = 3


def _check_runtime(runtime: Report) -> None:
    """Check that the runtime check names the emulator that ran the corpus.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The parsed ``runtime-check.json``.
    """
    require(
        runtime["emulator_pid"] == EMULATOR_PID
        and runtime["running_executable_sha256"] == EMULATOR_SHA256,
        "Move runtime identity differs",
    )


def _check_auxiliary(reports: dict[str, Report]) -> None:
    """Check the preflight names, the low account and the auxiliary operations.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each case.
    """
    initial = listing(reply(reports["preflight"], 10))
    require(
        len(initial) == PREFLIGHT_NAMES
        and ROOT not in initial
        and not any(n.startswith(b"m-mv22-") for n in initial),
        "Move preflight names were not absent",
    )
    require(
        fields(reply(reports["preflight"], 20))[FIELD_ACCESS_BITMAP]
        == bytes(ACCESS_BYTES),
        "Low-account preflight bitmap differs",
    )
    require(
        all(
            f["error"] == 0
            for r in [reports["seed"], reports["final"], reports["cleanup"]]
            for f in r["frames"]
        ),
        "Move auxiliary operation failed",
    )
    require(
        listing(reply(reports["cleanup"], 90)) == initial,
        "Owned move cleanup did not restore Files wire listing",
    )


def _check_aggregates(
    manifest: Report, reports: dict[str, Report], connections: int
) -> None:
    """Check the completed report and paired connection counts of the manifest.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each case.
    connections : int
        The number of paired connections counted from the reports.
    """
    require(
        manifest["completed_reports"] == len(reports) == COMPLETED_REPORTS
        and manifest["paired_connections"] == connections == PAIRED_CONNECTIONS,
        "Move aggregate counts differ",
    )


def _check_oracle_queries(directory: Path) -> None:
    """Check the oracle queries of the move corpus: their inventory and their code.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    """
    queries = list((directory / "oracle-queries").glob("*.json"))
    addresses = {
        "100177d0",
        "1002c130",
        "100140e0",
        "1002ba20",
        "1002bf70",
        "10080140",
        "1002b0e0",
        "1002c630",
        "1002e120",
        "1007f230",
        "10008ab0",
    }
    require(
        len(queries) == ORACLE_QUERIES
        and {p.stem.removeprefix("MV-D-") for p in queries} == addresses,
        "Move oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Move oracle identity/code differs",
        )


def verify(directory: Path) -> dict[str, typ.Any]:
    """Verify the native move and Trash corpus in ``directory``.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory: the manifest, the runtime check, the packet captures
        and one directory per case.

    Returns
    -------
    dict[str, typing.Any]
        The counts, the outcome of each move and deletion, the catalogue result and
        the scope that the corpus does not prove.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    _check_runtime(json.loads((directory / "runtime-check.json").read_text()))
    expected = expected_cases()
    check_inventory(directory, manifest, expected)
    packets = read_corpus_packets(directory, manifest)
    reports, connections = run_captures(directory, expected, packets)
    observed_moves = [move(reports["moves/" + s["case"]], s) for s in move_specs()]
    observed_deletes = [
        deletion(reports["deletions/" + s["case"]], s) for s in deletion_specs()
    ]
    _check_auxiliary(reports)
    _check_aggregates(manifest, reports, connections)
    _check_oracle_queries(directory)
    return {
        "completed_reports": COMPLETED_REPORTS,
        "paired_connections": connections,
        "move_successes": MOVE_SUCCESSES,
        "move_errors": MOVE_ERRORS,
        "delete_successes": DELETE_SUCCESSES,
        "delete_errors": DELETE_ERRORS,
        "moves": observed_moves,
        "deletions": observed_deletes,
        "catalogue": catalogue(directory),
        "scope": "Same-volume OS9 fixtures; cross-volume, locked/protected targets, "
        "interrupted I/O, root deletion, every refresh and restart durability remain "
        "unproven. Trash-target alias remains live, not a missing-target fixture.",
    }


def show(directory: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``directory``.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native move and Trash corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
