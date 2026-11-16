#!/usr/bin/env python3
"""Replay the frozen Hotline 1.9 board fixture without a VM or live server."""

import json
from pathlib import Path

from script_cli import run
from verify_native_board_checks import Report, inventory, need, read, sha, utc
from verify_native_board_identity import identity
from verify_native_board_packets import packets
from verify_native_board_pins import (
    BASE,
    BOARD,
    BOARD_BYTES,
    CASES,
    DATA,
    DEADLINE,
    EXE,
    FORKS,
    INODE,
    NS,
    PID,
    PLAN,
    PORTS,
    ROM,
    RSRC,
    RUNNER,
    SCHEMA,
    START,
)
from verify_native_board_reports import reports
from verify_native_board_source import frozen, source_and_plan
from verify_native_board_terminal import terminal

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-board-01"
)

# The checks live in the verify_native_board_* modules and the recorded identities
# in verify_native_board_pins; the names below stay importable from this module.
# CORPUS and verify are imported by scripts/tests/test_native_board_corpus.py; the
# others are kept because the original module defined them publicly.
__all__ = [
    "BASE",
    "BOARD",
    "CASES",
    "CORPUS",
    "DATA",
    "DEADLINE",
    "EXE",
    "FORKS",
    "INODE",
    "NS",
    "PID",
    "PLAN",
    "PORTS",
    "ROM",
    "RSRC",
    "RUNNER",
    "SCHEMA",
    "START",
    "frozen",
    "identity",
    "inventory",
    "main",
    "need",
    "packets",
    "read",
    "reports",
    "sha",
    "show",
    "source_and_plan",
    "terminal",
    "utc",
    "verify",
]


def verify(corpus: Path = CORPUS) -> Report:
    """Verify the retained board corpus and summarise its evidence.

    Returns
    -------
    dict[str, typing.Any]
        The status, the corpus, the board's digest and size, the flows and the
        baseline that the corpus does not exercise.
    """
    inventory(corpus)
    with frozen(corpus) as modules:
        plan = source_and_plan(corpus, modules)
        identity(corpus)
        report = reports(corpus, modules, plan)
        flows = packets(corpus, modules, report)
        terminal(corpus, report)
    return {
        "status": "PASS",
        "corpus": str(corpus),
        "board_sha256": BOARD,
        "board_bytes": BOARD_BYTES,
        "flows": flows,
        "full_file_baseline": "not_exercised",
    }


def show(*, corpus: str = str(CORPUS)) -> None:
    """Print the verification of the corpus at ``corpus`` as JSON.

    Parameters
    ----------
    corpus : str
        The corpus directory to verify.
    """
    print(json.dumps(verify(Path(corpus)), indent=2, sort_keys=True))


def main() -> None:
    """Verify a retained board corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
