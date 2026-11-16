#!/usr/bin/env python3
"""Replay the frozen two-session native roster overlap without a VM."""

import sys
from pathlib import Path

from script_cli import run
from verify_native_roster_overlap_common import (
    A7,
    BASE,
    DEADLINE,
    EXE,
    INODE,
    NS,
    ORACLE,
    PID,
    ROM,
    RSRC,
    SCHEMA,
    SOURCE_HEAD,
    START,
    frozen,
    need,
    read,
    sha,
)
from verify_native_roster_overlap_gates import identity, inventory, source_gate
from verify_native_roster_overlap_report import report_gate
from verify_native_roster_overlap_streams import streams
from verify_native_roster_overlap_terminal import terminal

# The names below stay importable from this module, as they were before the checks
# moved to verify_native_roster_overlap_common, _gates, _report, _streams and
# _terminal. test_native_roster_overlap_witness uses SCHEMA, CORPUS and verify.
__all__ = [
    "A7",
    "BASE",
    "CORPUS",
    "DEADLINE",
    "EXE",
    "INODE",
    "NS",
    "ORACLE",
    "PID",
    "ROM",
    "RSRC",
    "SCHEMA",
    "SOURCE_HEAD",
    "START",
    "frozen",
    "identity",
    "inventory",
    "main",
    "need",
    "read",
    "report_gate",
    "sha",
    "source_gate",
    "streams",
    "terminal",
    "verify",
]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-roster-overlap-01"
)


def verify(corpus: Path = CORPUS) -> None:
    """Replay every gate of the native roster overlap corpus in ``corpus``.

    The gates run in a fixed order, and the first failing check raises.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory, which holds the manifest and the raw evidence.
    """
    manifest = inventory(corpus)
    modules = frozen(corpus)
    source_gate(corpus, manifest, modules)
    identity(corpus)
    result = report_gate(corpus, modules)
    streams(corpus, modules, result)
    terminal(corpus)


def _replay(*, corpus: str = str(CORPUS)) -> None:
    """Replay the corpus named by ``--corpus`` and report that the replay passed.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    verify(Path(corpus))
    sys.stdout.write("native roster overlap: offline replay PASS\n")


def main() -> None:
    """Replay the native roster overlap corpus from the command line."""
    run(_replay, __doc__)


if __name__ == "__main__":
    main()
