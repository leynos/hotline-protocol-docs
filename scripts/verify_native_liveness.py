#!/usr/bin/env python3
"""Replay the frozen native preonline liveness witness without a guest."""

import sys
from pathlib import Path

from script_cli import run
from verify_native_liveness_checks import (
    frozen,
    inventory,
    need,
    read,
    sha,
    utc,
)
from verify_native_liveness_identity import identity
from verify_native_liveness_packets import packet_gate
from verify_native_liveness_pins import (
    A7,
    BASE,
    CASES,
    DATA,
    DEADLINE,
    EXE,
    EXPECTED_302,
    FLOWS,
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
from verify_native_liveness_report import report_gate
from verify_native_liveness_source import source_gate
from verify_native_liveness_terminal import terminal

# Consumers: test_native_liveness_corpus imports CORPUS, SCHEMA and verify; the
# evidence-held copies of this verifier use the rest by the same names.
__all__ = [
    "A7",
    "BASE",
    "CASES",
    "CORPUS",
    "DATA",
    "DEADLINE",
    "EXE",
    "EXPECTED_302",
    "FLOWS",
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
    "packet_gate",
    "read",
    "report_gate",
    "sha",
    "show",
    "source_gate",
    "terminal",
    "utc",
    "verify",
]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-liveness-01"
)


def verify(corpus: Path = CORPUS) -> None:
    """Replay every gate of the corpus in order, raising at the first refusal.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory to verify.
    """
    inventory(corpus)
    with frozen(corpus) as modules:
        plan = source_gate(corpus, modules)
        identity(corpus)
        report = report_gate(corpus, modules, plan)
        packet_gate(corpus, modules, report)
        terminal(corpus)


def show(*, corpus: str = str(CORPUS)) -> None:
    """Verify the corpus at ``corpus`` and print the verdict.

    Parameters
    ----------
    corpus : str
        The corpus directory to verify.
    """
    verify(Path(corpus))
    sys.stdout.write("native liveness: offline replay PASS\n")


def main() -> None:
    """Replay the retained liveness witness from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
