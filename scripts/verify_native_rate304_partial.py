#!/usr/bin/env python3
"""Replay the failed native 304 first pair from a frozen, offline corpus."""

import sys
from pathlib import Path

from script_cli import run
from verify_native_rate304_partial_core import (
    CASES,
    DATA,
    FORKS,
    PLAN,
    PORTS,
    RUNNER,
    fields,
    need,
    read,
    sha,
)
from verify_native_rate304_partial_corpus import inventory, scoped_identity, sources
from verify_native_rate304_partial_numbered import numbered
from verify_native_rate304_partial_packets import packet_evidence
from verify_native_rate304_partial_stopped import stopped

# The names below stay importable from this module. The shared constants and
# helpers live in verify_native_rate304_partial_core, the corpus checks in
# verify_native_rate304_partial_corpus, the numbered report in
# verify_native_rate304_partial_numbered, the captures in
# verify_native_rate304_partial_packets and the stopped state in
# verify_native_rate304_partial_stopped. test_native_rate304_partial imports CORPUS
# and verify; the others are kept because the original module defined them publicly.
__all__ = [
    "CASES",
    "CORPUS",
    "DATA",
    "FORKS",
    "PLAN",
    "PORTS",
    "RUNNER",
    "fields",
    "inventory",
    "main",
    "need",
    "numbered",
    "packet_evidence",
    "read",
    "scoped_identity",
    "sha",
    "sources",
    "stopped",
    "verify",
]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-rate304-first-pair-01"
)


def verify(corpus: Path) -> None:
    """Run every check of the corpus in order, raising ValueError on a difference."""
    inventory(corpus)
    raw = corpus / "raw"
    sources(raw)
    scoped_identity(raw)
    report = read(raw / "coordinator/report.json")
    numbered(report)
    packet_evidence(raw, report)
    stopped(raw)


def verify_corpus(*, corpus: str | None = None) -> None:
    """Verify the retained corpus and print the verdict line.

    The default corpus is the one beside this script.
    """
    verify(CORPUS if corpus is None else Path(corpus))
    sys.stdout.write(
        "native rate304 first pair: failed case and three complete flows verified\n"
    )


def main() -> None:
    """Verify the corpus named on the command line."""
    run(verify_corpus, __doc__)


if __name__ == "__main__":
    main()
