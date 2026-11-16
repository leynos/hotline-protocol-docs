#!/usr/bin/env python3
"""Replay the frozen first native temporary-ban epoch without guest access."""

import json
import sys
from pathlib import Path

from script_cli import run
from verify_native_ban_expiry_first_common import need, read, sha, when
from verify_native_ban_expiry_first_identity import identity_gate
from verify_native_ban_expiry_first_inventory import (
    failed_launch_gate,
    frozen_modules,
    inventory,
    raw_gate,
    source_gate,
)
from verify_native_ban_expiry_first_packets import clock_gate, packet_gate
from verify_native_ban_expiry_first_reports import generic_report, reports_gate
from verify_native_ban_expiry_first_wire import (
    A7,
    DEADLINE,
    EXE,
    FIRST,
    INODE,
    NS,
    ORACLE,
    PID,
    PROTECTED_UNREAD,
    SCHEMA,
    START,
)

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01"
)

# The names below are kept importable from this module, because the first
# verifier's test imports CORPUS, FIRST, frozen_modules and verify, and the
# original module defined the others, which code may still reach through it.
__all__ = [
    "A7",
    "CORPUS",
    "DEADLINE",
    "EXE",
    "FIRST",
    "INODE",
    "NS",
    "ORACLE",
    "PID",
    "PROTECTED_UNREAD",
    "SCHEMA",
    "START",
    "clock_gate",
    "failed_launch_gate",
    "frozen_modules",
    "generic_report",
    "identity_gate",
    "inventory",
    "need",
    "packet_gate",
    "raw_gate",
    "read",
    "reports_gate",
    "sha",
    "show",
    "source_gate",
    "verify",
    "when",
]


def verify(corpus: Path = CORPUS) -> dict:
    """Verify the first temporary-ban epoch and summarise what it proves.

    Parameters
    ----------
    corpus : Path
        The first-epoch corpus directory.

    Returns
    -------
    dict
        The status, the connection and packet counts, and the ban clock.
    """
    manifest = inventory(corpus)
    source_gate(corpus, manifest)
    raw = raw_gate(corpus)
    control, base, capture, tcp = frozen_modules(corpus)
    receipt = identity_gate(corpus, raw)
    failed_launch_gate(corpus, raw)
    reports = reports_gate(raw, receipt, (control, base, capture))
    packet = packet_gate(corpus, raw, reports, tcp)
    clock_gate(corpus, raw)
    return {
        "status": "verified_first_epoch_only",
        "full_file_baseline": "not_exercised",
        "cases": len(FIRST),
        **packet,
        "request_utc": read(raw / "results-first-c77/ban-clock.json")["request_utc"],
        "ack_utc": read(raw / "results-first-c77/ban-clock.json")["ack_utc"],
        "vm_retained_at_terminal": True,
        "expiry_proven": False,
    }


def show(corpus: str = str(CORPUS)) -> None:
    """Print the JSON summary of the first-epoch verification of ``corpus``.

    Parameters
    ----------
    corpus : str
        The first-epoch corpus directory.
    """
    text = json.dumps(verify(Path(corpus)), indent=2)
    sys.stdout.write(text + "\n")


def main() -> None:
    """Verify the first temporary-ban epoch from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
