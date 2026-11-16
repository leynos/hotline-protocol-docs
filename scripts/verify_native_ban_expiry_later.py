#!/usr/bin/env python3
"""Replay the stopped lab's later temporary-ban epoch without a VM."""

import json
import sys
from pathlib import Path

from script_cli import run
from verify_native_ban_expiry_first_common import need, read, sha, when
from verify_native_ban_expiry_later_capture import (
    clock_gate,
    generic_post,
    post_receipt_gate,
    pre_gate,
    unit_gate,
)
from verify_native_ban_expiry_later_inventory import (
    frozen,
    inventory,
    source_gate,
)
from verify_native_ban_expiry_later_packets import packet_gate
from verify_native_ban_expiry_later_reports import reports_gate
from verify_native_ban_expiry_later_stopped import stopped_gate
from verify_native_ban_expiry_later_wire import (
    BASE,
    DEADLINE,
    HOST_PCAP_HEADER,
    INODE,
    NS,
    PID,
    ROM,
    SCHEMA,
    START,
    WORKING,
)

ROOT = Path(__file__).resolve().parents[1] / "evidence/gap-remediation/2026-11-14"
CORPUS = ROOT / SCHEMA
FIRST = ROOT / "native-ban-expiry-first-01"

# The names below are kept importable from this module, because the later
# verifier's test imports CORPUS, FIRST and verify, and the original module
# defined the others, which code may still reach through it.
__all__ = [
    "BASE",
    "CORPUS",
    "DEADLINE",
    "FIRST",
    "HOST_PCAP_HEADER",
    "INODE",
    "NS",
    "PID",
    "ROM",
    "ROOT",
    "SCHEMA",
    "START",
    "WORKING",
    "clock_gate",
    "frozen",
    "generic_post",
    "inventory",
    "need",
    "packet_gate",
    "post_receipt_gate",
    "pre_gate",
    "read",
    "reports_gate",
    "sha",
    "show",
    "source_gate",
    "stopped_gate",
    "unit_gate",
    "verify",
    "when",
]


def verify(corpus: Path = CORPUS, first: Path = FIRST) -> dict:
    """Verify the later temporary-ban epoch and summarise what it proves.

    Parameters
    ----------
    corpus : Path
        The later-epoch corpus directory.
    first : Path
        The first-epoch corpus directory, which the later epoch extends.

    Returns
    -------
    dict
        The status, the flow and cleanup results, and the stopped-image receipt.
    """
    manifest = inventory(corpus, first)
    source_gate(corpus, manifest)
    raw = corpus / "raw"
    clock_gate(raw)
    pre_gate(raw)
    modules = frozen(corpus)
    receipt = post_receipt_gate(raw)
    reports = reports_gate(corpus, first, receipt, modules)
    flows = packet_gate(corpus, first, reports, modules[4])
    stopped = stopped_gate(corpus, first, manifest)
    return {
        "status": "verified_later_epoch_only",
        "pre_window": "missed_no_probe",
        "post_host_elapsed_seconds": read(raw / "post/results/summary.json")[
            "timing_gate"
        ]["host_elapsed_seconds"],
        "later_flows": flows,
        "cleanup": "owned_delete_and_control_postflight_passed",
        "stopped": stopped,
        "exact_1800_boundary_proven": False,
    }


def show(corpus: str = str(CORPUS), *, first: str = str(FIRST)) -> None:
    """Print the JSON summary of the later-epoch verification of ``corpus``.

    Parameters
    ----------
    corpus : str
        The later-epoch corpus directory.
    first : str
        The first-epoch corpus directory.
    """
    text = json.dumps(verify(Path(corpus), Path(first)), indent=2)
    sys.stdout.write(text + "\n")


def main() -> None:
    """Verify the later temporary-ban epoch from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
