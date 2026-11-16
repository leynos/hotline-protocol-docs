#!/usr/bin/env python3
"""Replay the control-only native Options-ban application witness offline."""

import json
import sys
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from script_cli import run
from verify_native_configured_ban_boot import boot_and_ui
from verify_native_configured_ban_case import case, timeline
from verify_native_configured_ban_constants import (
    ADMIN,
    BANNED,
    BANNED_BYTES,
    BASE,
    CAPTURE_WINDOW_SECONDS,
    CASES,
    CLIENT_PID,
    CONTROL_PORT,
    CONTROLLER,
    DATA,
    DISTINCT_NAMESPACES,
    EMPTY_PCAP_BYTES,
    EXE,
    FORBIDDEN_TYPES,
    GATE_ACTION,
    GUEST_PORT,
    LEASE_LOCK_INODE,
    LEASE_MAIN_PID,
    LOW,
    MAX_CORPUS_FILES,
    MAX_PCAP_BYTES,
    MAX_SAVE_RETURN_SECONDS,
    MAX_SOURCE_BYTES,
    MAX_TRIGGER_SECONDS,
    MIN_REMAINING_SECONDS,
    MIN_REQUEST_HEX_CHARS,
    NOTICE_ACTIONS,
    NS,
    ORIGINAL_USER_COUNT,
    OWNED_USER_DATA_BYTES,
    PHASES,
    PID,
    PREFS,
    PREFS_BYTES,
    PRIMARY_PID,
    PRIMARY_PORTS,
    ROM,
    RSRC,
    SAVE_ACTION,
    SCHEMA,
    SCOPED_CONNECTIONS,
    START,
    STOPPED,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
)
from verify_native_configured_ban_corpus import failed_c65, inventory, preboot
from verify_native_configured_ban_support import instant, need, read, sha
from verify_native_configured_ban_terminal import terminal
from verify_native_configured_ban_traffic import packets

# The names below stay importable from this module, for the tests and the evidence
# that name it. The checks live in verify_native_configured_ban_boot, _case, _corpus,
# _terminal, _traffic and _support, and the pinned values in _constants.
__all__ = [
    "ADMIN",
    "BANNED",
    "BANNED_BYTES",
    "BASE",
    "CAPTURE_WINDOW_SECONDS",
    "CASES",
    "CLIENT_PID",
    "CONTROLLER",
    "CONTROL_PORT",
    "DATA",
    "DISTINCT_NAMESPACES",
    "EMPTY_PCAP_BYTES",
    "EXE",
    "FORBIDDEN_TYPES",
    "GATE_ACTION",
    "GUEST_PORT",
    "LEASE_LOCK_INODE",
    "LEASE_MAIN_PID",
    "LOW",
    "MAX_CORPUS_FILES",
    "MAX_PCAP_BYTES",
    "MAX_SAVE_RETURN_SECONDS",
    "MAX_SOURCE_BYTES",
    "MAX_TRIGGER_SECONDS",
    "MIN_REMAINING_SECONDS",
    "MIN_REQUEST_HEX_CHARS",
    "NOTICE_ACTIONS",
    "NS",
    "ORIGINAL_USER_COUNT",
    "OWNED_USER_DATA_BYTES",
    "PHASES",
    "PID",
    "PREFS",
    "PREFS_BYTES",
    "PRIMARY_PID",
    "PRIMARY_PORTS",
    "ROM",
    "RSRC",
    "SAVE_ACTION",
    "SCHEMA",
    "SCOPED_CONNECTIONS",
    "START",
    "STOPPED",
    "TCP_FIN",
    "TCP_RST",
    "TCP_SYN",
    "boot_and_ui",
    "case",
    "decode_frame",
    "failed_c65",
    "instant",
    "inventory",
    "lifetime",
    "main",
    "need",
    "packets",
    "preboot",
    "read",
    "read_packets",
    "sha",
    "show",
    "stream",
    "terminal",
    "timeline",
    "verify",
    "verify_capture",
]


def verify(corpus: Path) -> dict:
    """Verify the retained configured-ban corpus in ``corpus``.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory: its manifest, its files and its case directories.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the scope of the evidence and the counts of the verified case.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    failed_c65(corpus)
    preboot(corpus)
    ready = boot_and_ui(corpus)
    reports = case(corpus, ready)
    timeline(corpus, reports)
    traffic = packets(corpus, reports)
    stored = terminal(corpus)
    return {
        "status": "verified_control_only_connected_configured_ban_notice",
        "full_file_baseline": "not_exercised",
        "primary_syn": 0,
        "lab_retired": True,
        **traffic,
        **stored,
    }


def show(corpus: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``corpus``.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Verify a configured-ban corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
