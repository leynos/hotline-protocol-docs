#!/usr/bin/env python3
"""Replay the C50 A7 and one focus event from a frozen, offline corpus."""

import json
import sys
import typing as typ
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from pinned_source import pinned_sha256
from protocol_capture import verify_capture
from script_cli import run
from verify_native_ui_focus_capture import (
    check_plans,
    check_recorders,
    check_report,
    data_connection,
    packet_views,
)
from verify_native_ui_focus_core import (
    APP_SHA,
    AS_PREPARED_SHA,
    BASE_SHA,
    DRIVER_SHA,
    EXE_SHA,
    OBSERVER_SHA,
    PLAN_SHA,
    PREFIX_SHA,
    ROM_SHA,
    inventory,
    load,
    require,
    sha,
)

# The names below are re-exported: scripts/test_native_ui_focus.py and
# tests/test_pinned_comparisons.py import this module by name, and the
# public names that the single-module verifier had stay importable from it.
__all__ = [
    "APP_SHA",
    "AS_PREPARED_SHA",
    "BASE_SHA",
    "DRIVER_SHA",
    "EXE_SHA",
    "OBSERVER_SHA",
    "PLAN_SHA",
    "PREFIX_SHA",
    "ROM_SHA",
    "gold_count",
    "inventory",
    "lifetime",
    "load",
    "main",
    "pinned_sha256",
    "png_rows",
    "read_packets",
    "require",
    "run",
    "sha",
    "show",
    "stream",
    "verify",
    "verify_capture",
]
from verify_native_ui_focus_event import (
    check_focus_images,
    check_focus_streams,
    check_timing,
)
from verify_native_ui_focus_png import gold_count, png_rows
from verify_native_ui_focus_runtime import (
    check_cleanup,
    check_emulator,
    check_observer,
    check_runtime,
    check_terminal,
)


def verify(corpus: Path) -> dict[str, typ.Any]:
    """Replay the frozen corpus and return the verdict it supports.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the A7 action count, the event count, the byte counts of
        the two captures and whether option two ran.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    boot, exp = corpus / "boot", corpus / "experiment"
    require(sha(exp / "a7-original-plan.json") == PLAN_SHA, "Original A7 plan differs")
    require(
        pinned_sha256("protocol_capture.py") == DRIVER_SHA, "A7 driver revision differs"
    )
    check_plans(exp)
    report = verify_capture(exp / "capture")
    streams = check_report(report)
    connection = data_connection(report)
    views = packet_views(boot, connection, streams)
    check_recorders(boot)
    result = check_focus_images(exp)
    check_focus_streams(result, views, connection[0])
    check_timing(result)
    check_observer(corpus, exp)
    terminal = check_terminal(exp, result, views)
    check_cleanup(exp, terminal)
    identity = check_emulator(boot, terminal)
    check_runtime(corpus, exp, identity)
    return {
        "status": "verified_failed_a7_and_negative_focus_event",
        "a7_actions": 21,
        "event_count": 1,
        "guest_bytes": views["guest"]["bytes"],
        "namespace_bytes": views["namespace"]["bytes"],
        "option_two_executed": False,
    }


def show(corpus: str) -> None:
    """Print the JSON summary of the replay of one corpus.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Replay the frozen focus corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
