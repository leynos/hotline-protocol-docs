#!/usr/bin/env python3
"""Replay the frozen, failed Hotline 1.9 rate304 sequence offline."""

import json
import sys
import typing as typ
from pathlib import Path

from script_cli import run
from verify_native_rate304_sequence_capture import paired_packets, stopped_and_capture
from verify_native_rate304_sequence_constants import (
    BASE,
    CASES,
    DATA,
    DEADLINE,
    EXE,
    FORKS,
    INODE,
    MISSING_CLIENT,
    NS,
    PID,
    PLAN,
    PORTS,
    ROM,
    RUNNER,
    SCHEMA,
    START,
    TEMP_ERROR,
)
from verify_native_rate304_sequence_events import events_and_actions
from verify_native_rate304_sequence_identity import frozen, identity, source_identity
from verify_native_rate304_sequence_observed import observed_prefix
from verify_native_rate304_sequence_support import (
    inventory,
    need,
    pin,
    read,
    sha,
)

if typ.TYPE_CHECKING:
    from verify_native_rate304_sequence_support import Modules

# The default corpus: the evidence directory beside this script's repository.
CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-rate304-sequence-01"
)

# The names below stay importable from this module, as they were before the split.
# The checks live in the verify_native_rate304_sequence_* modules named above; the
# test module imports CORPUS and verify.
__all__ = [
    "BASE",
    "CASES",
    "CORPUS",
    "DATA",
    "DEADLINE",
    "EXE",
    "FORKS",
    "INODE",
    "MISSING_CLIENT",
    "NS",
    "PID",
    "PLAN",
    "PORTS",
    "ROM",
    "RUNNER",
    "SCHEMA",
    "START",
    "TEMP_ERROR",
    "events_and_actions",
    "frozen",
    "identity",
    "inventory",
    "main",
    "need",
    "observed_prefix",
    "paired_packets",
    "pin",
    "read",
    "sha",
    "source_identity",
    "stopped_and_capture",
    "verify",
]


def _check_readiness(raw: Path, modules: Modules) -> None:
    """Run the readiness check of the pre-capture on the frozen modules.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    modules : tuple[types.ModuleType, ...]
        The frozen modules yielded by the ``frozen`` context manager.
    """
    _, _, readiness, capture, _ = modules
    pre = capture.verify_capture(raw / "readiness")
    readiness.readiness(pre)


def verify(corpus: Path = CORPUS) -> dict[str, typ.Any]:
    """Verify the failed rate304 sequence corpus and return its summary.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory, as ``CORPUS`` names it by default.

    Returns
    -------
    dict[str, typing.Any]
        The status, the case status, the flow byte counts and the host timing.
    """
    inventory(corpus)
    identity(corpus)
    raw = corpus / "raw/epoch"
    with frozen(raw) as modules:
        plan = source_identity(corpus, modules)
        _check_readiness(raw, modules)
        report = read(raw / "coordinator/report.json")
        events_and_actions(report, plan, modules)
        timing = observed_prefix(report, plan, modules)
        flows = paired_packets(corpus, report, modules)
    stopped_and_capture(corpus)
    return {
        "status": "PASS",
        "case_status": "failed",
        "flows": flows,
        "host_timing_ns": timing,
    }


def show(*, corpus: str = str(CORPUS)) -> None:
    """Print the JSON summary of the verification of the corpus in ``corpus``.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2, sort_keys=True) + "\n")


def main() -> None:
    """Verify the rate304 sequence corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
