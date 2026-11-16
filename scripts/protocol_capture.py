#!/usr/bin/env python3
"""Record planned TCP exchanges without treating tool tests as native evidence.

``capture`` records a plan against a peer; ``verify`` checks a retained capture
directory. The work is split across the modules of ``CAPTURE_MODULES``, and this
module keeps their public names and the two constants that tests patch.

A report records which scripts made it (decision D31): ``driver_sha256`` is the
digest of the whole module set, and ``driver_identity`` holds the commit, the
hash of each module and whether any differed from the commit. See
``capture_identity``. A report captured before that decision holds the hash of
this one file in ``driver_sha256`` and has no ``driver_identity``; its verifiers
keep their comparison for it.

This module runs under a bare ``python3``: a recipe verifies retained captures
with ``python3 scripts/protocol_capture.py verify``, so the command line stays
on ``argparse``.
"""

import argparse
import json
import typing as typ
from pathlib import Path

import capture_identity

# Re-exported for the verifiers, controls and tests that import these names from
# protocol_capture, as the module was one file before it was split.
from protocol_capture_decode import decode_frame
from protocol_capture_plan import VARIABLE, field_saves, validate
from protocol_capture_recorder import RecorderBase
from protocol_capture_report import (
    Outcome,
    build_report,
    check_frames,
    check_inventory,
    check_report,
    digest,
    write_directory,
)

# The scripts that make a capture, in the fixed order of its identity digest: this
# file, then the modules split out of it. A test requires the list to be exact.
CAPTURE_MODULES = (
    "protocol_capture.py",
    "protocol_capture_decode.py",
    "protocol_capture_plan.py",
    "protocol_capture_recorder.py",
    "protocol_capture_report.py",
)

ORACLE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024

__all__ = [
    "CAPTURE_MODULES",
    "MAX_CAPTURE_BYTES",
    "ORACLE_SHA256",
    "VARIABLE",
    "Recorder",
    "decode_frame",
    "digest",
    "field_saves",
    "main",
    "run_plan",
    "validate_plan",
    "verify_capture",
]


def validate_plan(plan: dict) -> None:
    """Reject invalid actions and unresolved connections before opening sockets.

    The oracle hash and the capture limit are read here, from this module, so
    that patching either on ``protocol_capture`` takes effect.

    Parameters
    ----------
    plan : dict
        The plan.
    """
    validate(plan, oracle=ORACLE_SHA256, limit=MAX_CAPTURE_BYTES)


class Recorder(RecorderBase):
    """Retain every successful send/receive chunk and action-relative timing."""

    @property
    def limit(self) -> int:
        """The session limit, read from this module so that a patch applies.

        Returns
        -------
        int
            ``MAX_CAPTURE_BYTES``.
        """
        return MAX_CAPTURE_BYTES


def _run_steps(
    recorder: RecorderBase, plan: dict[str, typ.Any]
) -> tuple[str, str, int]:
    """Run every step, retaining a failed exchange as a failure.

    Every connection still open at the end is closed, and each close is an
    event, whether the run completed, failed or was interrupted.

    Parameters
    ----------
    recorder : RecorderBase
        The recorder that executes the steps.
    plan : dict[str, typing.Any]
        The validated plan.

    Returns
    -------
    tuple[str, str, int]
        The status (``"completed"`` or ``"failed"``), the error as
        ``"Type: message"`` or the empty string, and the steps finished.
    """
    status, error, completed = "completed", "", 0
    try:
        for index, step in enumerate(plan["steps"]):
            recorder.execute(index, step)
            completed += 1
    except (OSError, EOFError, ValueError, KeyboardInterrupt) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in recorder.sockets.items():
            connection.close()
            recorder.event(completed, name, "close")
    return status, error, completed


def run_plan(plan_path: Path, binary: Path, output: Path) -> dict:
    """Record a plan into a new directory; retain a failed exchange as failure.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan file.
    binary : pathlib.Path
        The oracle binary, whose hash the plan must name.
    output : pathlib.Path
        A directory that does not exist yet.

    Returns
    -------
    dict
        The report, which is also written to ``output``.

    Raises
    ------
    ValueError
        If the plan is invalid or the binary is not the plan's oracle.
    """
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    if digest(binary.read_bytes()) != plan["oracle_sha256"]:
        message = "Oracle binary hash mismatch"
        raise ValueError(message)
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, completed = _run_steps(recorder, plan)
    report = build_report(
        Outcome(plan, source, recorder, status, error, completed),
        capture_identity.identity(CAPTURE_MODULES),
    )
    write_directory(output, source, report)
    return report


def verify_capture(directory: Path) -> dict:
    """Check retained bytes and stream reconstruction, without certifying a peer.

    Parameters
    ----------
    directory : pathlib.Path
        A capture directory.

    Returns
    -------
    dict
        The report.
    """
    check_inventory(directory)
    plan_bytes = (directory / "plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    validate_plan(plan)
    report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    check_report(report, plan, plan_bytes)
    check_frames(plan, report)
    return report


def main() -> None:
    """Capture a planned exchange or verify an existing transcript.

    Raises
    ------
    SystemExit
        With status 1 when the capture did not complete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("plan", type=Path)
    capture.add_argument("--oracle-binary", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        report = run_plan(args.plan, args.oracle_binary, args.output)
    else:
        report = verify_capture(args.directory)
    line = f"{report['profile']}: {report['status']}; "
    print(f"{line}{report['completed_actions']} actions")
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
