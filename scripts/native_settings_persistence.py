#!/usr/bin/env python3
"""Gate a control-only settings phase while sockets remain live for app Quit.

The gates live in ``native_settings_persistence_gates`` and
``native_settings_persistence_phase``, and every name they define stays importable
from here. A phase is run only after a separate root START. The scripts that make
a capture are the modules of ``CAPTURE_MODULES``: the planner records the path and
hash of each (decision D31) beside the plans, the runner checks that the live files
are the recorded ones, and the report records the commit and the digest of the set
in ``driver_sha256``, with the record in ``driver_identity``. A report made before
that decision holds the hash of this one file in ``driver_sha256``.

Command line::

    native_settings_persistence.py --run --plan F --readiness-dir D
        --capture-receipt F --binary F --output D
"""

import json
import os
import sys
import time
import typing as typ
from pathlib import Path

import capture_identity
from native_control_readiness import capture_gate
from native_settings_persistence_gates import (
    frame_at,
    gate_identity,
    gate_readiness,
    gate_update,
    verify_plan,
)
from native_settings_persistence_phase import gate_pm, phase_gate, semantic
from native_settings_persistence_run import (
    LIMIT_SECONDS,
    NANOSECONDS,
    Capture,
    Progress,
    hold,
    quit_steps,
    report_of,
    write_files,
)
from protocol_capture import ORACLE_SHA256, Recorder, digest, verify_capture
from script_cli import UsageError
from script_cli import run as run_command
from verify_native_core import require

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_settings_persistence.py",
    "native_settings_persistence_cases.py",
    "native_settings_persistence_gates.py",
    "native_settings_persistence_phase.py",
    "native_settings_persistence_run.py",
)

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

STEP_FAILURES = (
    OSError,
    EOFError,
    ValueError,
    KeyError,
    IndexError,
    TimeoutError,
    KeyboardInterrupt,
)
IDENTITY_FILE = "source-code-identity.json"

__all__ = [
    "CAPTURE_MODULES",
    "LIMIT_SECONDS",
    "capture_gate",
    "frame_at",
    "gate_identity",
    "gate_pm",
    "gate_readiness",
    "gate_update",
    "main",
    "phase_gate",
    "run_gated",
    "semantic",
    "verify_plan",
]


def _check_sources(plan_path: Path, raw: bytes, phase: int) -> None:
    """Check the plan against its recorded digest and the live scripts against theirs.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan; its directory holds the planner's records.
    raw : bytes
        The plan file's bytes.
    phase : int
        The phase number.
    """
    plan_hashes = json.loads((plan_path.parent / "source-hashes.json").read_text())
    require(plan_hashes[f"phase{phase}"] == digest(raw), "Plan source hash differs")
    files = json.loads((plan_path.parent / IDENTITY_FILE).read_text())["files"]
    recorded = {"files": files, "digest": capture_identity.set_digest(files)}
    first = next(iter(capture_identity.differences(recorded, CAPTURE_MODULES)), None)
    require(first is None, f"Source code differs: {first}")


def _check_readiness(readiness_dir: Path, plan: Plan) -> None:
    """Check the readiness capture and that it ran against the same emulator.

    Parameters
    ----------
    readiness_dir : pathlib.Path
        The readiness capture directory.
    plan : dict[str, typing.Any]
        The phase's plan.
    """
    ready_plan = json.loads((readiness_dir / "plan.json").read_text())
    ready_report = verify_capture(readiness_dir)
    gate_readiness(ready_report, ready_plan)
    require(
        ready_plan["environment"] == plan["environment"]
        and ready_plan["endpoints"] == plan["endpoints"]
        and ready_report["oracle_sha256"] == plan["oracle_sha256"],
        "Readiness runtime/endpoint differs",
    )


def _observe(recorder: Recorder, plan: Plan, progress: Progress) -> None:
    """Run the observation steps, gating each, within the time limit.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    plan : dict[str, typing.Any]
        The phase's plan.
    progress : Progress
        What has been done; updated as the steps run.

    Raises
    ------
    TimeoutError
        If the phase runs longer than the limit.
    """
    for index, step in enumerate(
        plan["steps"][: plan["expectation"]["observation_actions"]]
    ):
        if (time.monotonic_ns() - recorder.started) / NANOSECONDS >= LIMIT_SECONDS:
            message = "Phase exceeded 12 minutes"
            raise TimeoutError(message)
        recorder.execute(index, step)
        progress.completed += 1
        result = phase_gate(
            {"frames": recorder.frames, "completed_actions": progress.completed},
            plan,
            index,
        )
        if result is not None:
            progress.passed.append(result)


def _run_phase(
    recorder: Recorder, plan: Plan, output: Path, phase: int
) -> tuple[str, str, Progress]:
    """Run the observation, the hold and the quit, stopping at the first failure.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    plan : dict[str, typing.Any]
        The phase's plan.
    output : pathlib.Path
        The output directory.
    phase : int
        The phase number.

    Returns
    -------
    tuple[str, str, Progress]
        The status, the error text and the progress.
    """
    progress = Progress()
    status, error = "completed", ""
    try:
        _observe(recorder, plan, progress)
        hold(recorder, output, phase)
        # Operator now performs native File > Quit with both sessions still open.
        quit_steps(recorder, plan, progress)
    except STEP_FAILURES as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(progress.completed, name, "close")
    return status, error, progress


def _prepared(
    plan_path: Path, readiness_dir: Path, receipt_path: Path, binary: Path
) -> tuple[bytes, Plan, int]:
    """Check everything that must hold before a phase may start.

    Parameters
    ----------
    plan_path : pathlib.Path
        The phase's plan.
    readiness_dir : pathlib.Path
        The readiness capture directory.
    receipt_path : pathlib.Path
        The capture-ready receipt.
    binary : pathlib.Path
        The oracle binary.

    Returns
    -------
    tuple[bytes, dict[str, typing.Any], int]
        The plan file's bytes, the plan and the phase number.
    """
    raw = plan_path.read_bytes()
    plan = json.loads(raw)
    phase = verify_plan(plan)
    _check_sources(plan_path, raw, phase)
    _check_readiness(readiness_dir, plan)
    receipt = json.loads(receipt_path.read_text())
    capture_gate(receipt)
    require(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Runtime PID differs",
    )
    require(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    return raw, plan, phase


def run_gated(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape: five paths, as the command line passes them
    plan_path: Path,
    readiness_dir: Path,
    receipt_path: Path,
    binary: Path,
    output: Path,
) -> Report:
    """Run a phase, only after a separate root START and a verified recorder receipt.

    Parameters
    ----------
    plan_path : pathlib.Path
        The phase's plan.
    readiness_dir : pathlib.Path
        The readiness capture directory.
    receipt_path : pathlib.Path
        The capture-ready receipt.
    binary : pathlib.Path
        The oracle binary.
    output : pathlib.Path
        A directory that must not exist yet.

    Returns
    -------
    dict[str, typing.Any]
        The report that was written.

    Raises
    ------
    PermissionError
        If the effective user is not root.
    """
    if os.geteuid() != 0:
        message = "Live phase requires root /proc identity checks"
        raise PermissionError(message)
    raw, plan, phase = _prepared(plan_path, readiness_dir, receipt_path, binary)
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    result = _run_phase(recorder, plan, output, phase)
    capture = Capture(
        plan,
        recorder,
        raw,
        result,
        (readiness_dir, receipt_path),
        CAPTURE_MODULES,
        ORACLE_SHA256,
    )
    report = report_of(capture)
    write_files(output, raw, report)
    return report


def command(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # one argument for each option
    *,
    run: bool = False,
    plan: str,
    readiness_dir: str,
    capture_receipt: str,
    binary: str,
    output: str,
) -> None:
    """Run one phase against a live emulator, after a separate root START.

    Parameters
    ----------
    run
        Required: run the phase.
    plan
        The phase's plan.
    readiness_dir
        The readiness capture directory.
    capture_receipt
        The capture-ready receipt.
    binary
        The oracle binary.
    output
        A directory that must not exist yet.

    Raises
    ------
    UsageError
        If ``--run`` is not given.
    SystemExit
        With status 1 when the phase did not complete.
    """
    if not run:
        message = "--run is required"
        raise UsageError(message)
    result = run_gated(
        Path(plan),
        Path(readiness_dir),
        Path(capture_receipt),
        Path(binary),
        Path(output),
    )
    summary = {
        "status": result["status"],
        "gates": result["gates"],
        "error": result["error"],
    }
    sys.stdout.write(json.dumps(summary) + "\n")
    if result["status"] != "completed":
        raise SystemExit(1)


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used or a phase
        failed.
    """
    try:
        run_command(command, __doc__, sys.argv[1:])
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
