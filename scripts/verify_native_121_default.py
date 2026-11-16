#!/usr/bin/env python3
"""Gate and replay two bounded delayed-121 default-response observations.

The checks live in ``verify_native_121_default_checks`` and
``verify_native_121_default_gates``, and every name they define stays importable
from here. The report that ``run_gated`` writes records which scripts made it
(decision D31): ``driver_sha256`` is the digest of the modules of
``CAPTURE_MODULES`` and ``driver_identity`` holds the commit and the hash of each.
A report made before that decision holds the hash of this one file in
``driver_sha256``.

Command lines::

    verify_native_121_default.py --verify CAPTURE
    verify_native_121_default.py --run PLAN --binary F --baseline-plan F --output D
"""

import datetime as dt
import json
import sys
import typing as typ
from pathlib import Path

import capture_identity
from native_121_default_cases import DEFAULT, observe
from native_pm_cases import BASELINE_SHA256, load_baseline
from protocol_capture import Recorder, digest, validate_plan, verify_capture
from script_cli import UsageError
from script_cli import run as run_command
from verify_native_121_default_checks import (
    AGREEMENT_SHA256,
    at,
    check_auto,
    check_roster,
    layout,
    own_uid,
    subject_uid,
)
from verify_native_121_default_gates import gate, semantic
from verify_native_core import require

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "verify_native_121_default.py",
    "verify_native_121_default_checks.py",
    "verify_native_121_default_gates.py",
    "verify_native_121_default_subject.py",
)

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

STEP_FAILURES = (OSError, EOFError, ValueError, KeyboardInterrupt)
FAILED = 1  # the exit status of a run that did not complete

__all__ = [
    "AGREEMENT_SHA256",
    "BASELINE_SHA256",
    "CAPTURE_MODULES",
    "DEFAULT",
    "at",
    "check_auto",
    "check_roster",
    "gate",
    "layout",
    "main",
    "observe",
    "own_uid",
    "run_gated",
    "semantic",
    "subject_uid",
]


def _execute(recorder: Recorder, plan: Plan) -> tuple[str, str, list[str], int]:
    """Execute every step and gate it, stopping at the first failure.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    plan : dict[str, typing.Any]
        The plan.

    Returns
    -------
    tuple[str, str, list[str], int]
        The status, the error text, the gates that passed and the completed
        actions.
    """
    completed, status, error, passed = 0, "completed", "", []
    try:
        for index, step in enumerate(plan["steps"]):
            recorder.execute(index, step)
            completed += 1
            result = gate(
                {"frames": recorder.frames, "events": recorder.events}, plan, index
            )
            if result is not None:
                passed.append(result)
    except STEP_FAILURES as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    return status, error, passed, completed


def _report(
    plan: Plan, recorder: Recorder, raw: bytes, outcome: tuple[str, str, list[str], int]
) -> Report:
    """Build the report of a run.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The plan.
    recorder : Recorder
        The recorder that ran it.
    raw : bytes
        The plan file's bytes.
    outcome : tuple[str, str, list[str], int]
        The status, the error text, the gates that passed and the completed
        actions.

    Returns
    -------
    dict[str, typing.Any]
        The report, with its keys in the order that earlier reports have.
    """
    status, error, _passed, completed = outcome
    identity = capture_identity.identity(CAPTURE_MODULES)
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "plan_sha256": digest(raw),
        "driver_sha256": identity["digest"],
        "driver_identity": identity,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": plan["gap_ids"],
        "completed_actions": completed,
        "error": error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def _write(output: Path, raw: bytes, report: Report, gates: Report) -> None:
    """Write the plan, the report, their checksums and the stage gates.

    Parameters
    ----------
    output : pathlib.Path
        The output directory.
    raw : bytes
        The plan file's bytes.
    report : dict[str, typing.Any]
        The report.
    gates : dict[str, typing.Any]
        The stage gates that passed, with the status and the error.
    """
    (output / "plan.json").write_bytes(raw)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    checks = [
        f"{digest((output / name).read_bytes())}  {name}"
        for name in ("plan.json", "report.json")
    ]
    (output / "checksums.sha256").write_text("\n".join(checks) + "\n")
    (output / "stage-gates.json").write_text(json.dumps(gates, indent=2) + "\n")


def run_gated(
    plan_path: Path, binary: Path, baseline_path: Path, output: Path
) -> Report:
    """Run a separately authorised plan, stopping after its first bad stage.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan.
    binary : pathlib.Path
        The oracle binary, which must be the one that the plan records.
    baseline_path : pathlib.Path
        The A7 baseline plan.
    output : pathlib.Path
        A directory that must not exist yet.

    Returns
    -------
    dict[str, typing.Any]
        The report that was written.
    """
    raw = plan_path.read_bytes()
    plan = json.loads(raw)
    validate_plan(plan)
    layout(plan)
    load_baseline(baseline_path.read_bytes())
    require(
        digest(binary.read_bytes()) == plan["oracle_sha256"],
        "Oracle binary hash differs",
    )
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    outcome = _execute(recorder, plan)
    report = _report(plan, recorder, raw, outcome)
    status, error, passed, _completed = outcome
    _write(output, raw, report, {"passed": passed, "status": status, "error": error})
    return report


def _live(
    run: str, binary: str | None, baseline: str | None, output: str | None
) -> Path:
    """Run the plan and return the capture directory, or exit when it failed.

    Parameters
    ----------
    run : str
        The plan.
    binary : str | None
        The oracle binary.
    baseline : str | None
        The baseline plan.
    output : str | None
        The output directory.

    Returns
    -------
    pathlib.Path
        The directory of the capture that was written.

    Raises
    ------
    UsageError
        If a path that a run needs is missing.
    SystemExit
        With status 1 and the error on standard error, when the run failed.
    """
    chosen = [binary, baseline, output]
    paths = [Path(item) for item in chosen if item is not None]
    if len(paths) != len(chosen):
        message = "--run requires --binary, --baseline-plan and --output"
        raise UsageError(message)
    report = run_gated(Path(run), *paths)
    if report["status"] != "completed":
        sys.stderr.write(report["error"] + "\n")
        raise SystemExit(FAILED)
    return paths[-1]


def command(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # one argument for each option
    *,
    verify: str | None = None,
    run: str | None = None,
    binary: str | None = None,
    baseline_plan: str | None = None,
    output: str | None = None,
) -> None:
    """Replay a capture offline, or run a plan that a separate live START allows.

    Parameters
    ----------
    verify
        An existing capture directory; offline.
    run
        A plan; a separate live START is required.
    binary
        The oracle binary (with ``--run``).
    baseline_plan
        The A7 baseline plan (with ``--run``).
    output
        The directory of the run (with ``--run``).

    Raises
    ------
    UsageError
        If neither or both of ``--verify`` and ``--run`` are given.
    """
    if (verify is None) == (run is None):
        message = "exactly one of --verify and --run is required"
        raise UsageError(message)
    if run is not None:
        capture = _live(run, binary, baseline_plan, output)
    else:
        capture = Path(typ.cast("str", verify))
    result = semantic(
        verify_capture(capture), json.loads((capture / "plan.json").read_text())
    )
    sys.stdout.write(json.dumps(result, indent=2) + "\n")


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used or a run
        failed.
    """
    try:
        run_command(command, __doc__, sys.argv[1:])
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
