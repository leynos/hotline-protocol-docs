#!/usr/bin/env python3
"""Verify or explicitly run one stage-gated same-session 304 matrix.

The stage checks live in ``verify_native_settings_transition_checks``, and every
name they define stays importable from here. The report that ``run_gated`` writes
records which scripts made it (decision D31): ``driver_sha256`` is the digest of
the modules of ``CAPTURE_MODULES`` and ``driver_identity`` holds the commit and
the hash of each. A report made before that decision holds the hash of this one
file in ``driver_sha256``.

Command lines::

    verify_native_settings_transition.py --verify CAPTURE [--output FILE]
    verify_native_settings_transition.py --run PLAN --binary F --output D
"""

import dataclasses as dc
import datetime as dt
import json
import sys
import typing as typ
from pathlib import Path

import capture_identity
from protocol_capture import Recorder, digest, validate_plan, verify_capture
from script_cli import UsageError
from script_cli import run as run_command
from verify_native_core import require
from verify_native_settings_transition_checks import (
    CASE,
    SAVE_UID,
    check_stage,
    check_update,
    check_updates,
    current_uids,
    semantic,
    stage_frames,
)

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "verify_native_settings_transition.py",
    "verify_native_settings_transition_checks.py",
)

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

STEP_FAILURES = (OSError, EOFError, ValueError, KeyboardInterrupt)
FAILED = 1  # the exit status of a run that did not complete
IDENTITY_SCOPE = (
    "Local binary hash verified; remote process identity is operator-reported"
)
GATE_LAYOUT = [("read_frame", "main"), ("read_frame", "subject")]

__all__ = [
    "CAPTURE_MODULES",
    "check_stage",
    "check_update",
    "check_updates",
    "current_uids",
    "main",
    "run_gated",
    "semantic",
    "stage_frames",
]


@dc.dataclass(slots=True)
class Stages:
    """What a run learns of its stages as the steps are executed.

    Attributes
    ----------
    plan : dict[str, typing.Any]
        The plan.
    saved : int
        The step that saves the subject's UID.
    uid : bytes
        The subject's UID, once it is saved.
    main_uid : bytes
        The observer's UID, once the subject's is saved.
    checked : list[dict[str, typing.Any]]
        The stages that passed.
    """

    plan: Plan
    saved: int
    uid: bytes = b""
    main_uid: bytes = b""
    checked: list[Report] = dc.field(default_factory=list)

    def after(self, frames: list[Report], index: int) -> None:
        """Run the gates that follow a step.

        Parameters
        ----------
        frames : list[dict[str, typing.Any]]
            The frames received so far.
        index : int
            The step that has just run.
        """
        report = {"frames": frames}
        if index == self.saved:
            self.uid, self.main_uid = current_uids(report, self.plan)
        for window in self.plan["expectation"]["windows"]:
            if window["first"] + 1 == index:
                check_update(report, window, self.uid, "main")
            if window["first"] + 2 == index:
                check_update(report, window, self.uid, "subject")
            if window["last"] == index:
                self.checked.append(
                    check_stage(report, self.plan, window, self.uid, self.main_uid)
                )


def _layout(plan: Plan) -> int:
    """Check that the identity is saved before the first 304 and each stage is gated.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The plan.

    Returns
    -------
    int
        The step that saves the subject's UID.
    """
    saved = [
        i for i, item in enumerate(plan["steps"]) if item.get("save_fields") == SAVE_UID
    ]
    require(len(saved) == 1, "Subject UID save step differs")
    windows = plan["expectation"]["windows"]
    require(saved[0] < windows[0]["first"], "Identity gate occurs after 304")
    for window in windows:
        pair = plan["steps"][window["first"] + 1 : window["first"] + 3]
        require(
            [(s["op"], s.get("connection")) for s in pair] == GATE_LAYOUT,
            "Stage 301 gate layout differs",
        )
    return saved[0]


def _execute(recorder: Recorder, stages: Stages) -> tuple[str, str, int]:
    """Execute every step and gate it, stopping at the first failure.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    stages : Stages
        The run's plan and what it learns.

    Returns
    -------
    tuple[str, str, int]
        The status, the error text and the completed actions.
    """
    completed, status, error = 0, "completed", ""
    try:
        for index, step in enumerate(stages.plan["steps"]):
            recorder.execute(index, step)
            completed += 1
            stages.after(recorder.frames, index)
    except STEP_FAILURES as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    return status, error, completed


def _report(
    recorder: Recorder, plan: Plan, source: bytes, outcome: tuple[str, str, int]
) -> Report:
    """Build the report of a run.

    Parameters
    ----------
    recorder : Recorder
        The recorder that ran the plan.
    plan : dict[str, typing.Any]
        The plan.
    source : bytes
        The plan file's bytes.
    outcome : tuple[str, str, int]
        The status, the error text and the completed actions.

    Returns
    -------
    dict[str, typing.Any]
        The report, with its keys in the order that earlier reports have.
    """
    status, error, completed = outcome
    identity = capture_identity.identity(CAPTURE_MODULES)
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "identity_scope": IDENTITY_SCOPE,
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "plan_sha256": digest(source),
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


def _write(output: Path, source: bytes, report: Report, gates: Report) -> None:
    """Write the plan, the report, their checksums and the stage gates.

    Parameters
    ----------
    output : pathlib.Path
        The output directory.
    source : bytes
        The plan file's bytes.
    report : dict[str, typing.Any]
        The report.
    gates : dict[str, typing.Any]
        The stages that passed, with the status and the error.
    """
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
    (output / "stage-gates.json").write_text(json.dumps(gates, indent=2) + "\n")


def run_gated(plan_path: Path, binary: Path, output: Path) -> Report:
    """Execute a separately authorised plan, stopping after its first bad stage.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan.
    binary : pathlib.Path
        The oracle binary, which must be the one that the plan records.
    output : pathlib.Path
        A directory that must not exist yet.

    Returns
    -------
    dict[str, typing.Any]
        The report that was written.
    """
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(plan["expectation"]["case"] == CASE, "Wrong run case")
    require(
        digest(binary.read_bytes()) == plan["oracle_sha256"],
        "Oracle binary hash differs",
    )
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    stages = Stages(plan, _layout(plan))
    outcome = _execute(recorder, stages)
    report = _report(recorder, plan, source, outcome)
    status, error, _completed = outcome
    gates = {"passed": stages.checked, "status": status, "error": error}
    _write(output, source, report, gates)
    return report


def _live(run: str, binary: str | None, output: str | None) -> Path:
    """Run the plan and return the capture directory, or exit when it failed.

    Parameters
    ----------
    run : str
        The plan.
    binary : str | None
        The oracle binary.
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
    if binary is None or output is None:
        message = "--run requires --binary and --output"
        raise UsageError(message)
    report = run_gated(Path(run), Path(binary), Path(output))
    if report["status"] != "completed":
        sys.stderr.write(report["error"] + "\n")
        raise SystemExit(FAILED)
    return Path(output)


def command(
    *,
    verify: str | None = None,
    run: str | None = None,
    binary: str | None = None,
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
    output
        With ``--run`` the directory of the run; with ``--verify`` a new file
        that receives the result.

    Raises
    ------
    UsageError
        If neither or both of ``--verify`` and ``--run`` are given, or if the
        file for the result exists.
    """
    if (verify is None) == (run is None):
        message = "exactly one of --verify and --run is required"
        raise UsageError(message)
    capture = (
        _live(run, binary, output) if run is not None else Path(typ.cast("str", verify))
    )
    report = verify_capture(capture)
    result = semantic(report, json.loads((capture / "plan.json").read_text()))
    if output is not None and run is None:
        target = Path(output)
        if target.exists():
            message = "Refusing existing output"
            raise UsageError(message)
        target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    else:
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
