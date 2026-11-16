"""The guarded ban run of the isolated ban-control capture.

Part of the capture driver's module set (``native_control_readiness.CAPTURE_MODULES``).
``run_ban`` runs the ban plan against a recorder, refuses to send the 110 request
until the target's identity is gated, and writes the plan, the report and the
checksums. The report records which scripts made it (decision D31):
``driver_sha256`` is the digest of the modules of the set and ``driver_identity``
holds the commit and the hash of each.
"""

import dataclasses as dc
import datetime as dt
import json
import os
import typing as typ

import capture_identity
from native_control_readiness_ban import target_gate
from protocol_capture import ORACLE_SHA256, Recorder, digest, validate_plan
from verify_native_core import require

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

BAN_REQUEST_PREFIX = "0000006e00000021"  # the 110 request, whose ID is 33
STEP_FAILURES = (
    OSError,
    EOFError,
    ValueError,
    KeyError,
    IndexError,
    StopIteration,
    KeyboardInterrupt,
)

__all__ = ["execute_ban_step", "run_ban"]


def execute_ban_step(recorder: Recorder, index: int, step: dict[str, typ.Any]) -> None:
    """Run one step, gating the 110 request on the target's identity.

    Parameters
    ----------
    recorder : Recorder
        The recorder that executes the plan.
    index : int
        The step's position in the plan.
    step : dict[str, typing.Any]
        The step.
    """
    if step["op"] == "send" and step["hex"].startswith(BAN_REQUEST_PREFIX):
        require(
            recorder.variables.get("target_uid") == target_gate(recorder.frames),
            "Saved target UID differs",
        )
    recorder.execute(index, step)


def _run_steps(recorder: Recorder, plan: Plan) -> tuple[str, str, int]:
    """Execute every step, stopping at the first failure.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    plan : dict[str, typing.Any]
        The plan.

    Returns
    -------
    tuple[str, str, int]
        The status, the error text and the number of completed actions.
    """
    status, error, completed = "completed", "", 0
    try:
        for index, step in enumerate(plan["steps"]):
            execute_ban_step(recorder, index, step)
            completed += 1
    except STEP_FAILURES as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    return status, error, completed


@dc.dataclass(frozen=True, slots=True)
class Capture:
    """What a finished run leaves for its report.

    Attributes
    ----------
    plan : dict[str, typing.Any]
        The plan.
    recorder : Recorder
        The recorder that ran it.
    source : bytes
        The plan file's bytes.
    result : tuple[str, str, int]
        The status, the error text and the completed actions.
    modules : collections.abc.Sequence[str]
        The scripts that make the capture, for its identity.
    """

    plan: Plan
    recorder: Recorder
    source: bytes
    result: tuple[str, str, int]
    modules: cabc.Sequence[str]


def _report(capture: Capture) -> Report:
    """Build the report of a run.

    Parameters
    ----------
    capture : Capture
        The finished run.

    Returns
    -------
    dict[str, typing.Any]
        The report, with its keys in the order that earlier reports have.
    """
    plan, recorder = capture.plan, capture.recorder
    status, error, completed = capture.result
    identity = capture_identity.identity(capture.modules)
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "controller_uid": os.geteuid(),
        "plan_sha256": digest(capture.source),
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


def _write(output: Path, source: bytes, report: Report) -> None:
    """Write the plan, the report and the checksums of both.

    Parameters
    ----------
    output : pathlib.Path
        The output directory.
    source : bytes
        The plan file's bytes.
    report : dict[str, typing.Any]
        The report.
    """
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )


def run_ban(
    plan_path: Path, binary: Path, output: Path, modules: cabc.Sequence[str]
) -> Report:
    """Run the ban plan, gating the 110 request, and write its capture.

    Parameters
    ----------
    plan_path : pathlib.Path
        The ban plan.
    binary : pathlib.Path
        The oracle binary, which must be the one that is recorded.
    output : pathlib.Path
        A directory that must not exist yet.
    modules : collections.abc.Sequence[str]
        The scripts that make the capture, for its identity.

    Returns
    -------
    dict[str, typing.Any]
        The report that was written.
    """
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle identity differs")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    result = _run_steps(recorder, plan)
    report = _report(Capture(plan, recorder, source, result, modules))
    _write(output, source, report)
    return report
