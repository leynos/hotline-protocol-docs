"""The phase run, its report and its files, for the settings persistence capture.

Part of the capture driver's module set
(``native_settings_persistence.CAPTURE_MODULES``). The report records which scripts
made the capture (decision D31): ``driver_sha256`` is the digest of the modules of
the set and ``driver_identity`` holds the commit and the hash of each.
"""

import dataclasses as dc
import datetime as dt
import json
import time
import typing as typ

import capture_identity
from protocol_capture import digest

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from protocol_capture import Recorder

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

LIMIT_SECONDS = 720
NANOSECONDS = 1e9

__all__ = [
    "LIMIT_SECONDS",
    "NANOSECONDS",
    "Capture",
    "Progress",
    "hold",
    "quit_steps",
    "report_of",
    "write_files",
]


@dc.dataclass(slots=True)
class Progress:
    """What a phase has done so far.

    Attributes
    ----------
    completed : int
        The actions that have run.
    passed : list[str]
        The gates that have passed.
    """

    completed: int = 0
    passed: list[str] = dc.field(default_factory=list)


def hold(recorder: Recorder, output: Path, phase: int) -> None:
    """Record that the sockets are held, ready for the operator to quit the app.

    Parameters
    ----------
    recorder : Recorder
        The recorder.
    output : pathlib.Path
        The output directory.
    phase : int
        The phase number.
    """
    held = {
        "utc": dt.datetime.now(dt.UTC).isoformat(),
        "phase": phase,
        "sockets": sorted(recorder.sockets),
    }
    (output / "hold-ready.json").write_text(json.dumps(held, indent=2) + "\n")


def quit_steps(recorder: Recorder, plan: Plan, progress: Progress) -> None:
    """Run the steps that wait for the app to quit, within the time limit.

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
        If the phase has run out of time before the app quits.
    """
    first = plan["expectation"]["observation_actions"]
    for index, step in enumerate(plan["steps"][first:], start=first):
        remaining = (
            LIMIT_SECONDS - (time.monotonic_ns() - recorder.started) / NANOSECONDS
        )
        if remaining <= 0:
            message = "Phase exceeded 12 minutes before app Quit"
            raise TimeoutError(message)
        recorder.execute(index, {**step, "timeout": min(step["timeout"], remaining)})
        progress.completed += 1


@dc.dataclass(frozen=True, slots=True)
class Capture:
    """What a finished phase leaves for its report.

    Attributes
    ----------
    plan : dict[str, typing.Any]
        The plan.
    recorder : Recorder
        The recorder that ran it.
    raw : bytes
        The plan file's bytes.
    result : tuple[str, str, Progress]
        The status, the error text and the progress.
    paths : tuple[pathlib.Path, pathlib.Path]
        The readiness directory and the capture receipt.
    modules : collections.abc.Sequence[str]
        The scripts that make the capture, for its identity.
    oracle : str
        The SHA-256 of the oracle binary that the capture was made against.
    """

    plan: Plan
    recorder: Recorder
    raw: bytes
    result: tuple[str, str, Progress]
    paths: tuple[Path, Path]
    modules: cabc.Sequence[str]
    oracle: str


def report_of(capture: Capture) -> Report:
    """Build the report of a phase.

    Parameters
    ----------
    capture : Capture
        The finished phase.

    Returns
    -------
    dict[str, typing.Any]
        The report, with its keys in the order that earlier reports have.
    """
    plan, recorder = capture.plan, capture.recorder
    status, error, progress = capture.result
    readiness_dir, receipt_path = capture.paths
    identity = capture_identity.identity(capture.modules)
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "persistence_proven": False,
        "full_file_baseline": "not_exercised",
        "oracle_sha256": capture.oracle,
        "plan_sha256": digest(capture.raw),
        "driver_sha256": identity["digest"],
        "driver_identity": identity,
        "readiness_report_sha256": digest((readiness_dir / "report.json").read_bytes()),
        "capture_receipt_sha256": digest(receipt_path.read_bytes()),
        "started_at_utc": recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "completed_actions": progress.completed,
        "error": error,
        "gates": progress.passed,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def write_files(output: Path, raw: bytes, report: Report) -> None:
    """Write the plan, the report and the checksums of both.

    Parameters
    ----------
    output : pathlib.Path
        The output directory.
    raw : bytes
        The plan file's bytes.
    report : dict[str, typing.Any]
        The report.
    """
    (output / "plan.json").write_bytes(raw)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
