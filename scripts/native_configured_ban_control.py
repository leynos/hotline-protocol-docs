#!/usr/bin/env python3
"""Gate a control-only configured-ban fixture and retain held TCP sessions.

The report records which scripts made the capture (decision D31):
``driver_sha256`` is the digest of the modules of ``CAPTURE_MODULES`` and
``driver_identity`` holds the commit and the hash of each. A report made before
that decision holds the hash of this one file in ``driver_sha256``.
"""

import argparse
import dataclasses as dc
import datetime as dt
import functools
import json
import os
import select
import time
import typing as typ
from pathlib import Path

import capture_identity
import native_configured_ban_cases as cases
import native_control_readiness as base
from native_configured_ban_control_gates import (
    EXPECTED_PLANS,
    HELD_ACTIONS,
    HELD_STEPS,
    SAVE_MARKER,
    account_gate,
    identity_gate,
    outcome,
    plan_gate,
)
from protocol_capture import ORACLE_SHA256, Recorder, digest, run_plan, validate_plan
from verify_native_core import require

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_configured_ban_control.py",
    "native_configured_ban_control_gates.py",
)

__all__ = [
    "CAPTURE_MODULES",
    "EXPECTED_PLANS",
    "HELD_ACTIONS",
    "SAVE_MARKER",
    "HeldInputs",
    "account_gate",
    "base",
    "identity_gate",
    "main",
    "outcome",
    "plan_gate",
    "run_held",
    "wait_for_reviewed_save",
]

SAVE_WAIT_SECONDS = 120
POLL_SECONDS = 0.05
SELECT_SIZE_LIMIT = 0


class HeldInputs(typ.NamedTuple):
    """The files that one held-apply run reads and writes."""

    plan_path: Path
    binary: Path
    output: Path
    trigger: Path
    receipt: Path


@dc.dataclass(frozen=True, slots=True)
class Progress:
    """How far a held-apply run got, as its report records it."""

    completed: int
    status: str
    error: str
    save_trigger: str | None


def report_from_recorder(recorder: Recorder, source: bytes, progress: Progress) -> dict:
    """Assemble the report of a held-apply run from what the recorder holds.

    Parameters
    ----------
    recorder : protocol_capture.Recorder
        The recorder that executed the plan.
    source : bytes
        The bytes of the plan that was run.
    progress : Progress
        The actions completed, the status, the error and the save trigger.

    Returns
    -------
    dict[str, typing.Any]
        The report, with the identity of this script's modules.
    """
    plan = recorder.plan
    identity = capture_identity.identity(CAPTURE_MODULES)
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": progress.status,
        "native_conformance": False,
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "controller_uid": os.geteuid(),
        "plan_sha256": digest(source),
        "driver_sha256": identity["digest"],
        "driver_identity": identity,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": plan["gap_ids"],
        "planned_actions": len(plan["steps"]),
        "completed_actions": progress.completed,
        "save_trigger": progress.save_trigger,
        "error": progress.error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def _quiet(recorder: Recorder, message: str) -> None:
    """Require that no socket holds unread bytes or an EOF."""
    ready, _, _ = select.select(
        list(recorder.sockets.values()), [], [], SELECT_SIZE_LIMIT
    )
    require(not ready, message)


def wait_for_reviewed_save(recorder: Recorder, trigger: Path, deadline: float) -> None:
    """Hold the sockets quiet until the reviewed Save trigger appears.

    Parameters
    ----------
    recorder : protocol_capture.Recorder
        The recorder whose sockets are held.
    trigger : pathlib.Path
        The file that the reviewer creates to release the hold.
    deadline : float
        The monotonic time at which to give up.

    Raises
    ------
    TimeoutError
        If the trigger does not arrive before the deadline.
    """
    require(not trigger.exists(), "Save trigger already exists before hold")
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            list(recorder.sockets.values()), [], [], POLL_SECONDS
        )
        require(not ready, "Notice, data or EOF arrived before reviewed Save")
        if trigger.exists():
            require(trigger.read_bytes() == SAVE_MARKER, "Save trigger differs")
            _quiet(recorder, "Socket changed before reviewed Save")
            return
    message = "Reviewed Save trigger did not arrive"
    raise TimeoutError(message)


def _hold_for_save(
    recorder: Recorder, inputs: HeldInputs, source: bytes, completed: int
) -> str:
    """Pause the plan after the notices are expected, until the Save is reviewed.

    Returns
    -------
    str
        The name of the trigger that released the hold.
    """
    require(
        identity_gate(recorder.frames) == recorder.variables.get("target_uid"),
        "Saved target UID differs",
    )
    base.capture_gate(json.loads(inputs.receipt.read_text(encoding="utf-8")))
    held = {
        "source_plan_sha256": digest(source),
        "completed_actions": completed,
        "target_uid_hex": recorder.variables["target_uid"].hex(),
        "controller_uid": os.geteuid(),
    }
    (inputs.output / "held-ready.json").write_text(
        json.dumps(held, indent=2) + "\n", encoding="utf-8"
    )
    wait_for_reviewed_save(
        recorder, inputs.trigger, time.monotonic() + SAVE_WAIT_SECONDS
    )
    base.capture_gate(json.loads(inputs.receipt.read_text(encoding="utf-8")))
    return "reviewed-save"


def _write_report(inputs: HeldInputs, source: bytes, report: dict) -> None:
    """Write the plan, the report and the checksums of a held-apply run."""
    output = inputs.output
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        ),
        encoding="utf-8",
    )


def run_held(inputs: HeldInputs) -> dict:
    """Run the held-apply plan and retain every byte, including on failure.

    Parameters
    ----------
    inputs : HeldInputs
        The plan, the native binary, the output directory, the Save trigger
        and the capture receipt.

    Returns
    -------
    dict[str, typing.Any]
        The report, with ``status`` ``completed`` or ``failed``.
    """
    source = inputs.plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(
        digest(inputs.binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs"
    )
    require(len(plan["steps"]) == HELD_STEPS, "Planned EOF tails absent")
    inputs.output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, completed, save_trigger = "completed", "", 0, None
    try:
        for index, step in enumerate(plan["steps"]):
            if index == HELD_ACTIONS:
                save_trigger = _hold_for_save(recorder, inputs, source, completed)
            recorder.execute(index, step)
            completed += 1
    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        IndexError,
        TimeoutError,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    report = report_from_recorder(
        recorder, source, Progress(completed, status, error, save_trigger)
    )
    _write_report(inputs, source, report)
    return report


def _prepare(args: argparse.Namespace) -> None:
    """Write the plans of the fixture for a runtime record."""
    env = json.loads(args.runtime_record.read_text(encoding="utf-8"))
    hashes = cases.write_plans(args.output, env, args.port)
    (args.output / "source-hashes.json").write_text(
        json.dumps(hashes, indent=2) + "\n", encoding="utf-8"
    )


def _execute(args: argparse.Namespace) -> None:
    """Run the readiness, guard, seed and held-apply cases in order."""
    base.require_controller_uid()
    receipt = json.loads(args.capture_ready.read_text(encoding="utf-8"))
    base.capture_gate(receipt)
    plan_gate(args.plans, receipt["emulator_pid"])
    args.output.mkdir(parents=True, exist_ok=False)
    for name, gate in (
        ("readiness", base.readiness),
        ("guard", functools.partial(account_gate, absent=True)),
        ("seed", functools.partial(account_gate, absent=False)),
    ):
        base.capture_gate(json.loads(args.capture_ready.read_text(encoding="utf-8")))
        report = run_plan(args.plans / f"{name}.json", args.binary, args.output / name)
        gate(report)
    report = run_held(
        HeldInputs(
            args.plans / "held-apply.json",
            args.binary,
            args.output / "held-apply",
            args.save_trigger,
            args.capture_ready,
        )
    )
    held_plan = json.loads((args.plans / "held-apply.json").read_text(encoding="utf-8"))
    outcome(report, held_plan)


def main() -> None:
    """Prepare the plans or run the fixture, as the command line says."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--runtime-record", type=Path, required=True)
    prepare.add_argument("--port", type=int, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("--plans", type=Path, required=True)
    execute.add_argument("--binary", type=Path, required=True)
    execute.add_argument("--capture-ready", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--save-trigger", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        _prepare(args)
    else:
        _execute(args)


if __name__ == "__main__":
    main()
