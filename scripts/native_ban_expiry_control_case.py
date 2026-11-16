"""Run one ban-expiry case on the wire and work out the ban's host-time bracket.

Part of the ban-expiry controller (``native_ban_expiry_control``), which
re-exports every public name below.
"""

import datetime as dt
import json
import time
import typing as typ

import native_ban_expiry_cases as cases
from native_ban_expiry_control_core import (
    MAX_WINDOW_SECONDS,
    Report,
    TimingBounds,
    require,
    utc,
)
from native_ban_expiry_control_outcome import identity_before_110, outcome_gate
from protocol_capture import ORACLE_SHA256, Recorder

if typ.TYPE_CHECKING:
    from pathlib import Path

# The failures that stop a case or an epoch and are recorded, not raised.
CAPTURE_FAILURES = (
    OSError,
    EOFError,
    ValueError,
    KeyError,
    IndexError,
    TimeoutError,
    KeyboardInterrupt,
)
DEFAULT_STEP_TIMEOUT = 2
NANOSECONDS = 1e9
KICK_REQUEST_PREFIX = "0000006e00000021"
KICK_REPLY_ID = 33


def _bounded_step(
    step: Report, recorder: Recorder, epoch_deadline: dt.datetime
) -> Report:
    """Cap a step's timeout by what is left of the epoch and of the case.

    Returns
    -------
    dict[str, typing.Any]
        The step with its timeout capped.
    """
    remaining = min(
        (epoch_deadline - dt.datetime.now(dt.UTC)).total_seconds(),
        MAX_WINDOW_SECONDS - (time.monotonic_ns() - recorder.started) / NANOSECONDS,
    )
    require(remaining > 0, "Epoch or case exceeded12min")
    return {
        **step,
        "timeout": min(step.get("timeout", DEFAULT_STEP_TIMEOUT), remaining),
    }


def _is_kick(step: Report) -> bool:
    """Say whether a step sends the kick request.

    Returns
    -------
    bool
        Whether the step is a send whose bytes begin with the kick header.
    """
    encoded = step.get("hex")
    if step["op"] != "send" or not isinstance(encoded, str):
        return False
    return encoded.startswith(KICK_REQUEST_PREFIX)


def _guard_kick(recorder: Recorder, step: Report, name: str) -> None:
    """Re-check both identities before the kick request is sent."""
    if _is_kick(step):
        identity_before_110(
            recorder.frames,
            recorder.variables.get("target_uid", b""),
            protected=name == "protected",
        )


def _outcome(
    recorder: Recorder, name: str, completed: int, failure: tuple[str, str]
) -> Report:
    """Assemble the report of a case from what the recorder holds.

    Returns
    -------
    dict[str, typing.Any]
        The report, before the outcome gate runs.
    """
    status, error = failure
    return {
        "schema_version": 1,
        "status": status,
        "case": name,
        "profile": "control-only",
        "full_file_baseline": "not_exercised",
        "oracle_sha256": ORACLE_SHA256,
        "started_at_utc": recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "completed_actions": completed,
        "error": error,
        "variables": {key: value.hex() for key, value in recorder.variables.items()},
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def run_case(
    plan: Report, name: str, output: Path, epoch_deadline: dt.datetime
) -> Report:
    """Run one case; preserve partial events and every read byte on failure.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The validated plan of the case.
    name : str
        The case name.
    output : pathlib.Path
        The new directory that receives ``plan.json`` and ``report.json``.
    epoch_deadline : datetime.datetime
        The deadline of the epoch.

    Returns
    -------
    dict[str, typing.Any]
        The report, with ``status`` ``completed`` or ``failed``.
    """
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    completed = 0
    failure = ("completed", "")
    try:
        for index, planned in enumerate(plan["steps"]):
            step = _bounded_step(planned, recorder, epoch_deadline)
            _guard_kick(recorder, step, name)
            recorder.execute(index, step)
            completed += 1
    except CAPTURE_FAILURES as error:
        failure = ("failed", f"{type(error).__name__}: {error}")
    finally:
        for label, sock in list(recorder.sockets.items()):
            sock.close()
            recorder.event(completed, label, "close")
    result = _outcome(recorder, name, completed, failure)
    if result["status"] == "completed":
        try:
            outcome_gate(result, name)
        except (ValueError, KeyError, IndexError) as error:
            result["status"] = "failed"
            result["error"] = f"{type(error).__name__}: {error}"
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def _bracket_indices(steps: list[Report]) -> tuple[int, int]:
    """Find the kick request and the acknowledgement it is bracketed by.

    Returns
    -------
    tuple[int, int]
        The index of the request and of the acknowledgement.
    """
    request_index = next(
        i
        for i, s in enumerate(steps)
        if s["op"] == "send" and s["hex"].startswith(KICK_REQUEST_PREFIX)
    )
    ack_index = next(
        i
        for i, s in enumerate(steps)
        if i > request_index
        and s["op"] == "read_frame"
        and s.get("match_frame", {}).get("id") == KICK_REPLY_ID
    )
    return request_index, ack_index


def ban_timing(report: Report, receipt: Report) -> TimingBounds:
    """Bracket the ban insertion in host time from the events of its case.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The completed ``tempban`` case report.
    receipt : dict[str, typing.Any]
        The runtime receipt that names the guest.

    Returns
    -------
    TimingBounds
        The checked bracket.
    """
    require(
        report["case"] == "tempban" and report["status"] == "completed",
        "No completed option-one case",
    )
    request_index, ack_index = _bracket_indices(cases.plans()["tempban"])
    sends = [
        e
        for e in report["events"]
        if e["action"] == request_index and e["event"] == "send"
    ]
    receives = [
        e
        for e in report["events"]
        if e["action"] == ack_index and e["event"] == "receive"
    ]
    require(bool(sends and receives), "Missing wire request/ACK bracket")
    origin = utc(report["started_at_utc"])
    result = TimingBounds(
        request_utc=origin
        + dt.timedelta(microseconds=min(e["elapsed_ns"] for e in sends) // 1000),
        ack_utc=origin
        + dt.timedelta(microseconds=max(e["elapsed_ns"] for e in receives) // 1000),
        image_inode=receipt["owned_working_image_inode"],
        emulator_pid=receipt["emulator_pid"],
        emulator_start_ticks=receipt["emulator_starttime"],
        emulator_sha256=receipt["emulator_sha256"],
        namespace_inode=receipt["emulator_netns_inode"],
    )
    return TimingBounds.from_json(result.to_json())
