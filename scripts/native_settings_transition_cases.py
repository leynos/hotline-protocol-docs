#!/usr/bin/env python3
"""Prepare one bounded, same-session native 304 transition observation."""

import dataclasses as dc
import typing as typ

from native_auth_cases import authentication
from native_baseline_planner import identified_baseline, write_prepared
from native_plan import close, login, packet, payload, read, send
from native_pm_cases import BASELINE_SHA256, load_baseline, variable_message
from native_wire_names import (
    FIELD_AUTO_RESPONSE,
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_SEND_PRIVATE_MESSAGE,
    TYPE_SET_CLIENT_INFO,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

type Json = dict[str, typ.Any]

# The names that the 121-default planner's tests and the capture driver take from
# this module stay importable from it.
__all__ = [
    "BASELINE_SHA256",
    "DEFAULT",
    "EXPLICIT",
    "ORACLE_SHA256",
    "STAGES",
    "SUBJECT",
    "Stage",
    "barrier",
    "load_baseline",
    "main",
    "observe",
    "plans",
    "settings",
]

SUBJECT = b"A32-Subject"
EXPLICIT = b"A32-Explicit"
DEFAULT = b"I'm not able to respond right now. Please try later!"
CONTROL_PORT = 15500
QUIET_SECONDS = 2
ROSTER_ID = 10
SETTINGS_BASE = 20  # stage ``n`` sends its 304 with this identifier plus ``n``
MESSAGE_BASE = 60  # and its message with this one
BARRIER_BASE = 100  # and its barrier with this one
RESTORE_ID = 90
FINAL_BARRIER_ID = 190
LOGIN_STEPS = 3  # the handshake steps that precede the login request
SUBJECT_REPLIES = 3  # the 107 reply, then the 354 and 109 notifications
GAP_IDS = ["GAP-029", "GAP-030"]
OPERATOR = "A32 offline preparation; separate live START and oracle.lock required"


@dc.dataclass(frozen=True, slots=True)
class Stage:
    """One 304 request of the sequence, and what its message must observe.

    Attributes
    ----------
    label : str
        The stage's name.
    name : bytes | None
        The name field to send, or ``None`` to omit it.
    icon : bytes | None
        The icon field to send, or ``None`` to omit it.
    option : bytes | None
        The options field to send, or ``None`` to omit it.
    auto : bytes | None
        The automatic-response field to send, or ``None`` to omit it.
    expected_name : bytes
        The name that the presence update must carry.
    expected_icon : bytes
        The icon that the presence update must carry.
    expected_auto : bytes | None
        The text of the automatic response, or ``None`` when none is expected.
    """

    label: str
    name: bytes | None
    icon: bytes | None
    option: bytes | None
    auto: bytes | None
    expected_name: bytes
    expected_icon: bytes
    expected_auto: bytes | None


STAGES = (
    Stage(
        "explicit",
        EXPLICIT,
        b"\0\7",
        b"\0\4",
        b"a32-explicit",
        EXPLICIT,
        b"\0\7",
        b"a32-explicit",
    ),
    Stage("omitted", None, None, b"\0\4", None, b"***", b"\0\0", DEFAULT),
    Stage("empty", b"", b"", b"\0\4", b"", b"***", b"\0\0", DEFAULT),
    Stage(
        "unknown-only",
        b"A32-Unknown",
        b"\0\11",
        b"\0\10",
        None,
        b"A32-Unknown",
        b"\0\11",
        None,
    ),
    Stage(
        "mixed-unknown",
        b"A32-Mixed",
        b"\0\12",
        b"\0\14",
        None,
        b"A32-Mixed",
        b"\0\12",
        DEFAULT,
    ),
    Stage(
        "disable-absent",
        b"A32-Off-A",
        b"\0\13",
        None,
        None,
        b"A32-Off-A",
        b"\0\13",
        None,
    ),
    Stage(
        "disable-zero",
        b"A32-Off-Z",
        b"\0\14",
        b"\0\0",
        None,
        b"A32-Off-Z",
        b"\0\14",
        None,
    ),
    Stage(
        "reenable",
        b"A32-Reenable",
        b"\0\15",
        b"\0\4",
        None,
        b"A32-Reenable",
        b"\0\15",
        DEFAULT,
    ),
)


def settings(stage: Stage, identifier: int) -> Json:
    """Build the 304 request of a stage on the subject connection.

    Parameters
    ----------
    stage : Stage
        The stage; a field that it leaves as ``None`` is not sent.
    identifier : int
        The request identifier.

    Returns
    -------
    dict[str, typing.Any]
        The send step.
    """
    values = []
    for field, value in (
        (FIELD_NAME, stage.name),
        (FIELD_ICON, stage.icon),
        (FIELD_OPTIONS, stage.option),
        (FIELD_AUTO_RESPONSE, stage.auto),
    ):
        if value is not None:
            values.append((field, value))
    return send(packet(TYPE_SET_CLIENT_INFO, identifier, payload(values)), "subject")


def barrier(identifier: int) -> list[Json]:
    """Order both connections with an empty request and wait for each reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        For each connection, the send, the matched read and a quiet window.
    """
    result = []
    for connection in ("main", "subject"):
        result += [
            send(packet(TYPE_EMPTY_ACK, identifier, payload([])), connection),
            read(connection, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": connection, "timeout": QUIET_SECONDS},
        ]
    return result


def session_steps() -> list[Json]:
    """Log both connections in and save the main connection's view of the subject.

    Returns
    -------
    list[dict[str, typing.Any]]
        The main login and roster, the subject login and its three reads, and
        the presence update that saves the peer's user id.
    """
    steps = [
        *login(),
        send(packet(TYPE_GET_USER_ROSTER, ROSTER_ID)),
        read(match_frame={"is_reply": 1, "id": ROSTER_ID}),
    ]
    steps += [{**step, "connection": "subject"} for step in login()[:LOGIN_STEPS]]
    steps += [
        authentication(b"admin", b"mothra19", name=SUBJECT, connection="subject"),
        *[read("subject") for _ in range(SUBJECT_REPLIES)],
        read(
            "main",
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_fields={"peer_uid": FIELD_USER_ID},
        ),
    ]
    return steps


def message_text(index: int, stage: Stage) -> bytes:
    """Name the message that a stage sends, so that no two stages share one.

    Returns
    -------
    bytes
        The message text.
    """
    return f"a32-pm-{index}-{stage.label}".encode()


def stage_steps(index: int, stage: Stage) -> list[Json]:
    """Build the steps of one stage: its setting, its message and its barrier.

    Parameters
    ----------
    index : int
        The stage's position in the sequence.
    stage : Stage
        The stage.

    Returns
    -------
    list[dict[str, typing.Any]]
        The 304 request, the two presence updates, the message and its reads,
        and the barrier.
    """
    message_id = MESSAGE_BASE + index
    steps = [settings(stage, SETTINGS_BASE + index)]
    steps += [
        read("main", match_frame={"type": TYPE_PRESENCE_UPDATE}),
        read("subject", match_frame={"type": TYPE_PRESENCE_UPDATE}),
    ]
    steps += [
        variable_message(
            TYPE_SEND_PRIVATE_MESSAGE,
            message_id,
            "peer_uid",
            [(FIELD_OPTIONS, b"\0\1"), (FIELD_DATA, message_text(index, stage))],
        )
    ]
    steps += [read("main", match_frame={"is_reply": 1, "id": message_id})]
    if stage.expected_auto is not None:
        steps += [read("main", match_frame={"type": TYPE_MESSAGE_NOTIFICATION})]
    steps += [read("subject", match_frame={"type": TYPE_MESSAGE_NOTIFICATION})]
    steps += barrier(BARRIER_BASE + index)
    return steps


def observe() -> tuple[list[Json], list[Json]]:
    """Build the whole observation and the window of each stage within it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The steps, and for each stage its label, first and last step index,
        message identifier and message text.
    """
    steps = session_steps()
    windows = []
    for index, stage in enumerate(STAGES):
        start = len(steps)
        steps += stage_steps(index, stage)
        windows.append({
            "label": stage.label,
            "first": start,
            "last": len(steps) - 1,
            "pm_id": MESSAGE_BASE + index,
            "pm_text_hex": message_text(index, stage).hex(),
        })
    # Restore only the two owned session settings; closing them ends session state.
    restore = Stage("restore", SUBJECT, b"\0\1", b"\0\0", None, SUBJECT, b"\0\1", None)
    steps += [
        settings(restore, RESTORE_ID),
        read("main", match_frame={"type": TYPE_PRESENCE_UPDATE}),
        read("subject", match_frame={"type": TYPE_PRESENCE_UPDATE}),
    ]
    steps += barrier(FINAL_BARRIER_ID)
    steps += [close("subject"), close()]
    return steps, windows


def plans(runtime: Json, baseline_raw: bytes) -> dict[str, Json]:
    """Prepare the preflight, observation and postflight plans.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record; its identity fields must equal the baseline's.
    baseline_raw : bytes
        The baseline plan's bytes.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The three plans, the baseline being its own preflight and postflight.
    """
    baseline = identified_baseline(runtime, baseline_raw)
    steps, windows = observe()
    observed = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": OPERATOR,
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": GAP_IDS,
        "environment": runtime,
        "endpoints": {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
        "steps": steps,
        "expectation": {
            "case": "same-session-304-transitions",
            "windows": windows,
            "baseline_plan_sha256": BASELINE_SHA256,
            "pm_count": len(STAGES),
        },
    }
    validate_plan(observed)
    return {"preflight": baseline, "observe": observed, "postflight": baseline}


def command(*, runtime_record: str, baseline_plan: str, output: str) -> None:
    """Write the preflight, observe and postflight plans to a new directory.

    Parameters
    ----------
    runtime_record
        The JSON record of the running emulator.
    baseline_plan
        The A7 baseline plan.
    output
        The directory to create; it must not exist.
    """
    write_prepared(
        plans,
        runtime_record=runtime_record,
        baseline_plan=baseline_plan,
        output=output,
    )


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(command, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
