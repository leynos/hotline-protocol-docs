#!/usr/bin/env python3
"""Prepare two client-only delayed-121 default-auto observations."""

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
    TYPE_ACCEPT_AGREEMENT,
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_SEND_PRIVATE_MESSAGE,
    TYPE_USER_LEFT,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

type Json = dict[str, typ.Any]

# The names that the capture driver and the tests take from this module stay
# importable from it.
__all__ = [
    "BASELINE_SHA256",
    "DEFAULT",
    "ORACLE_SHA256",
    "barrier",
    "delayed_case",
    "load_baseline",
    "main",
    "observe",
    "packet",
    "plans",
    "roster",
]

DEFAULT = b"I'm not able to respond right now. Please try later!"
CONTROL_PORT = 15500
QUIET_SECONDS = 2
FIRST_ROSTER_ID = 10
LOGIN_STEPS = 3  # the handshake steps that precede the login request
CASE_LABELS = ("absent", "empty")
ICON_BASE = 7  # case ``n`` takes the icon of this plus ``n``
LOGIN_BASE = 2
AGREEMENT_BASE = 20
CASE_ID_STRIDE = 20  # case ``n`` numbers its requests from its base plus ``n`` strides
PM_BASE = 30
GAP_IDS = ["GAP-029", "GAP-030"]
OPERATOR = "A35 offline 121 preparation; separate live START required"


def roster(identifier: int) -> list[Json]:
    """Request the roster on the main connection and wait for its reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the matched read.
    """
    return [
        send(packet(TYPE_GET_USER_ROSTER, identifier)),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def barrier(identifier: int, subject: str) -> list[Json]:
    """Order the main and the subject connections with an empty request.

    Returns
    -------
    list[dict[str, typing.Any]]
        For each connection, the send, the matched read and a quiet window.
    """
    result = []
    for connection in ("main", subject):
        result += [
            send(packet(TYPE_EMPTY_ACK, identifier, payload([])), connection),
            read(connection, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": connection, "timeout": QUIET_SECONDS},
        ]
    return result


def subject_login(subject: str, login_id: int) -> list[Json]:
    """Log the subject connection in without a name or an icon.

    Parameters
    ----------
    subject : str
        The subject connection's name.
    login_id : int
        The login request identifier.

    Returns
    -------
    list[dict[str, typing.Any]]
        The handshake, the login and the reads of its reply and agreement.
    """
    steps = [{**step, "connection": subject} for step in login()[:LOGIN_STEPS]]
    steps += [
        authentication(
            b"admin",
            b"mothra19",
            name=None,
            icon=None,
            connection=subject,
            identifier=login_id,
        ),
        read(subject, match_frame={"is_reply": 1, "id": login_id}),
        read(subject, match_frame={"type": TYPE_LOGIN_AGREEMENT}),
    ]
    return steps


def agreement_steps(
    subject: str, values: list[tuple[int, bytes]], agreement_id: int
) -> list[Json]:
    """Accept the agreement with a delayed 121 and drain what it provokes.

    Parameters
    ----------
    subject : str
        The subject connection's name.
    values : list[tuple[int, bytes]]
        The fields of the 121.
    agreement_id : int
        The 121 request identifier; the barrier that follows uses the next one.

    Returns
    -------
    list[dict[str, typing.Any]]
        The 121 and its reply, the presence update that saves the peer's user
        id, the privileges notification and a barrier.
    """
    steps = [
        send(packet(TYPE_ACCEPT_AGREEMENT, agreement_id, payload(values)), subject)
    ]
    steps += [read(subject, match_frame={"is_reply": 1, "id": agreement_id})]
    steps += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_fields={"peer_uid": FIELD_USER_ID},
        )
    ]
    steps += [read(subject, match_frame={"type": TYPE_PRIVILEGES_NOTIFICATION})]
    # 122 depends on saved client version and banner configuration; the 500
    # barrier records it if present without making it a prerequisite.
    steps += [send(packet(TYPE_EMPTY_ACK, agreement_id + 1), subject)]
    steps += [read(subject, match_frame={"is_reply": 1, "id": agreement_id + 1})]
    return steps


def message_steps(subject: str, pm_id: int, text: bytes) -> list[Json]:
    """Send a private message to the subject and check what each side receives.

    Parameters
    ----------
    subject : str
        The subject connection's name.
    pm_id : int
        The message request identifier.
    text : bytes
        The message text.

    Returns
    -------
    list[dict[str, typing.Any]]
        The message, its reply, the feedback and the delivery, a barrier, the
        subject's close and the 302 that announces it, and a roster.
    """
    steps = [
        variable_message(
            TYPE_SEND_PRIVATE_MESSAGE,
            pm_id,
            "peer_uid",
            [(FIELD_OPTIONS, b"\0\1"), (FIELD_DATA, text)],
        )
    ]
    steps += [
        read(match_frame={"is_reply": 1, "id": pm_id}),
        read(match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        read(subject, match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
    ]
    steps += barrier(pm_id + 1, subject)
    steps += [close(subject), read(match_frame={"type": TYPE_USER_LEFT})]
    steps += roster(pm_id + 2)
    return steps


def delayed_case(label: str, index: int) -> tuple[list[Json], Json]:
    """Build one delayed-121 case.

    Parameters
    ----------
    label : str
        ``absent`` to omit field 215 from the 121, or ``empty`` to send it empty.
    index : int
        The case's position, which numbers its icon and its requests.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the detail that the observation records for the case.
    """
    subject = f"subject_{label}"
    name = f"A35-{label}-215".encode()
    icon = (ICON_BASE + index).to_bytes(2, "big")
    login_id = LOGIN_BASE + index
    agreement_id = AGREEMENT_BASE + index * CASE_ID_STRIDE
    pm_id = PM_BASE + index * CASE_ID_STRIDE
    text = f"a35-{label}-pm".encode()
    steps = subject_login(subject, login_id)
    steps += roster(FIRST_ROSTER_ID + 1 + index)
    values = [(FIELD_NAME, name), (FIELD_ICON, icon), (FIELD_OPTIONS, b"\0\4")]
    if label == "empty":
        values.append((FIELD_AUTO_RESPONSE, b""))
    steps += agreement_steps(subject, values, agreement_id)
    steps += roster(agreement_id + 2)
    steps += message_steps(subject, pm_id, text)
    return steps, {
        "label": label,
        "subject_connection": subject,
        "name_hex": name.hex(),
        "icon_hex": icon.hex(),
        "login_id": login_id,
        "agreement_id": agreement_id,
        "pm_id": pm_id,
        "pm_text_hex": text.hex(),
        "default_text_hex": DEFAULT.hex(),
    }


def observe() -> tuple[list[Json], list[Json]]:
    """Build the observation: both cases, each with its first and last step.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The steps and the detail of each case.
    """
    steps = login() + roster(FIRST_ROSTER_ID)
    expected = []
    for index, label in enumerate(CASE_LABELS):
        first = len(steps)
        case_steps, detail = delayed_case(label, index)
        steps += case_steps
        detail.update(first=first, last=len(steps) - 1)
        expected.append(detail)
    return [*steps, close()], expected


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
    steps, cases = observe()
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
            "case": "delayed-121-default-215",
            "cases": cases,
            "baseline_plan_sha256": BASELINE_SHA256,
            "pm_request_count": len(cases),
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
