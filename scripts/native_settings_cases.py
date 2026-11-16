#!/usr/bin/env python3
"""Prepare ten bounded native 304/113 width, presence and duplicate probes."""

import json
import typing as typ
from pathlib import Path

from native_auth_cases import authentication
from native_plan import close, login, packet, payload, read, send
from native_wire_names import (
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_PRESENCE_UPDATE,
    TYPE_SEND_PRIVATE_MESSAGE,
    TYPE_SET_CLIENT_INFO,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

type Json = dict[str, typ.Any]

CASES: dict[str, tuple[list[bytes] | None, int | None]] = {
    "absent": (None, 0),
    "empty": ([b""], 0),
    "zero-two": ([b"\0\0"], 0),
    "one-byte-refuse": ([b"\x01"], 1),
    "two-byte-auto": ([b"\0\x04"], 4),
    "three-byte-default": ([b"\0\0\x01"], 0),
    "four-byte-both": ([b"\0\0\0\x05"], 5),
    "five-byte-prefix": ([b"\0\0\0\x01\xff"], 1),
    "duplicate-refuse-auto": ([b"\0\x01", b"\0\x04"], None),
    "duplicate-auto-refuse": ([b"\0\x04", b"\0\x01"], None),
}

NAME = b"settings25"
ICON = b"\0\x07"
LAB_LOGIN = (b"admin", b"mothra19")  # the lab account's login and password
DUPLICATE_REVERSED = "duplicate-auto-refuse"  # also interleaves the known fields
DUPLICATE_VALUES = 2  # the duplicate cases carry two field-113 values
UID_VARIABLE = "{subject_uid}"
UID_BYTES = 2
FIELD_ID_BYTES = 2
FIELD_SIZE_BYTES = 2
FRAME_HEADER_HEX_CHARS = 40  # the 20-byte frame header of a built packet
FIELD_COUNT_BYTES = 2
FIELD_COUNT_HEX = "0003"  # the PM carries a user id, an option and the text
SUBJECT_LOGIN_READS = 3  # the 107 reply, then the 354 and 109 notifications
SETTINGS_ID = 40
RESTORE_ID = 80
PM_ID = 70
CONTROL_PORT = 15500
BARRIER_IDS = (41, 71, 72, 81, 82)  # main, main, subject, main, subject
GAP_IDS = ["GAP-015", "GAP-016", "GAP-017", "GAP-084"]
OPERATOR = "delegated native settings operator"


def pm_request(identifier: int, text: bytes) -> Json:
    """Substitute the saved native two-byte subject UID into an exact TLV.

    Parameters
    ----------
    identifier : int
        The request identifier.
    text : bytes
        The message text.

    Returns
    -------
    dict[str, typing.Any]
        The send step whose user id is the ``subject_uid`` variable.
    """
    fields = [
        (FIELD_USER_ID, UID_VARIABLE),
        (FIELD_OPTIONS, b"\0\x01".hex()),
        (FIELD_DATA, text.hex()),
    ]

    def length(field: int, value: str) -> int:
        """Measure a field's value; the variable stands for two bytes.

        Returns
        -------
        int
            The value's byte length.
        """
        return UID_BYTES if field == FIELD_USER_ID else len(bytes.fromhex(value))

    size = FIELD_COUNT_BYTES + sum(
        FIELD_ID_BYTES + FIELD_SIZE_BYTES + length(field, value)
        for field, value in fields
    )
    header = packet(TYPE_SEND_PRIVATE_MESSAGE, identifier, bytes(size))[
        :FRAME_HEADER_HEX_CHARS
    ]
    body = FIELD_COUNT_HEX + "".join(
        field.to_bytes(FIELD_ID_BYTES, "big").hex()
        + length(field, value).to_bytes(FIELD_SIZE_BYTES, "big").hex()
        + value
        for field, value in fields
    )
    return send(header + body)


def subject_login() -> list[Json]:
    """Log the subject connection in as the settings account.

    Returns
    -------
    list[dict[str, typing.Any]]
        The handshake steps, the login and the three reads of its replies.
    """
    steps = [{**step, "connection": "subject"} for step in login()[:3]]
    steps += [
        authentication(
            *LAB_LOGIN,
            name=NAME,
            icon=ICON,
            connection="subject",
        )
    ]
    steps += [read("subject") for _ in range(SUBJECT_LOGIN_READS)]
    return steps


def barrier(connection: str, identifier: int) -> list[Json]:
    """Order the connection with an empty request and wait for its reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the matched read.
    """
    return [
        send(packet(TYPE_EMPTY_ACK, identifier), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def settings_fields(name: str, values: list[bytes] | None) -> list[tuple[int, bytes]]:
    """Build the fields of the 304 request for one case.

    Parameters
    ----------
    name : str
        The case name; the reversed duplicate case interleaves the known fields.
    values : list[bytes] | None
        The field-113 values, or ``None`` when the field is absent.

    Returns
    -------
    list[tuple[int, bytes]]
        The name and icon, then each field-113 value.
    """
    fields = [(FIELD_NAME, NAME), (FIELD_ICON, ICON)]
    if values is not None:
        fields += [(FIELD_OPTIONS, values[0])]
        if len(values) == DUPLICATE_VALUES:
            # The second order also interleaves the known icon/name fields.
            if name == DUPLICATE_REVERSED:
                fields += [(FIELD_ICON, ICON), (FIELD_NAME, NAME)]
            fields += [(FIELD_OPTIONS, values[1])]
    return fields


def restore_step() -> Json:
    """Build the 304 request that clears field 113 again.

    Returns
    -------
    dict[str, typing.Any]
        The send step on the subject connection.
    """
    fields = [(FIELD_NAME, NAME), (FIELD_ICON, ICON), (FIELD_OPTIONS, b"\0\0")]
    return send(
        packet(TYPE_SET_CLIENT_INFO, RESTORE_ID, payload(fields)),
        "subject",
    )


def update(save_fields: Json | None = None) -> Json:
    """Wait for a 301 presence update on the main connection.

    Parameters
    ----------
    save_fields : dict[str, typing.Any] | None
        The fields to save from the frame, if any.

    Returns
    -------
    dict[str, typing.Any]
        The read step.
    """
    match = {"type": TYPE_PRESENCE_UPDATE}
    if save_fields is None:
        return read(match_frame=match)
    return read(match_frame=match, save_fields=save_fields)


def case_steps(fields: list[tuple[int, bytes]], text: bytes) -> list[Json]:
    """Build the steps of one case from its 304 fields and PM text.

    Returns
    -------
    list[dict[str, typing.Any]]
        Both logins, the setting, the message, the restore and both closes.
    """
    steps = login() + subject_login()
    steps += [update(save_fields={"subject_uid": FIELD_USER_ID})]
    steps += [
        send(packet(TYPE_SET_CLIENT_INFO, SETTINGS_ID, payload(fields)), "subject")
    ]
    steps += [update(), *barrier("main", BARRIER_IDS[0])]
    steps += [
        pm_request(PM_ID, text),
        read(match_frame={"is_reply": 1, "id": PM_ID}),
    ]
    steps += [*barrier("main", BARRIER_IDS[1]), *barrier("subject", BARRIER_IDS[2])]
    steps += [restore_step(), update()]
    steps += [*barrier("main", BARRIER_IDS[3]), *barrier("subject", BARRIER_IDS[4])]
    steps += [close("subject"), close()]
    return steps


def cases() -> dict[str, tuple[list[Json], Json]]:
    """Build every case's steps and expectation.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case, by name, in table order.
    """
    result = {}
    for number, (name, (values, flags)) in enumerate(CASES.items(), 1):
        text = f"settings25-pm-{number:02d}".encode()
        result[name] = (
            case_steps(settings_fields(name, values), text),
            {
                "case": name,
                "expected_flags": flags,
                "duplicate": flags is None,
                "pm_text": text.hex(),
                "oracle_sha256": ORACLE_SHA256,
            },
        )
    return result


def plan_of(environment: Json, steps: list[Json], expectation: Json) -> Json:
    """Assemble one case's plan around the recorded environment.

    Returns
    -------
    dict[str, typing.Any]
        The plan, before it is validated.
    """
    return {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": OPERATOR,
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "gap_ids": GAP_IDS,
        "endpoints": {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
        "expectation": expectation,
        "steps": steps,
    }


def command(*, runtime_record: str, output: str) -> None:
    """Write one validated plan per case to a new directory.

    Parameters
    ----------
    runtime_record
        The JSON record of the running emulator.
    output
        The directory to create; it must not exist.
    """
    environment = json.loads(Path(runtime_record).read_text(encoding="utf-8"))
    target = Path(output)
    target.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in cases().items():
        plan = plan_of(environment, steps, expectation)
        validate_plan(plan)
        (target / f"{name}.json").write_text(json.dumps(plan, indent=2) + "\n")
    print(f"Prepared {len(CASES)} native settings cases")


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
