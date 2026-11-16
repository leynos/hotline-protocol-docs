#!/usr/bin/env python3
"""Generate bounded native 303 diagnostic observations for one owned account."""

import json
from pathlib import Path

from native_auth_cases import complement
from native_live_account_cases import account_values, subject
from native_mkdir_cases import exchange
from native_plan import close, login, packet, read, send
from native_wire_names import (
    FIELD_LOGIN,
    FIELD_USER_ID,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_GET_USER_ROSTER,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import UsageError, run

KEY = b"m-diag31-zero"
PASSWORD = b"diag-pass31"
NAME = b"Diag31-\x8e"
ACCESS = bytes(8)
UID_BYTES = 2  # the measured width of the UID in field 103
SCHEMA_VERSION = 1
CONTROL_PORT = 15500


def diagnostic_request(connection: str, identifier: int, uid: str | bytes) -> dict:
    """Build a 303 whose field 103 has the measured two-byte UID width.

    Parameters
    ----------
    connection : str
        The connection that sends the request.
    identifier : int
        The transaction identifier of the request.
    uid : str | bytes
        Either the name of a current-session UID or the raw UID bytes.

    Returns
    -------
    dict
        The planned send step.

    Raises
    ------
    ValueError
        If a name other than a current-session UID is given, or the raw UID is
        not exactly two bytes long.
    """
    if isinstance(uid, str):
        if uid not in {"target_uid", "admin_uid"}:
            message = "Only current-session UIDs may be substituted"
            raise ValueError(message)
        content = "{" + uid + "}"
    elif len(uid) == UID_BYTES:
        content = uid.hex()
    else:
        message = "A diagnostic UID must be exactly two bytes"
        raise ValueError(message)
    return send(
        packet(303, identifier, bytes(8))[:40] + "000100670002" + content, connection
    )


def suites(stale_uid: bytes | None = None) -> dict[str, tuple[list[dict], dict]]:
    """Plan the preflight, seed, observation, self and cleanup suites.

    Parameters
    ----------
    stale_uid : bytes | None
        The optional two-byte UID that the stale-UID request names.

    Returns
    -------
    dict[str, tuple[list[dict], dict]]
        The steps and expectation of each suite, by its name.
    """
    preflight = login() + exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
    preflight += exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
    preflight += [*exchange(TYPE_GET_USER_ROSTER, 12, []), close()]
    seed = login() + exchange(
        TYPE_CREATE_ACCOUNT, 10, account_values(KEY, PASSWORD, NAME, ACCESS)
    )
    seed += [*exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)]), close()]
    observe = login() + subject("zero", KEY, PASSWORD, 31)
    observe += [
        read(
            "main",
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_fields={"target_uid": FIELD_USER_ID},
        ),
        diagnostic_request("main", 10, "target_uid"),
        read(match_frame={"is_reply": 1, "id": 10}),
        diagnostic_request("zero", 11, "target_uid"),
        read("zero", match_frame={"is_reply": 1, "id": 11}),
        diagnostic_request("main", 12, b"\xff\xff"),
        read(match_frame={"is_reply": 1, "id": 12}),
    ]
    if stale_uid is not None:
        observe += [
            diagnostic_request("main", 13, stale_uid),
            read(match_frame={"is_reply": 1, "id": 13}),
        ]
    observe += [*exchange(TYPE_GET_USER_ROSTER, 20, []), close("zero"), close()]
    self_case = [
        *login(),
        send(packet(TYPE_GET_USER_ROSTER, 10)),
        read(
            match_frame={"is_reply": 1, "id": 10},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
        diagnostic_request("main", 11, "admin_uid"),
        read(match_frame={"is_reply": 1, "id": 11}),
        close(),
    ]
    cleanup = login() + exchange(
        TYPE_DELETE_ACCOUNT, 10, [(FIELD_LOGIN, complement(KEY))]
    )
    cleanup += exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
    cleanup += [*exchange(TYPE_ENUMERATE_ACCOUNTS, 12, []), close()]
    return {
        "preflight": (preflight, {"kind": "diagnostic-preflight"}),
        "seed": (seed, {"kind": "diagnostic-seed"}),
        "observe": (observe, {"kind": "diagnostic-observe"}),
        "self": (self_case, {"kind": "diagnostic-self"}),
        "cleanup": (cleanup, {"kind": "diagnostic-cleanup"}),
    }


def parse_stale_uid(text: str) -> bytes:
    """Parse the hexadecimal value of ``--stale-uid``.

    Parameters
    ----------
    text : str
        The hexadecimal text given on the command line.

    Returns
    -------
    bytes
        The two bytes of the stale UID.

    Raises
    ------
    UsageError
        If the text is not hexadecimal or not exactly two bytes long.
    """
    try:
        value = bytes.fromhex(text)
    except ValueError as error:
        # argparse's wording, kept byte for byte, including its "<lambda>" name
        message = f"argument --stale-uid: invalid <lambda> value: {text!r}"
        raise UsageError(message) from error
    if len(value) != UID_BYTES:
        message = "--stale-uid requires exactly two bytes"
        raise UsageError(message)
    return value


def write_plans(
    *, runtime_record: str, output: str, stale_uid: str | None = None
) -> None:
    """Write one plan per suite into a new output directory.

    The stale UID is parsed first, then the runtime record is read, then the
    output directory is created, which must not exist yet.

    Parameters
    ----------
    runtime_record : str
        The JSON runtime record of the environment.
    output : str
        The new directory that receives one plan per suite.
    stale_uid : str | None
        The optional hexadecimal UID of the stale-UID request.
    """
    stale = None if stale_uid is None else parse_stale_uid(stale_uid)
    runtime = json.loads(Path(runtime_record).read_text(encoding="utf-8"))
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in suites(stale).items():
        plan = {
            "schema_version": SCHEMA_VERSION,
            "profile": "native-mac-oracle",
            "operator": "delegated native diagnostic operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-037"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
            "steps": steps,
            "expectation": expectation,
        }
        validate_plan(plan)
        (directory / f"{name}.json").write_text(
            json.dumps(plan, indent=2) + "\n", encoding="utf-8"
        )


def main() -> None:
    """Generate the bounded native 303 diagnostic plans from the command line."""
    run(write_plans, __doc__)


if __name__ == "__main__":
    main()
