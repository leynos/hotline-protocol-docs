"""Control-only plans for one configured-address ban application fixture."""

import hashlib
import json
from pathlib import Path  # ruff: ignore[typing-only-standard-library-import]  # write_plans is inspected at run time

from native_auth_cases import authentication, complement
from native_ban_control_cases import A7_SHA, FILE, ZERO
from native_plan import close, eof, login, packet, payload, read, send
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    TYPE_CREATE_ACCOUNT,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import ORACLE_SHA256, validate_plan

KEY = b"m-ban-apply-only"
PASSWORD = b"apply-ban-pass"
NAME = b"Ban Apply Target"
ADDRESS = b"10.0.2.2"
# The request type that names a user by field 103; native_wire_names has no name.
TYPE_USER_NAMED_REQUEST = 303
# The primary server's ports, which a control-only plan must not use.
PRIMARY_PORTS = {15500, 15501}
# The lowest and the highest port that an owned lab endpoint may use.
MIN_OWNED_PORT = 1024
MAX_OWNED_PORT = 65534
# The offset and size of the admin UID that the roster reply carries.
ADMIN_UID_OFFSET = 26
ADMIN_UID_SIZE = 2


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[dict]:
    """Return the send of one request and the read of its matching reply.

    Parameters
    ----------
    kind : int
        The transaction type of the request.
    identifier : int
        The request identifier, which the reply echoes.
    values : list[tuple[int, bytes]]
        The field identifiers and values of the request.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step followed by the read step.
    """
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def tail_eof(connection: str) -> dict:
    """Return an end-of-file step without its expected bytes.

    Parameters
    ----------
    connection : str
        The name of the connection that is read to its end.

    Returns
    -------
    dict[str, typing.Any]
        The end-of-file step.
    """
    step = eof(connection)
    del step["expect_hex"]
    return step


def plans() -> dict[str, list[dict]]:
    """Return the four source plans of the fixture, keyed by their names.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The steps of the readiness, guard, seed and held-apply plans.
    """
    ready = login()
    ready += exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
    ready += exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    ready += exchange(TYPE_GET_FILE_INFO, 12, [(FIELD_FILE_NAME, FILE)])
    ready += [
        send(packet(TYPE_GET_USER_ROSTER, 13)),
        read(
            match_frame={"is_reply": 1, "id": 13},
            save={
                "name": "admin_uid",
                "offset": ADMIN_UID_OFFSET,
                "size": ADMIN_UID_SIZE,
            },
        ),
        send(
            packet(TYPE_USER_NAMED_REQUEST, 14, payload([(FIELD_USER_ID, b"\0\0")]))[
                :-4
            ]
            + "{admin_uid}"
        ),
        read(match_frame={"is_reply": 1, "id": 14}),
        close(),
    ]
    guard = login() + exchange(TYPE_GET_ACCOUNT, 30, [(FIELD_LOGIN, KEY)]) + [close()]
    seed = login() + exchange(
        TYPE_CREATE_ACCOUNT,
        31,
        [
            (FIELD_LOGIN, complement(KEY)),
            (FIELD_PASSWORD, complement(PASSWORD)),
            (FIELD_NAME, NAME),
            (FIELD_ACCESS_BITMAP, ZERO),
        ],
    )
    seed += [*exchange(TYPE_GET_ACCOUNT, 32, [(FIELD_LOGIN, KEY)]), close()]
    held = login()
    held += [{**step, "connection": "target"} for step in login()[:3]]
    held += [authentication(KEY, PASSWORD, name=NAME, connection="target")]
    held += [read("target"), read("target"), read("target")]
    held += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_field={"name": "target_uid", "id": FIELD_USER_ID},
        )
    ]
    held += exchange(TYPE_GET_USER_ROSTER, 32, [])
    # The tail is part of this same source plan and resulting report.
    held += [
        read(match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        read("target", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        tail_eof("main"),
        tail_eof("target"),
        close(),
        close("target"),
    ]
    return {"readiness": ready, "guard": guard, "seed": seed, "held-apply": held}


def write_plans(output: Path, environment: dict, port: int) -> dict[str, str]:
    """Write the four source plans to ``output`` and return their digests.

    Parameters
    ----------
    output : pathlib.Path
        The directory to create; it must not exist.
    environment : dict[str, typing.Any]
        The runtime record of the lab emulator, which must name the A7 source plan.
    port : int
        The control port of the owned lab endpoint.

    Returns
    -------
    dict[str, str]
        The SHA-256 digest of each written plan, keyed by its name.

    Raises
    ------
    ValueError
        If the port is not an owned lab port, or the A7 source-plan hash differs.
    """
    if port in PRIMARY_PORTS or not MIN_OWNED_PORT <= port <= MAX_OWNED_PORT:
        message = "Control endpoint must be an owned lab port"
        raise ValueError(message)
    if environment.get("source_a7_sha256") != A7_SHA:
        message = "Original A7 source-plan hash differs"
        raise ValueError(message)
    output.mkdir(parents=True, exist_ok=False)
    result = {}
    for name, steps in plans().items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "C64 configured-address ban application operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-044"],
            "environment": {
                **environment,
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            },
            "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
            "steps": steps,
            "expectation": {
                "case": name,
                "owned_key_hex": KEY.hex(),
                "address_hex": ADDRESS.hex(),
            },
        }
        validate_plan(plan)
        encoded = (json.dumps(plan, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(encoded)
        result[name] = hashlib.sha256(encoded).hexdigest()
    return result
