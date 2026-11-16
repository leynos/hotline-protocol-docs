"""Plans for one isolated, control-only native permanent-ban observation.

This module stays one file: ``native_settings_persistence_cases`` records the
SHA-256 of this file in the plans it writes, and ``native_settings_persistence``
hashes it again at capture, so its bytes must mean one module.
"""

import hashlib
import json
import typing as typ

from native_auth_cases import authentication, complement
from native_plan import close, eof, login, packet, payload, read, send
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_OPTIONS,
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

if typ.TYPE_CHECKING:
    from pathlib import Path

type Json = dict[str, typ.Any]

KEY = b"m-ban52-only"
PASSWORD = b"ban52-pass"
NAME = b"Ban52 Target"
ZERO = bytes(8)
FILE = b"mothra-race-fixture"
A7_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"

TYPE_USER_NAMED_REQUEST = 303  # the request whose target is field 103
TYPE_BAN_USER = 110  # the disconnect or ban request; not named in native_wire_names
BAN_OPTION = b"\0\2"  # the permanent-ban option of the 110
LOGIN_STEPS = 3  # the handshake steps that precede the login request
TARGET_REPLIES = 3  # the 107 reply, then the 354 and 109 notifications
READINESS_ID = 10  # the readiness plan's first request
FILE_LIST_ID = 11
FILE_INFO_ID = 12
ROSTER_ID = 13
USER_NAMED_ID = 14
GUARD_ID = 30
SEED_ID = 31
SEED_READBACK_ID = 32
BAN_ROSTER_ID = 32
BAN_ID = 33
POST_ENUMERATE_ID = 40
PRIMARY_PORTS = {15500, 15501}  # the bridge ports of the primary lab
LOWEST_LAB_PORT = 1024
HIGHEST_LAB_PORT = 65534
ZERO_UID_FIELD_HEX = "006700020000"  # field 103, two bytes of zero
TARGET_UID_FIELD_HEX = "00670002{target_uid}"  # the same with the saved user id
UID_HEX_CHARS = 4  # the two-byte value that the 303 request carries, in hex
ADMIN_UID_OFFSET = 26  # where the admin's user id sits in the 300 reply
UID_SIZE = 2
GAP_IDS = ["GAP-044"]
OPERATOR = "C52 isolated ban-control operator"
CONTROL_HOST = "127.0.0.1"


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[Json]:
    """Send one request and read the reply that carries its identifier.

    Parameters
    ----------
    kind : int
        The transaction type.
    identifier : int
        The request identifier.
    values : list[tuple[int, bytes]]
        The fields of the request.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the matched read.
    """
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def read_state(first: int) -> list[Json]:
    """Read the account list, the file list, the file info and the roster.

    Parameters
    ----------
    first : int
        The identifier of the account enumeration; the others follow it.

    Returns
    -------
    list[dict[str, typing.Any]]
        The four exchanges.
    """
    steps = exchange(TYPE_ENUMERATE_ACCOUNTS, first, [])
    steps += exchange(TYPE_LIST_FILES, first + 1, [(FIELD_FILE_PATH, b"\0\0")])
    steps += exchange(TYPE_GET_FILE_INFO, first + 2, [(FIELD_FILE_NAME, FILE)])
    return steps + exchange(TYPE_GET_USER_ROSTER, first + 3, [])


def readiness_plan() -> list[Json]:
    """Plan the readiness check: login, the lab's state, and the admin's name.

    The plan is the login, five correlated exchanges and the close, 18 steps in
    all, and carries no 202 or HTXF.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    ready = login()
    ready += exchange(TYPE_ENUMERATE_ACCOUNTS, READINESS_ID, [])
    ready += exchange(TYPE_LIST_FILES, FILE_LIST_ID, [(FIELD_FILE_PATH, b"\0\0")])
    ready += exchange(TYPE_GET_FILE_INFO, FILE_INFO_ID, [(FIELD_FILE_NAME, FILE)])
    ready += [
        send(packet(TYPE_GET_USER_ROSTER, ROSTER_ID)),
        read(
            match_frame={"is_reply": 1, "id": ROSTER_ID},
            save={"name": "admin_uid", "offset": ADMIN_UID_OFFSET, "size": UID_SIZE},
        ),
    ]
    named = packet(
        TYPE_USER_NAMED_REQUEST, USER_NAMED_ID, payload([(FIELD_USER_ID, b"\0\0")])
    )
    ready += [
        send(named[:-UID_HEX_CHARS] + "{admin_uid}"),
        read(match_frame={"is_reply": 1, "id": USER_NAMED_ID}),
    ]
    return [*ready, close()]


def guard_plan() -> list[Json]:
    """Plan the guard: the owned account must be absent.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    return (
        login() + exchange(TYPE_GET_ACCOUNT, GUARD_ID, [(FIELD_LOGIN, KEY)]) + [close()]
    )


def seed_plan() -> list[Json]:
    """Plan the seed: create the owned zero-access account and read it back.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    fields = [
        (FIELD_LOGIN, complement(KEY)),
        (FIELD_PASSWORD, complement(PASSWORD)),
        (FIELD_NAME, NAME),
        (FIELD_ACCESS_BITMAP, ZERO),
    ]
    seed = login() + exchange(TYPE_CREATE_ACCOUNT, SEED_ID, fields)
    return (
        seed
        + exchange(TYPE_GET_ACCOUNT, SEED_READBACK_ID, [(FIELD_LOGIN, KEY)])
        + [close()]
    )


def ban_plan() -> list[Json]:
    """Plan the ban: the owned account joins, is banned, and the state is read.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    ban = login() + [{**step, "connection": "target"} for step in login()[:LOGIN_STEPS]]
    ban += [authentication(KEY, PASSWORD, name=NAME, connection="target")]
    ban += [read("target") for _ in range(TARGET_REPLIES)]
    ban += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_field={"name": "target_uid", "id": FIELD_USER_ID},
        )
    ]
    ban += exchange(TYPE_GET_USER_ROSTER, BAN_ROSTER_ID, [])
    request = packet(
        TYPE_BAN_USER,
        BAN_ID,
        payload([(FIELD_USER_ID, b"\0\0"), (FIELD_OPTIONS, BAN_OPTION)]),
    )
    ban += [send(request.replace(ZERO_UID_FIELD_HEX, TARGET_UID_FIELD_HEX))]
    ban += [
        read("target", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        eof("target"),
    ]
    ban += [read(), read(), close("target")]
    return ban + read_state(POST_ENUMERATE_ID) + [close()]


def probe_plan() -> list[Json]:
    """Plan the probe: a fresh login of the banned account.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    return [
        *login()[:LOGIN_STEPS],
        authentication(KEY, PASSWORD, name=NAME),
        read(match_frame={"is_reply": 1, "id": 1}),
        close(),
    ]


def plans() -> dict[str, list[Json]]:
    """Build the five plans.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The readiness, guard, seed, ban and probe plans, in that order.
    """
    return {
        "readiness": readiness_plan(),
        "guard": guard_plan(),
        "seed": seed_plan(),
        "ban": ban_plan(),
        "probe": probe_plan(),
    }


def plan_of(name: str, steps: list[Json], environment: Json, port: int) -> Json:
    """Assemble one plan around the recorded environment.

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
        "gap_ids": GAP_IDS,
        "environment": {
            **environment,
            "fixture_profile": "control-only",
            "full_file_baseline": "not_exercised",
        },
        "endpoints": {"control": {"host": CONTROL_HOST, "port": port}},
        "steps": steps,
        "expectation": {"case": name, "owned_key_hex": KEY.hex()},
    }


def write_plans(output: Path, environment: Json, port: int) -> dict[str, str]:
    """Write the five plans to a new directory and digest each file.

    Parameters
    ----------
    output : pathlib.Path
        The directory to create; it must not exist.
    environment : dict[str, typing.Any]
        The runtime record, which must carry the original A7 source-plan hash.
    port : int
        The control port: an owned lab port, never one of the primary bridge's.

    Returns
    -------
    dict[str, str]
        The SHA-256 of each plan file, by plan name.

    Raises
    ------
    ValueError
        If the port is not an owned lab port, or the record's A7 hash differs.
    """
    if port in PRIMARY_PORTS or not LOWEST_LAB_PORT <= port <= HIGHEST_LAB_PORT:
        message = "Control endpoint must be an owned lab port"
        raise ValueError(message)
    if environment.get("source_a7_sha256") != A7_SHA:
        message = "Original A7 source-plan hash differs"
        raise ValueError(message)
    output.mkdir(parents=True, exist_ok=False)
    result = {}
    for name, steps in plans().items():
        plan = plan_of(name, steps, environment, port)
        validate_plan(plan)
        encoded = (json.dumps(plan, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(encoded)
        result[name] = hashlib.sha256(encoded).hexdigest()
    return result
