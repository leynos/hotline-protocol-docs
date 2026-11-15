"""Plan the steps that the native authentication cases share.

The login, pause, roster and reply-read steps and the login request of the
account lookup and login-state cases, with the fixture accounts they use.
"""

import typing as typ

from native_plan import (
    COMPLEMENT_MASK,
    FIXTURE_ICON,
    FIXTURE_VERSION,
    Action,
    packet,
    payload,
    read,
    send,
)
from native_wire_names import (
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_VERSION,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

PASSWORD = b"auth-pass"
KEY31 = b"m-auth-" + b"a" * 24
KEY32 = b"m-auth-" + b"b" * 25
ACCOUNTS: list[tuple[bytes, bytes, bytes]] = [
    (b"m-auth-cr", b"Auth CR", bytes(8)),
    (b"m-auth-\x8a", b"Auth high byte", bytes(8)),
    (KEY31, b"Auth length31", bytes(8)),
    (KEY32, b"Auth length32", bytes(8)),
    (b"m-auth-bypass", b"Auth bypass", bytes.fromhex("0000003000000000")),
]

ADMIN_PASSWORD = b"mothra19"
FIXTURE_NAME = b"auth-fixture"
FIRST_ID = 10  # the setup and cleanup requests take IDs 10 to 14, and 20 to 24
PAIR_OFFSET = 10  # a readback follows a create or delete ten IDs later
PAUSE_SECONDS = 3
QUIET_SECONDS = 3
HANDSHAKE_STEPS = 3  # connect, send the handshake and read its reply


class AuthenticationOptions(typ.TypedDict, total=False):
    """The choices of a login request; each has the default noted.

    ``name`` and ``icon`` are omitted from the request when ``None``; the
    defaults are the fixture name and icon. ``connection`` defaults to
    ``"main"`` and ``identifier`` to 1.
    """

    name: bytes | None
    icon: bytes | None
    connection: str
    identifier: int


def complement(value: bytes) -> bytes:
    """Return the byte complement in which logins and passwords are sent.

    Returns
    -------
    bytes
        ``value`` with every byte complemented.
    """
    return bytes(b ^ COMPLEMENT_MASK for b in value)


def pause() -> Action:
    """Plan the pause that lets the server settle.

    Returns
    -------
    dict[str, typing.Any]
        The ``pause`` action.
    """
    return {"op": "pause", "seconds": PAUSE_SECONDS}


def silence(connection: str) -> Action:
    """Plan a bounded silence on a named connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``expect_quiet`` action.
    """
    return {"op": "expect_quiet", "connection": connection, "timeout": QUIET_SECONDS}


def on(connection: str, steps: list[Action]) -> list[Action]:
    """Move planned steps to a named connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        Copies of ``steps`` that name ``connection``.
    """
    return [{**s, "connection": connection} for s in steps]


def answer(identifier: int, connection: str = "main") -> Action:
    """Plan the read of the reply to the request with ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The ``read_frame`` action that matches the reply.
    """
    return read(connection, match_frame={"is_reply": 1, "id": identifier})


def authentication(
    key: bytes | None,
    password: bytes,
    **options: typ.Unpack[AuthenticationOptions],
) -> Action:
    """Plan a login request on a connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``send`` action; the key, name and icon are left out when ``None``.
    """
    name = options.get("name", FIXTURE_NAME)
    icon = options.get("icon", FIXTURE_ICON)
    values = [(FIELD_PASSWORD, complement(password)), (FIELD_VERSION, FIXTURE_VERSION)]
    if key is not None:
        values.append((FIELD_LOGIN, complement(key)))
    if name is not None:
        values.append((FIELD_NAME, name))
    if icon is not None:
        values.append((FIELD_ICON, icon))
    identifier = options.get("identifier", 1)
    return send(
        packet(TYPE_LOGIN, identifier, payload(values)),
        options.get("connection", "main"),
    )


def roster(identifier: int) -> list[Action]:
    """Plan a roster request and the read of its reply on the observer.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send and the reply read.
    """
    return [
        send(packet(TYPE_GET_USER_ROSTER, identifier), "observer"),
        answer(identifier, "observer"),
    ]
