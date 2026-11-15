"""Build exact native fixture messages and ordered TCP actions."""

import struct
import typing as typ

from native_wire_names import (
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_VERSION,
    FRAME_HEADER_FORMAT,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REPLY_HEX,
    HANDSHAKE_REQUEST_HEX,
    TYPE_LOGIN,
)

type Action = dict[str, typ.Any]

# Seconds a planned action may take before the recorder gives up.
READ_TIMEOUT_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 10
HANDSHAKE_TIMEOUT_SECONDS = 10
QUIET_WINDOW_SECONDS = 3
COMPLEMENT_MASK = 0xFF  # login and password travel as their byte complement
LOGIN_REQUEST_ID = 1
LOGIN_REPLY_FRAMES = 3  # the 107 reply, then the 354 and 109 notifications
FIXTURE_VERSION = b"\0\xbe"  # reported client version 190
FIXTURE_NAME = b"framing-fixture"
FIXTURE_ICON = b"\0\1"
FIXTURE_PASSWORD = b"mothra19"


def payload(fields: list[tuple[int, bytes]]) -> bytes:
    """Encode a field count followed by each field's ID, length and value.

    Returns
    -------
    bytes
        The transaction data.
    """
    return struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", k, len(v)) + v for k, v in fields
    )


class FrameOptions(typ.TypedDict, total=False):
    """The header words of a frame that a caller may set; each defaults to 0.

    ``total`` and ``size`` default to the length of the data.
    """

    total: int
    size: int
    flags: int
    reply: int
    error: int


def packet(
    kind: int,
    identifier: int,
    data: bytes = b"\0\0",
    **options: typ.Unpack[FrameOptions],
) -> str:
    """Encode one physical frame as hexadecimal.

    Returns
    -------
    str
        The header and data; ``total`` and ``size`` default to the data length.
    """
    return (
        struct.pack(
            FRAME_HEADER_FORMAT,
            options.get("flags", 0),
            options.get("reply", 0),
            kind,
            identifier,
            options.get("error", 0),
            options.get("total", len(data)),
            options.get("size", len(data)),
        )
        + data
    ).hex()


def send(value: str, connection: str = "main") -> Action:
    """Plan sending the bytes ``value`` (hexadecimal) on a connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``send`` action.
    """
    return {
        "op": "send",
        "connection": connection,
        "hex": value,
        "timeout": READ_TIMEOUT_SECONDS,
    }


def read(connection: str = "main", **options: object) -> Action:
    """Plan reading one frame, with extra action options.

    Returns
    -------
    dict[str, typing.Any]
        The ``read_frame`` action.
    """
    return {
        "op": "read_frame",
        "connection": connection,
        "timeout": READ_TIMEOUT_SECONDS,
        **options,
    }


def connect(connection: str = "main", endpoint: str = "control") -> Action:
    """Plan opening a connection to a named endpoint.

    Returns
    -------
    dict[str, typing.Any]
        The ``connect`` action.
    """
    return {
        "op": "connect",
        "connection": connection,
        "endpoint": endpoint,
        "timeout": CONNECT_TIMEOUT_SECONDS,
    }


def close(connection: str = "main") -> Action:
    """Plan closing a connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``close`` action.
    """
    return {"op": "close", "connection": connection}


def quiet() -> Action:
    """Plan a bounded silence on the main connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``expect_quiet`` action.
    """
    return {
        "op": "expect_quiet",
        "connection": "main",
        "timeout": QUIET_WINDOW_SECONDS,
    }


def eof(connection: str = "main") -> Action:
    """Plan reading until the peer closes, expecting no further bytes.

    Returns
    -------
    dict[str, typing.Any]
        The ``read_eof`` action.
    """
    return {
        "op": "read_eof",
        "connection": connection,
        "timeout": READ_TIMEOUT_SECONDS,
        "expect_hex": "",
    }


def login() -> list[Action]:
    """Plan the handshake and an administrator login that is accepted.

    Returns
    -------
    list[dict[str, typing.Any]]
        The connect, handshake, login request and three reply reads.
    """
    credentials = [
        (FIELD_LOGIN, bytes(v ^ COMPLEMENT_MASK for v in b"admin")),
        (FIELD_PASSWORD, bytes(v ^ COMPLEMENT_MASK for v in FIXTURE_PASSWORD)),
        (FIELD_VERSION, FIXTURE_VERSION),
        (FIELD_NAME, FIXTURE_NAME),
        (FIELD_ICON, FIXTURE_ICON),
    ]
    return [
        connect(),
        send(HANDSHAKE_REQUEST_HEX),
        {
            "op": "read",
            "connection": "main",
            "size": HANDSHAKE_REPLY_BYTES,
            "expect_hex": HANDSHAKE_REPLY_HEX,
            "timeout": HANDSHAKE_TIMEOUT_SECONDS,
        },
        send(packet(TYPE_LOGIN, LOGIN_REQUEST_ID, payload(credentials))),
        *[read() for _ in range(LOGIN_REPLY_FRAMES)],
    ]
