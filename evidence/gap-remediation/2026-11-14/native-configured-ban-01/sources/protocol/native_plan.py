"""Build exact native fixture messages and ordered TCP actions."""

import struct


def payload(fields: list[tuple[int, bytes]]) -> bytes:
    """Encode a list of field identifiers and values as a protocol payload."""
    return struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", k, len(v)) + v for k, v in fields
    )


def packet(
    kind: int,
    identifier: int,
    data: bytes = b"\0\0",
    *,
    total: int | None = None,
    size: int | None = None,
    flags: int = 0,
    reply: int = 0,
    error: int = 0,
) -> str:
    """Encode a protocol packet header and payload as hexadecimal text."""
    return (
        struct.pack(
            ">BBHIIII",
            flags,
            reply,
            kind,
            identifier,
            error,
            len(data) if total is None else total,
            len(data) if size is None else size,
        )
        + data
    ).hex()


def send(value: str, connection: str = "main") -> dict:
    """Return the plan step that sends the given hexadecimal bytes."""
    return {"op": "send", "connection": connection, "hex": value, "timeout": 30}


def read(connection: str = "main", **options) -> dict:
    """Return the plan step that reads one frame."""
    return {"op": "read_frame", "connection": connection, "timeout": 30, **options}


def connect(connection: str = "main", endpoint: str = "control") -> dict:
    """Return the plan step that opens a connection to an endpoint."""
    return {
        "op": "connect",
        "connection": connection,
        "endpoint": endpoint,
        "timeout": 10,
    }


def close(connection: str = "main") -> dict:
    """Return the plan step that closes a connection."""
    return {"op": "close", "connection": connection}


def quiet() -> dict:
    """Return the plan step that expects no traffic for a short time."""
    return {"op": "expect_quiet", "connection": "main", "timeout": 3}


def eof(connection: str = "main") -> dict:
    """Return the plan step that expects the peer to close the connection."""
    return {"op": "read_eof", "connection": connection, "timeout": 30, "expect_hex": ""}


def login() -> list[dict]:
    """Return the plan steps that connect, handshake and log in as the admin account."""
    credentials = [
        (105, bytes(v ^ 255 for v in b"admin")),
        (106, bytes(v ^ 255 for v in b"mothra19")),
        (160, b"\0\xbe"),
        (102, b"framing-fixture"),
        (104, b"\0\1"),
    ]
    return [
        connect(),
        send("54525450484f544c00010002"),
        {
            "op": "read",
            "connection": "main",
            "size": 8,
            "expect_hex": "5452545000000000",
            "timeout": 10,
        },
        send(packet(107, 1, payload(credentials))),
        read(),
        read(),
        read(),
    ]
