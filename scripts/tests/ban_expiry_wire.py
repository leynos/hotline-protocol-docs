"""Wire-frame builders for the identity and probe fixtures of the ban tests."""

import native_ban_expiry_cases as cases
from native_plan import packet, payload
from protocol_capture import decode_frame
from verify_native_auth import ADMIN


def frame(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # callers name the reply and error flags
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]],
    connection: str,
    *,
    is_reply: int = 0,
    error: int = 0,
) -> dict:
    """Decode one framed packet and tag it with its connection.

    Returns
    -------
    dict
        The decoded frame, with its connection and a zero action index.
    """
    result = decode_frame(
        bytes.fromhex(
            packet(kind, identifier, payload(values), reply=is_reply, error=error)
        )
    )
    result["connection"] = connection
    result["action"] = 0
    return result


def roster_record(uid: int, name: bytes) -> bytes:
    """Encode one roster record: a user identifier, four zero bytes and a name.

    Returns
    -------
    bytes
        The record as the server frames it.
    """
    return uid.to_bytes(2, "big") + b"\0\0\0\0" + len(name).to_bytes(2, "big") + name


def identity_frames(*, protected: bool = False) -> list[dict]:
    """Build the identity exchange of the main and target connections.

    Returns
    -------
    list of dict
        The frames of the exchange, in wire order.
    """
    access = cases.PROTECTED_ACCESS if protected else cases.ZERO_ACCESS
    name = cases.PROTECTED_NAME if protected else cases.ZERO_NAME
    return [
        frame(0, 1, [], "main", is_reply=1),
        frame(354, 2, [(110, ADMIN)], "main"),
        frame(109, 3, [], "main"),
        frame(0, 1, [], "target", is_reply=1),
        frame(354, 2, [(110, access)], "target"),
        frame(109, 3, [], "target"),
        frame(301, 4, [(103, b"\0\x32"), (102, name)], "main"),
        frame(
            0,
            32,
            [
                (300, roster_record(1, b"framing-fixture")),
                (300, roster_record(50, name)),
            ],
            "main",
            is_reply=1,
        ),
    ]


def probe_frames(*, success: bool) -> list[dict]:
    """Build the frames that a post-ban lookup returns, successful or refused.

    Returns
    -------
    list of dict
        The frames of the probe, in wire order.
    """
    if not success:
        return [
            frame(0, 1, [(100, cases.TEMPORARY_NOTICE)], "main", is_reply=1, error=1)
        ]
    return [
        frame(0, 1, [], "main", is_reply=1),
        frame(354, 2, [(110, cases.ZERO_ACCESS)], "main"),
        frame(109, 3, [], "main"),
        frame(0, 40, [(300, roster_record(50, cases.ZERO_NAME))], "main", is_reply=1),
    ]
