"""Check the control frames that each D1 console client exchanged with the server."""

import typing as typ

from native_wire_names import (
    FIELD_DATA,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REPLY_HEX,
    HANDSHAKE_REQUEST_HEX,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_mac_peer_first_session import field_map, parse_frames, require
from verify_native_console_broadcast_capture import NAMES, connection

type Report = dict[str, typ.Any]
type Frame = dict[str, typ.Any]

TEXT_CONSOLE = b"D1-console-message"
TEXT_BEFORE = b"D1-client-before"
TEXT_AFTER = b"D1-client-after"
TYPE_BROADCAST = 355  # the console broadcast notification of the D1 corpus
FIELD_ACTIVATION = 104  # the activation state that a waiting client sends
USER_ID_BYTES = 2  # the two-byte user identifier of a broadcast sender
HANDSHAKE_REQUEST_BYTES = 12  # the request that a client sends before its frames

EXPECTED_OUT: dict[str, list[int]] = {
    "ConsoleSender": [TYPE_LOGIN, TYPE_BROADCAST, TYPE_BROADCAST],
    "ConsoleRefuse": [TYPE_LOGIN],
    "ConsoleWaiting": [TYPE_LOGIN, TYPE_ACCEPT_AGREEMENT],
    "ConsoleUnauth": [],
}
EXPECTED_IN: dict[str, list[int]] = {
    "ConsoleSender": [
        0,
        TYPE_PRIVILEGES_NOTIFICATION,
        TYPE_LOGIN_AGREEMENT,
        TYPE_PRESENCE_UPDATE,
        0,
        TYPE_MESSAGE_NOTIFICATION,
        TYPE_PRESENCE_UPDATE,
        0,
    ],
    "ConsoleRefuse": [
        0,
        TYPE_PRIVILEGES_NOTIFICATION,
        TYPE_LOGIN_AGREEMENT,
        TYPE_BROADCAST,
        TYPE_MESSAGE_NOTIFICATION,
        TYPE_PRESENCE_UPDATE,
        TYPE_BROADCAST,
    ],
    "ConsoleWaiting": [
        0,
        TYPE_LOGIN_AGREEMENT,
        0,
        TYPE_PRIVILEGES_NOTIFICATION,
        TYPE_BANNER_METADATA,
        TYPE_BROADCAST,
    ],
    "ConsoleUnauth": [],
}


def _check_handshake(sent: bytes, received: bytes) -> None:
    """Check the handshake request and reply of one client connection.

    Parameters
    ----------
    sent : bytes
        The bytes that the client sent.
    received : bytes
        The bytes that the client received.
    """
    require(
        sent.startswith(bytes.fromhex(HANDSHAKE_REQUEST_HEX)),
        "Handshake request differs",
    )
    require(
        received.startswith(bytes.fromhex(HANDSHAKE_REPLY_HEX)),
        "Handshake reply differs",
    )


def _check_sequence(name: str, outbound: list[Frame], inbound: list[Frame]) -> None:
    """Check the frame types and the statuses of one client connection.

    Parameters
    ----------
    name : str
        The client connection name.
    outbound : list[dict[str, typing.Any]]
        The frames that the client sent.
    inbound : list[dict[str, typing.Any]]
        The frames that the client received.
    """
    require(
        [f["type"] for f in outbound] == EXPECTED_OUT[name],
        f"Outbound frame sequence differs: {name}",
    )
    require(
        [f["type"] for f in inbound] == EXPECTED_IN[name],
        f"Inbound frame sequence differs: {name}",
    )
    require(all(f["error"] == 0 for f in inbound), "Unexpected frame status")


def _check_sender(outbound: list[Frame], inbound: list[Frame]) -> None:
    """Check the broadcast requests of the sending client and their replies.

    Parameters
    ----------
    outbound : list[dict[str, typing.Any]]
        The frames that the sender sent.
    inbound : list[dict[str, typing.Any]]
        The frames that the sender received.
    """
    require(
        [field_map(f) for f in outbound[1:]]
        == [{FIELD_DATA: TEXT_BEFORE}, {FIELD_DATA: TEXT_AFTER}],
        "Client broadcast requests differ",
    )
    require(
        all(
            f["is_reply"] == 1 and f["id"] == identifier
            for f, identifier in zip((inbound[4], inbound[7]), (2, 3), strict=True)
        ),
        "Sender 355 ACK differs",
    )


def _check_client(name: str, outbound: list[Frame], inbound: list[Frame]) -> None:
    """Check the client-specific requests of one connection.

    Parameters
    ----------
    name : str
        The client connection name.
    outbound : list[dict[str, typing.Any]]
        The frames that the client sent.
    inbound : list[dict[str, typing.Any]]
        The frames that the client received.
    """
    if name == "ConsoleSender":
        _check_sender(outbound, inbound)
    if name == "ConsoleWaiting":
        require(
            field_map(outbound[1])
            == {FIELD_NAME: b"ConsoleWaiting", FIELD_ACTIVATION: b"\x00\x01"},
            "Waiting activation differs",
        )
    if name == "ConsoleRefuse":
        require(
            field_map(outbound[0])[FIELD_OPTIONS] == b"\x00\x03",
            "Refuse options differ",
        )
    if name != "ConsoleUnauth":
        require(
            field_map(outbound[0]).get(FIELD_NAME, b"")
            == (name.encode() if name != "ConsoleWaiting" else b""),
            "Client name/state differs",
        )


def _check_connections(report: Report) -> dict[str, list[Frame]]:
    """Check the handshake and the frames of every client connection.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified report of the D1 capture.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The inbound frames of each client connection, by connection name.
    """
    inbound_by_name: dict[str, list[Frame]] = {}
    for name in NAMES:
        _, sent, received = connection(report, name)
        _check_handshake(sent, received)
        outbound = parse_frames(sent[HANDSHAKE_REQUEST_BYTES:])
        inbound = parse_frames(received[HANDSHAKE_REPLY_BYTES:])
        _check_sequence(name, outbound, inbound)
        _check_client(name, outbound, inbound)
        inbound_by_name[name] = inbound
    return inbound_by_name


def _check_console_frame(frame: Frame) -> None:
    """Check that a console 104 frame carries only the console text.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        The frame to check.
    """
    require(
        frame["type"] == TYPE_MESSAGE_NOTIFICATION
        and field_map(frame) == {FIELD_DATA: TEXT_CONSOLE},
        "Console 104 is not data-only",
    )


def _check_broadcast_frame(frame: Frame, text: bytes) -> None:
    """Check that a 355 frame carries the text and the sender of the broadcast.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        The 355 frame to check.
    text : bytes
        The text that the broadcast must carry.
    """
    fields = field_map(frame)
    require(
        frame["type"] == TYPE_BROADCAST
        and set(fields) == {FIELD_DATA, FIELD_NAME, FIELD_USER_ID}
        and fields[FIELD_DATA] == text
        and fields[FIELD_NAME] == b"ConsoleSender"
        and len(fields[FIELD_USER_ID]) == USER_ID_BYTES,
        "355 sender fields differ",
    )


def _check_broadcasts(
    sender: list[Frame], refuse: list[Frame], waiting: list[Frame]
) -> None:
    """Check which clients received each console and broadcast frame.

    Parameters
    ----------
    sender : list[dict[str, typing.Any]]
        The inbound frames of the sending client.
    refuse : list[dict[str, typing.Any]]
        The inbound frames of the refusing client.
    waiting : list[dict[str, typing.Any]]
        The inbound frames of the waiting client.
    """
    for frame in (sender[5], refuse[4]):
        _check_console_frame(frame)
    for frame, text in (
        (refuse[3], TEXT_BEFORE),
        (refuse[6], TEXT_AFTER),
        (waiting[5], TEXT_AFTER),
    ):
        _check_broadcast_frame(frame, text)
    require(
        field_map(refuse[3])[FIELD_USER_ID]
        == field_map(refuse[6])[FIELD_USER_ID]
        == field_map(waiting[5])[FIELD_USER_ID],
        "355 sender UID differs",
    )
    require(
        all(f["type"] != TYPE_BROADCAST for f in sender), "Self-recipient 355 appeared"
    )
    require(
        all(
            f["type"] not in {TYPE_MESSAGE_NOTIFICATION, TYPE_BROADCAST}
            for f in waiting[:5]
        ),
        "Waiting peer received early broadcast",
    )


def check_frames(report: Report) -> dict[str, typ.Any]:
    """Check the control frames of the D1 console clients and their broadcasts.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified report of the D1 capture.

    Returns
    -------
    dict[str, typing.Any]
        The sender identifier and the recipients of each console and broadcast frame.
    """
    inbound = _check_connections(report)
    sender, refuse, waiting = [inbound[name] for name in NAMES[:3]]
    _check_broadcasts(sender, refuse, waiting)
    return {
        "sender_uid_hex": field_map(refuse[3])[FIELD_USER_ID].hex(),
        "console_104_recipients": ["ConsoleSender", "ConsoleRefuse"],
        "before_355_recipients": ["ConsoleRefuse"],
        "after_355_recipients": ["ConsoleRefuse", "ConsoleWaiting"],
    }
