"""Frame checks of the bounded 303 diagnostic replies and requests.

The names are re-exported by verify_native_diagnostics, which the tests and the
evidence checkers import. The provenance checks that use them are in
verify_native_diagnostic_semantic.
"""

import native_diagnostic_cases as cases
from native_wire_names import (
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_NAME,
    FIELD_USER_ID,
    FRAME_HEADER_BYTES,
)
from protocol_capture import decode_frame
from verify_native_core import require
from verify_native_shx import fields

NAMES = ("preflight", "seed", "observe", "self", "cleanup")
DIAGNOSTIC_TYPE = 303  # the request whose replies these checks read
UID_BYTES = 2  # a session UID is a big-endian 16-bit value
TEXT_CAP_BYTES = 1024  # the source cap that the measured text must stay under
HIGH_BYTE = 0x8E  # a byte above 0x7F that the high-byte key must keep
TRANSPORT_PREFIX_HEX = "54525450"  # ASCII TRTP: a transport frame, not a request

DENIED = b"You are not allowed to get client information."
MISSING = b"Cannot get info for the specified client because it does not exist."
EMPTY_SECTIONS = (
    b"\r\r-------- File Downloads ---------\r\rNone.\r"
    b"\r------- Folder Downloads --------\r\rNone.\r"
    b"\r--------- File Uploads ----------\r\rNone.\r"
    b"\r-------- Folder Uploads ---------\r\rNone.\r"
    b"\r------- Waiting Downloads -------\r\rNone.\r"
)


def diagnostic_text(nickname: bytes, name: bytes, account: bytes) -> bytes:
    """Build the measured display snapshot that a 303 success reply carries.

    The snapshot is a measured display, not a release parity requirement.

    Parameters
    ----------
    nickname : bytes
        The nickname shown in the snapshot.
    name : bytes
        The name shown in the snapshot.
    account : bytes
        The account shown in the snapshot.

    Returns
    -------
    bytes
        The snapshot text.
    """
    return (
        b"Nickname:   "
        + nickname
        + b"\rName:       "
        + name
        + b"\rAccount:    "
        + account
        + b"\rAddress:    10.0.2.2"
        + EMPTY_SECTIONS
    )


def sent(report: dict, kind: int, identifier: int, connection: str = "main") -> dict:
    """Return the one sent request of ``kind`` and ``identifier``.

    Parameters
    ----------
    report : dict
        A verified capture report.
    kind : int
        The transaction type of the request.
    identifier : int
        The transaction identifier of the request.
    connection : str
        The connection on which the request was sent.

    Returns
    -------
    dict
        The decoded request frame.
    """
    matches = [
        decode_frame(bytes.fromhex(event["hex"]))
        for event in report["events"]
        if event["event"] == "send"
        and event["connection"] == connection
        and len(bytes.fromhex(event["hex"])) >= FRAME_HEADER_BYTES
        and event["hex"][:8] != TRANSPORT_PREFIX_HEX
    ]
    matches = [f for f in matches if f["type"] == kind and f["id"] == identifier]
    require(len(matches) == 1, "Missing/duplicate diagnostic request")
    return matches[0]


def uid_field(frame: dict) -> bytes:
    """Return the UID field of a request, after checking its shape.

    Parameters
    ----------
    frame : dict
        A decoded request frame.

    Returns
    -------
    bytes
        The two-byte UID value.
    """
    values = fields(frame)
    require(
        set(values) == {FIELD_USER_ID} and len(values[FIELD_USER_ID]) == UID_BYTES,
        "303 UID shape differs",
    )
    return values[FIELD_USER_ID]


def success(frame: dict, nickname: bytes, name: bytes, account: bytes) -> None:
    """Check that a 303 reply is a success carrying the expected snapshot.

    Parameters
    ----------
    frame : dict
        A decoded reply frame.
    nickname : bytes
        The nickname that the snapshot must show.
    name : bytes
        The name that the snapshot must show.
    account : bytes
        The account that the snapshot must show.
    """
    actual = fields(frame)
    expected = diagnostic_text(nickname, name, account)
    require(
        frame["type"] == 0
        and frame["error"] == 0
        and actual == {FIELD_DATA: expected, FIELD_NAME: nickname},
        "303 success fields/bytes differ",
    )
    require(
        HIGH_BYTE in expected if account == cases.KEY else True,
        "High byte lost",
    )
    require(
        len(actual[FIELD_DATA]) < TEXT_CAP_BYTES,
        "303 measured text exceeds source cap",
    )


def failure(frame: dict, text: bytes) -> None:
    """Check that a 303 reply is a failure carrying ``text``.

    Parameters
    ----------
    frame : dict
        A decoded reply frame.
    text : bytes
        The error text that the reply must carry.
    """
    require(
        frame["type"] == 0
        and frame["error"] == 1
        and fields(frame) == {FIELD_ERROR_TEXT: text},
        "303 failure fields/status differ",
    )
