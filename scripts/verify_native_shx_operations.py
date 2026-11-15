"""Check the chat, listing and download exchanges that the shx peer drove."""

import dataclasses as dc
import typing as typ

from native_filp import decode, metadata
from native_transfer_cases import resource_fork
from native_wire_names import (
    FIELD_DATA,
    FIELD_FILE_ENTRY,
    FIELD_FILE_SIZE,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FILE_ENTRY_HEADER_BYTES,
    FILE_ENTRY_NAME_LENGTH_START,
    HTXF_MAGIC_HEX,
    TYPE_CHAT_NOTIFICATION,
)
from verify_native_core import require
from verify_native_shx_frames import CHAT, DATA, NAME, fields
from verify_native_shx_packets import CONTROL_PORT
from verify_native_shx_terminal import LISTING_CASES

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

TRANSFER_PORT = CONTROL_PORT + 1  # mac-peer-first-session.md: the data connection
CHAT_LINE = b"mothra-shx-basic-chat"
# transfer-contracts.md: a nonempty ordinary download streams 510 bytes of
# flattened file for a logical file size of 330.
STREAM_BYTES = 510
FILE_BYTES = 330
FIXTURE_TYPE_CREATOR = b"TEXTMOTH"  # the listing's type and creator words
SIZE_START = 8  # the listing's size word follows the type and creator
SIZE_END = 12
TYPE_CREATOR_END = 8
TRANSFER_SOCKETS = 2  # the control connection and the data connection


@dc.dataclass(frozen=True, slots=True)
class Session:
    """What a peer session sent and received on its control connection.

    Attributes
    ----------
    case : pathlib.Path
        The capture directory.
    name : str
        The case name that selects the checks.
    connections : list[dict[str, typing.Any]]
        Every paired connection of the session.
    requests : list[dict[str, typing.Any]]
        The frames the peer sent on the control connection.
    replies : list[dict[str, typing.Any]]
        The frames the server returned on the control connection.
    terminal : bytes
        The raw terminal output of the peer.
    """

    case: Path
    name: str
    connections: list[Report]
    requests: list[Report]
    replies: list[Report]
    terminal: bytes


def reply_to(session: Session, request: Report) -> Report:
    """Find the first reply to a request.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    return next(
        r for r in session.replies if r["is_reply"] and r["id"] == request["id"]
    )


def check_chat(session: Session) -> None:
    """Check that the chat line was sent and echoed by the server."""
    require(
        fields(session.requests[-1]) == {FIELD_DATA: CHAT_LINE},
        "Peer chat send differs",
    )
    require(
        any(
            r["type"] == TYPE_CHAT_NOTIFICATION
            and CHAT_LINE in fields(r).get(FIELD_DATA, b"")
            for r in session.replies
        ),
        "Native chat echo missing",
    )


def check_ambiguous_text(session: Session) -> None:
    """Check that the high bytes of the chat line were kept, not re-encoded."""
    chat = [
        fields(r)[FIELD_DATA]
        for r in session.replies
        if r["type"] == TYPE_CHAT_NOTIFICATION
    ]
    require(
        chat == [b"\rnative-byte-w:  " + CHAT],
        "Native ambiguous chat bytes changed",
    )
    require(CHAT in session.terminal, "Peer terminal reencoded ambiguous bytes")


def check_listing(session: Session) -> None:
    """Check the one listing entry of the fixture file and its display."""
    listing = reply_to(session, session.requests[2])
    found = []
    for f in listing["fields"]:
        value = bytes.fromhex(f["hex"])
        require(
            f["id"] == FIELD_FILE_ENTRY
            and len(value) >= FILE_ENTRY_HEADER_BYTES
            and int.from_bytes(
                value[FILE_ENTRY_NAME_LENGTH_START:FILE_ENTRY_HEADER_BYTES], "big"
            )
            == len(value) - FILE_ENTRY_HEADER_BYTES,
            "Native listing layout differs",
        )
        if value[FILE_ENTRY_HEADER_BYTES:] == NAME:
            found.append(value)
    require(
        len(found) == 1
        and found[0][:TYPE_CREATOR_END] == FIXTURE_TYPE_CREATOR
        and int.from_bytes(found[0][SIZE_START:SIZE_END], "big") == FILE_BYTES,
        "Missing exact fork fixture listing",
    )
    require(NAME in session.terminal, "Peer did not display listing")


def check_download(session: Session) -> None:
    """Check the download ACK, the transfer connection and the saved forks."""
    require(len(session.connections) == TRANSFER_SOCKETS, "Missing transfer socket")
    data = next(c for c in session.connections if c["endpoint"] == TRANSFER_PORT)
    ack = fields(reply_to(session, session.requests[-1]))
    require(
        ack[FIELD_TRANSFER_SIZE] == STREAM_BYTES.to_bytes(2, "big")
        and ack[FIELD_FILE_SIZE] == FILE_BYTES.to_bytes(2, "big"),
        "Native transfer sizes differ",
    )
    require(
        data["sent"]
        == bytes.fromhex(HTXF_MAGIC_HEX)
        + ack[FIELD_TRANSFER_REFERENCE]
        + STREAM_BYTES.to_bytes(4, "big")
        + bytes(4),
        "Peer transfer attach/reference differs",
    )
    forks = decode(data["received"])
    require(
        forks["DATA"] == DATA and forks["MACR"] == resource_fork(),
        "Native fork contents differ",
    )
    require(metadata(forks["INFO"])["name"] == NAME, "Native INFO name differs")
    require(
        (session.case / "work/mothra-fork-fixture").read_bytes() == forks["DATA"],
        "Saved data fork differs",
    )
    require(
        (session.case / "work/.resource/mothra-fork-fixture").read_bytes()
        == forks["MACR"],
        "Saved resource fork differs",
    )


def check_operations(session: Session) -> None:
    """Run the checks that belong to the case of a session."""
    if session.name == "basic-empty-name":
        check_chat(session)
    if session.name == "ambiguous-text":
        check_ambiguous_text(session)
    if session.name in LISTING_CASES:
        check_listing(session)
    if session.name == "fork-download":
        check_download(session)
    else:
        require(len(session.connections) == 1, "Unexpected extra peer socket")
