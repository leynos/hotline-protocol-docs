"""Read the room notifications, identities and joins of one retained report."""

import native_room_cases as cases
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_NAME,
    FIELD_ROSTER_SUBJECT,
    FIELD_USER_ID,
    FIELD_USER_RECORD,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_rooms_wire import (
    FIELD_ROOM,
    OWNER_ID_BYTES,
    PARTICIPANTS,
    ROOM_ID_BYTES,
)
from verify_native_shx import fields

CLOSED_ROOM_TEXT = b"Cannot join private chat because it has been closed already."


def pushes(report: dict, connection: str, kind: int) -> list[dict]:
    """Return the notifications of type ``kind`` pushed to ``connection``.

    Parameters
    ----------
    report : dict
        The retained report of one case.
    connection : str
        The connection that received the notifications.
    kind : int
        The transaction type of the notifications.

    Returns
    -------
    list[dict]
        The fields of each matching push, in the order received.
    """
    return [
        fields(f)
        for f in selected(report, connection)
        if f["type"] == kind and not f["is_reply"]
    ]


def identities(report: dict) -> tuple[bytes, dict[str, bytes]]:
    """Return the room identifier and the user identifier of each participant.

    Parameters
    ----------
    report : dict
        The retained report of the case that creates the room.

    Returns
    -------
    tuple[bytes, dict[str, bytes]]
        The room identifier and the identifier of the owner and of each role.
    """
    created = fields(reply(report, 10))
    room, owner = created[FIELD_ROOM], created[FIELD_USER_ID]
    require(
        len(room) == ROOM_ID_BYTES
        and int.from_bytes(room, "big") != 0
        and len(owner) == OWNER_ID_BYTES,
        "Room/owner ID width differs",
    )
    ids = {"main": owner}
    for label, access_bitmap in cases.ROLES.items():
        matches = [
            f
            for f in pushes(report, "main", TYPE_PRESENCE_UPDATE)
            if f.get(FIELD_NAME) == b"Room30-" + label.encode()
        ]
        require(bool(matches), "Owned room participant not announced")
        ids[label] = matches[0][FIELD_USER_ID]
        access = pushes(report, label, TYPE_PRIVILEGES_NOTIFICATION)[0]
        require(
            access == {FIELD_ACCESS_BITMAP: access_bitmap},
            "Room participant privilege differs",
        )
    require(
        len(set(ids.values())) == PARTICIPANTS, "Room participant identity collision"
    )
    return room, ids


def members(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    report: dict,
    connection: str,
    identifier: int,
    expected: set[bytes],
    topic: bytes = b"",
) -> None:
    """Check the reply to a room join: its subject and its roster.

    Parameters
    ----------
    report : dict
        The retained report of the case.
    connection : str
        The connection that sent the join.
    identifier : int
        The request identifier of the join.
    expected : set[bytes]
        The user identifiers that the roster must contain.
    topic : bytes
        The topic that the reply must carry, or nothing when empty.
    """
    frame = reply(report, identifier, connection)
    require(frame["error"] == 0, "Room join failed")
    rows = [f for f in frame["fields"] if f["id"] == FIELD_USER_RECORD]
    others = [f for f in frame["fields"] if f["id"] != FIELD_USER_RECORD]
    require(
        others == ([{"id": FIELD_ROSTER_SUBJECT, "hex": topic.hex()}] if topic else []),
        "Room join subject presence differs",
    )
    require(
        {r["uid"] for r in roster({**frame, "fields": rows})}
        == {int.from_bytes(v, "big") for v in expected},
        "Room roster inclusion differs",
    )


def missing(report: dict, connection: str, identifier: int) -> None:
    """Check that a join to a closed room is refused with its message.

    Parameters
    ----------
    report : dict
        The retained report of the case.
    connection : str
        The connection that sent the join.
    identifier : int
        The request identifier of the join.
    """
    frame = reply(report, identifier, connection)
    require(
        frame["error"] == 1 and fields(frame) == {FIELD_ERROR_TEXT: CLOSED_ROOM_TEXT},
        "Missing-room join outcome differs",
    )


def formatted(
    name: bytes,
    value: bytes,
    action: bool = False,  # ruff: ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]  # the callers' shape
) -> bytes:
    """Format a chat line as the client shows it, including its continuations.

    Parameters
    ----------
    name : bytes
        The name of the speaker.
    value : bytes
        The text, whose carriage returns continue the line with the prefix.
    action : bool
        Whether the line is an action, shown with the name and no colon.

    Returns
    -------
    bytes
        The formatted line.
    """
    prefix = (
        b"\r *** " + name + b" "
        if action
        else b"\r" + name[:13].rjust(13, b" ") + b":  "
    )
    return prefix + value.replace(b"\r", prefix)
