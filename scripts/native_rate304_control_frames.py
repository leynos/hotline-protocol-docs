"""Read and check single frames of the 304 reset and limit experiment.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. Each check fails
closed with a ``ValueError`` that names what differed.
"""

import hashlib
import typing as typ

import native_rate304_cases as cases
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import roster
from verify_native_shx import fields

type Report = dict[str, typ.Any]

LOGIN_REPLY_FIELDS = {160: b"\0\xbe", 161: b"\0\0"}
# The roster request of the subject: its reply identifier.
ROSTER_ID = 10
SUBJECT_ROSTER_ROWS = 2
UPDATE_FIELDS = {FIELD_NAME, FIELD_USER_ID, FIELD_ICON, 112}
UID_BYTES = 2
NO_TAIL = ""  # the text of a frame that leaves nothing unconsumed
# The experiment: 26 spaced updates, then a 27th that the limiter must refuse.
UPDATES = 26
ICON_FIRST = 2
ICON_TERMINAL = 28
PACED_REQUESTS = 1000
PACED_BARRIERS = 2000
BURST_REQUESTS = 3000
BURST_BARRIERS = 4000
QUIET_SECONDS = 70
TRIAL_SECONDS = 20
MAX_UID = 65535


def need(ok: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # called as need(ok, message) throughout
    """Fail closed unless a condition holds.

    Parameters
    ----------
    ok : bool
        The condition.
    message : str
        The message of the failure.

    Raises
    ------
    ValueError
        If the condition is false.
    """
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


def one(  # pylint: disable=too-many-arguments,too-many-positional-arguments  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # the five selectors name one frame, in the order every caller gives them
    frames: list[Report], connection: str, kind: int, identifier: int, reply: int
) -> Report:
    """Find the single frame of a flow with a given type, id and reply marker.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    matches = [
        frame
        for frame in frames
        if (frame["connection"], frame["type"], frame["id"], frame["is_reply"])
        == (connection, kind, identifier, reply)
    ]
    need(len(matches) == 1, f"Missing/duplicate {connection}/{kind}/{identifier}")
    return matches[0]


def exact_fields(frame: Report) -> dict[int, bytes]:
    """Read a frame's fields, refusing a malformed, fragmented or repeated one.

    Returns
    -------
    dict[int, bytes]
        The field values by identifier.
    """
    result = fields(frame)
    need(
        frame["total_size"] == frame["data_size"]
        and len(result) == len(frame["fields"])
        and frame.get("declared_field_count") == len(result)
        and frame.get("unconsumed_hex") == NO_TAIL,
        "Frame fields malformed/fragmented/duplicated",
    )
    return result


def successful(frame: Report) -> None:
    """Require a frame to be a direct success reply."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Reply is not direct success",
    )


def agreement(frames: list[Report], connection: str) -> None:
    """Require a flow to have received exactly the controlled agreement."""
    notices = [
        frame
        for frame in frames
        if frame["connection"] == connection and frame["type"] == TYPE_LOGIN_AGREEMENT
    ]
    need(len(notices) == 1 and notices[0]["is_reply"] == 0, "Agreement differs")
    content = exact_fields(notices[0])
    need(
        set(content) == {FIELD_DATA}
        and digest(content[FIELD_DATA]) == cases.AGREEMENT_SHA256,
        "Controlled agreement bytes differ",
    )


def login_identity(frames: list[Report], connection: str, access: bytes) -> None:
    """Require a flow's login reply, its privileges and its agreement."""
    ack = one(frames, connection, 0, 1, 1)
    successful(ack)
    need(exact_fields(ack) == LOGIN_REPLY_FIELDS, "Login107 extras differ")
    grants = [
        frame
        for frame in frames
        if frame["connection"] == connection
        and frame["type"] == TYPE_PRIVILEGES_NOTIFICATION
    ]
    need(
        len(grants) == 1 and exact_fields(grants[0]) == {FIELD_ACCESS_BITMAP: access},
        "Login access/354 differs",
    )
    agreement(frames, connection)


def subject_identity(frames: list[Report], connection: str) -> int:
    """Require a subject's login and roster, and return its user id.

    Returns
    -------
    int
        The user id that the roster gives the subject.
    """
    login_identity(frames, connection, bytes.fromhex(cases.ZERO_ACCESS))
    reply = one(frames, connection, 0, ROSTER_ID, 1)
    successful(reply)
    rows = roster(reply)
    own = [r for r in rows if bytes.fromhex(r["name_hex"]) == cases.SUBJECT_NAME]
    need(len(own) == 1 and own[0]["icon"] == 1, "Subject roster identity differs")
    need(
        len(rows) == SUBJECT_ROSTER_ROWS,
        "Subject roster lacks observer or has third party",
    )
    need(
        any(bytes.fromhex(r["name_hex"]) == cases.OBS_NAME for r in rows),
        "Observer missing from subject roster",
    )
    return own[0]["uid"]


def update_frame(frame: Report, uid: int, icon: int) -> None:
    """Require a frame to be the 301 update that names a subject and its icon."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 0
        and frame["type"] == TYPE_PRESENCE_UPDATE
        and frame["error"] == 0,
        "Expected update301 differs",
    )
    data = exact_fields(frame)
    need(
        set(data) == UPDATE_FIELDS
        and data[FIELD_USER_ID] == uid.to_bytes(UID_BYTES, "big")
        and data[FIELD_NAME] == cases.SUBJECT_NAME
        and data[FIELD_ICON] == icon.to_bytes(UID_BYTES, "big"),
        "Update301 UID/name/icon differs",
    )
