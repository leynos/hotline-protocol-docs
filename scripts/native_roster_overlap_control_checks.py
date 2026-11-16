"""Check the frames of one roster overlap against the values its plan expects.

Each check raises ``ValueError`` with the reason for its first mismatch, and
the checks run in the order the control driver made them. The control module
re-exports these names, so its importers keep their paths.
"""

import hashlib

import native_roster_overlap_cases as cases
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from verify_native_auth import roster
from verify_native_shx import fields

OVERLAP_MEMBERS = 2  # the two accounts that a roster reply of the overlap lists
OVERLAP_FRAMES = 5  # the replies and updates that the overlap drain collects
UPDATE_FIELDS = 4  # name, UID, icon and field 112 of a presence update
UPDATE_OPAQUE_FIELD = (
    112  # field 112 of a presence update, which native_wire_names does not name
)


def need(ok: bool, reason: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the condition positionally
    """Raise ``ValueError`` with ``reason`` unless ``ok`` holds.

    Parameters
    ----------
    ok : bool
        The condition that must hold.
    reason : str
        The message of the error raised when it does not.

    Raises
    ------
    ValueError
        When ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def sha(raw: bytes) -> str:
    """Return the SHA-256 digest of ``raw`` as hexadecimal text.

    Parameters
    ----------
    raw : bytes
        The bytes to digest.

    Returns
    -------
    str
        The digest.
    """
    return hashlib.sha256(raw).hexdigest()


def frame_key(frame: dict) -> tuple[str, int, int, int]:
    """Return the key that identifies a frame in an overlap.

    Parameters
    ----------
    frame : dict
        A decoded frame with its connection label.

    Returns
    -------
    tuple[str, int, int, int]
        The connection, reply flag, type and identifier. A presence update or
        departure that is not a reply has identifier zero.
    """
    identifier = (
        0
        if frame["type"] in {TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT}
        and not frame["is_reply"]
        else frame["id"]
    )
    return frame["connection"], frame["is_reply"], frame["type"], identifier


def expected_frame(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # a frame key has five parts, as the planner writes them
    frame: dict, connection: str, kind: int, identifier: int, is_reply: int
) -> bool:
    """Tell whether a frame has the given connection, type and identifier.

    Parameters
    ----------
    frame : dict
        A decoded frame with its connection label.
    connection : str
        The connection label that the frame must carry.
    kind : int
        The transaction type that the frame must carry.
    identifier : int
        The identifier that the frame must carry, after :func:`frame_key`.
    is_reply : int
        The reply flag that the frame must carry.

    Returns
    -------
    bool
        Whether the key of ``frame`` is the given key.
    """
    return frame_key(frame) == (connection, is_reply, kind, identifier)


def one(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers name a frame by five parts
    frames: list[dict], connection: str, kind: int, identifier: int, is_reply: int
) -> dict:
    """Return the single frame that has the given key.

    Parameters
    ----------
    frames : list[dict]
        The frames to search.
    connection : str
        The connection label that the frame must carry.
    kind : int
        The transaction type that the frame must carry.
    identifier : int
        The identifier that the frame must carry.
    is_reply : int
        The reply flag that the frame must carry.

    Returns
    -------
    dict
        The one matching frame.
    """
    matches = [
        f for f in frames if expected_frame(f, connection, kind, identifier, is_reply)
    ]
    need(len(matches) == 1, f"Missing or duplicate {connection}/{kind}/{identifier}")
    return matches[0]


def exact_rows(
    frame: dict,
    a_uid: int | None = None,
    b_uid: int | None = None,
    *,
    b_new: bool = False,
) -> tuple[int, int]:
    """Check a roster reply lists exactly the two overlap accounts.

    Parameters
    ----------
    frame : dict
        The roster reply, decoded.
    a_uid : int | None
        The UID that account a must keep, or ``None`` to accept any.
    b_uid : int | None
        The UID that account b must keep, or ``None`` to accept any.
    b_new : bool
        Whether account b must carry its renamed name and icon.

    Returns
    -------
    tuple[int, int]
        The UIDs of accounts a and b.
    """
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Roster reply header differs",
    )
    rows = roster(frame)
    need(len(rows) == OVERLAP_MEMBERS, "Roster has missing or unexplained third member")
    names = {bytes.fromhex(row["name_hex"]): row for row in rows}
    need(
        set(names) == {cases.OLD_A, cases.NEW_B if b_new else cases.OLD_B},
        "Roster identity is mixed or unexpected",
    )
    a, b = names[cases.OLD_A], names[cases.NEW_B if b_new else cases.OLD_B]
    need(
        a["icon"] == 1
        and b["icon"] == (3 if b_new else 2)
        and a["uid"] != b["uid"]
        and a["uid"] > 0
        and b["uid"] > 0,
        "Roster icon/UID pair is torn",
    )
    need(
        (a_uid is None or a["uid"] == a_uid) and (b_uid is None or b["uid"] == b_uid),
        "Roster UID changed",
    )
    return a["uid"], b["uid"]


def check_overlap(frames: list[dict], a_uid: int, b_uid: int) -> str:
    """Check the overlap frames and tell whether account b was renamed.

    Parameters
    ----------
    frames : list[dict]
        The frames that the overlap drain collected.
    a_uid : int
        The UID of account a.
    b_uid : int
        The UID of account b.

    Returns
    -------
    str
        ``"old"`` when the roster snapshot still shows the old name, or
        ``"new"`` when it shows the new one.
    """
    expected = {
        ("a", 1, 0, 11),
        ("a", 1, 0, 12),
        ("b", 1, 0, 12),
        ("a", 0, 301, 0),
        ("b", 0, 301, 0),
    }
    need(
        len(frames) == OVERLAP_FRAMES and {frame_key(f) for f in frames} == expected,
        "Overlap reply/update set differs",
    )
    for label in ("a", "b"):
        ack = one(frames, label, 0, 12, 1)
        need(ack["error"] == 0 and ack["fields"] == [], "500 barrier ACK differs")
        update = one(frames, label, 301, 0, 0)
        value = fields(update)
        need(
            update["error"] == 0
            and len(update["fields"]) == UPDATE_FIELDS
            and set(value)
            == {FIELD_NAME, FIELD_USER_ID, FIELD_ICON, UPDATE_OPAQUE_FIELD}
            and value.get(FIELD_USER_ID) == b_uid.to_bytes(2, "big")
            and value.get(FIELD_NAME) == cases.NEW_B
            and value.get(FIELD_ICON) == cases.ICON_NEW,
            "Rename 301 identity/icon differs",
        )
    snapshot = one(frames, "a", 0, 11, 1)
    try:
        exact_rows(snapshot, a_uid, b_uid)
    except ValueError:
        exact_rows(snapshot, a_uid, b_uid, b_new=True)
        return "new"
    return "old"
