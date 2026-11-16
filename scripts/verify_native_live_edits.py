"""Check the live edit and deletion of accounts that two sessions are using.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from protocol_capture import decode_frame
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]

SUBJECT_ICONS = [("one", 7), ("two", 8)]  # the two sessions and their icons
ROSTER_ROWS = 3  # the caller and the two subjects
INITIAL_ACCESS = bytes.fromhex("2000000000000000")
RENAMED = b"Stored Beta27"
RENAMED_FLAGS_FIELD = 112  # a field of the rename update whose meaning is open
RENAMED_FLAGS = b"\0\x20"
UID_BYTES = 2
ACCESS_UPDATES = 2  # the access at login, then the access after the edit
EDIT_ACK_ID = 11
EDIT_ROSTER_ID = 12
REVOKED_ID = 91
CONTROL_IDS = [80, 90, 92, 93]
SNAPSHOT_IDS = [12, 22, 32]
FLAGGED_IDS = [21, 31]
FINAL_ROSTER_IDS = [40, 41]
DELETED_NAME = b"Delete Target27"
HEADER_BYTES = 20  # the header of a frame, the last word of which is its data size
SIZE_START = 16
DELETE_LOOKUP_ID = 14
STALE_IDS = [12, 13]


def subject_uid(
    report: Report, rows: list[Report], name: bytes, spec: tuple[str, int]
) -> int:
    """Find one subject session in the roster and check its initial access.

    Returns
    -------
    int
        The subject's user ID.
    """
    connection, icon = spec
    matches = [r for r in rows if r["icon"] == icon and r["name_hex"] == name.hex()]
    require(len(matches) == 1, "Live account subject identity differs")
    access = next(
        f
        for f in selected(report, connection)
        if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access) == {FIELD_ACCESS_BITMAP: INITIAL_ACCESS},
        "Initial live access differs",
    )
    return matches[0]["uid"]


def subjects(report: Report, name: bytes) -> dict[str, int]:
    """Find the two subject sessions by name and icon in the initial roster.

    Returns
    -------
    dict[str, int]
        The user ID of each subject, by connection name.
    """
    rows = roster(reply(report, 10))
    require(len(rows) == ROSTER_ROWS, "Live account initial roster cardinality differs")
    return {spec[0]: subject_uid(report, rows, name, spec) for spec in SUBJECT_ICONS}


def check_updates(frames: list[Report], uids: dict[str, int]) -> list[Report]:
    """Check that each session saw one rename update per subject, byte for byte.

    Returns
    -------
    list[dict[str, typing.Any]]
        The rename updates that the session received.
    """
    updates = [
        f
        for f in frames
        if f["type"] == TYPE_PRESENCE_UPDATE and fields(f).get(FIELD_NAME) == RENAMED
    ]
    require(
        len(updates) == len(SUBJECT_ICONS)
        and {int.from_bytes(fields(f)[FIELD_USER_ID], "big") for f in updates}
        == set(uids.values()),
        "Live rename recipients differ",
    )
    for frame in updates:
        uid = int.from_bytes(fields(frame)[FIELD_USER_ID], "big")
        icon = 7 if uid == uids["one"] else 8
        require(
            fields(frame)
            == {
                FIELD_USER_ID: uid.to_bytes(UID_BYTES, "big"),
                FIELD_ICON: icon.to_bytes(UID_BYTES, "big"),
                RENAMED_FLAGS_FIELD: RENAMED_FLAGS,
                FIELD_NAME: RENAMED,
            },
            "Live rename field bytes differ",
        )
    return updates


def check_peer(
    report: Report, connection: str, updates: list[Report], uids: dict[str, int]
) -> None:
    """Check a subject's own access change, revocation and uninterrupted control."""
    frames = selected(report, connection)
    access = [f for f in frames if f["type"] == TYPE_PRIVILEGES_NOTIFICATION]
    own = next(
        f
        for f in updates
        if int.from_bytes(fields(f)[FIELD_USER_ID], "big") == uids[connection]
    )
    require(
        len(access) == ACCESS_UPDATES
        and fields(access[1]) == {FIELD_ACCESS_BITMAP: bytes(8)}
        and frames.index(access[1]) < frames.index(own),
        "Own 354 must precede own rename",
    )
    require(
        fields(reply(report, REVOKED_ID, connection))
        == {FIELD_ERROR_TEXT: b"You are not allowed to download files."}
        and reply(report, REVOKED_ID, connection)["error"] == 1,
        "Live revocation not enforced",
    )
    for identifier in CONTROL_IDS:
        require(
            reply(report, identifier, connection)["error"] == 0
            and fields(reply(report, identifier, connection)) == {},
            "Password change interrupted live control",
        )


def check_connection(
    report: Report, connection: str, ack: Report, uids: dict[str, int]
) -> None:
    """Check what one session saw of the edit: the updates, order and access."""
    frames = selected(report, connection)
    updates = check_updates(frames, uids)
    if connection == "main":
        require(
            all(
                frames.index(ack)
                < frames.index(f)
                < frames.index(reply(report, EDIT_ROSTER_ID))
                for f in updates
            ),
            "Caller ACK/rename/roster order differs",
        )
    else:
        check_peer(report, connection, updates, uids)


def check_snapshots(report: Report, uids: dict[str, int]) -> None:
    """Check the rosters and the ACKs that follow the edit."""
    for identifier in SNAPSHOT_IDS:
        rows = roster(reply(report, identifier))
        require(
            {r["uid"] for r in rows if r["name_hex"] == RENAMED.hex()}
            == set(uids.values()),
            "Live post-edit snapshot differs",
        )
    for identifier in FLAGGED_IDS:
        require(
            reply(report, identifier)["error"] == 0
            and fields(reply(report, identifier)) == {},
            "Password/attribute-only ACK differs",
        )
    for identifier in FINAL_ROSTER_IDS:
        require(
            not (
                set(uids.values())
                & {r["uid"] for r in roster(reply(report, identifier))}
            ),
            "Closed live subjects remain in final edit roster",
        )


def check_edit(report: Report) -> dict[str, int]:
    """Check the live rename, revocation and password change of the stored account.

    Returns
    -------
    dict[str, int]
        The user ID of each subject, by connection name.
    """
    uids = subjects(report, b"Stored Alpha27")
    main = selected(report, "main")
    ack = reply(report, EDIT_ACK_ID)
    require(ack["error"] == 0 and fields(ack) == {}, "Live edit ACK differs")
    for connection in ["main", "one", "two"]:
        check_connection(report, connection, ack, uids)
    check_snapshots(report, uids)
    removals = [fields(f) for f in main if f["type"] == TYPE_USER_LEFT]
    require(
        removals
        == [
            {FIELD_USER_ID: uids["one"].to_bytes(UID_BYTES, "big")},
            {FIELD_USER_ID: uids["two"].to_bytes(UID_BYTES, "big")},
        ],
        "Live EOF removal notifications differ",
    )
    return uids


def check_deleted_notices(report: Report, observations: Report) -> None:
    """Check the notice that each deleted session got and its native close."""
    for connection in ["one", "two"]:
        notices = [
            f
            for f in selected(report, connection)
            if f["type"] == TYPE_MESSAGE_NOTIFICATION
        ]
        require(
            len(notices) == 1
            and notices[0]["is_reply"] == 0
            and notices[0]["error"] == 0
            and fields(notices[0])
            == {FIELD_DATA: b"You are logged in with an account which was deleted."},
            "Deleted account notice differs",
        )
        require(
            observations[connection]["guest_server_initiated_close"]
            and observations[connection]["guest_server_close_kind"] == "FIN",
            "Deletion must retain native first FIN",
        )


def late_removals(tail: bytes) -> list[bytes]:
    """Decode the removal notices that were left unread, and check each.

    Returns
    -------
    list[bytes]
        The user ID of each removal, in order.
    """
    removals = []
    while tail:
        require(len(tail) >= HEADER_BYTES, "Truncated late removal header")
        size = HEADER_BYTES + int.from_bytes(tail[SIZE_START:HEADER_BYTES], "big")
        frame = decode_frame(tail[:size])
        require(
            size <= len(tail)
            and frame["type"] == TYPE_USER_LEFT
            and frame["is_reply"] == 0
            and frame["error"] == 0
            and set(fields(frame)) == {FIELD_USER_ID},
            "Unexpected unread deletion output",
        )
        removals.append(fields(frame)[FIELD_USER_ID])
        tail = tail[size:]
    return removals


def check_delete(report: Report, tail: bytes, observations: Report) -> dict[str, int]:
    """Check the live deletion of the account and the removals it caused.

    Returns
    -------
    dict[str, int]
        The user ID of each subject, by connection name.
    """
    uids = subjects(report, DELETED_NAME)
    require(
        reply(report, EDIT_ACK_ID)["error"] == 0
        and fields(reply(report, EDIT_ACK_ID)) == {},
        "Live deletion ACK differs",
    )
    check_deleted_notices(report, observations)
    for identifier in STALE_IDS:
        require(
            set(uids.values()) <= {r["uid"] for r in roster(reply(report, identifier))},
            "Deletion stale roster observation changed",
        )
    require(
        not any(f["type"] == TYPE_USER_LEFT for f in report["frames"]),
        "Deletion report must preserve unread removal tail",
    )
    require(
        reply(report, DELETE_LOOKUP_ID)["error"] == 1
        and fields(reply(report, DELETE_LOOKUP_ID))
        == {FIELD_ERROR_TEXT: b"No account with login \xd2m-delete27\xd3."},
        "Live deleted account lookup differs",
    )
    require(
        late_removals(tail)
        == [
            uids["one"].to_bytes(UID_BYTES, "big"),
            uids["two"].to_bytes(UID_BYTES, "big"),
        ],
        "Late removal UIDs differ",
    )
    return uids
