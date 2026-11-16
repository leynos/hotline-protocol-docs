"""Check the owned accounts, duplicates and deletions of the identity corpus.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

import native_account_identity_cases as cases
from native_auth_cases import complement
from native_plan import payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
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

NAME_PREFIX = b"Identity29-"
PRESENT_PASSWORD = b"x"  # a stand-in: the reply carries a password only as a flag
ANNOUNCE_FLAGS_FIELD = 112  # a field of the owned target's announcement
ANNOUNCE_FLAGS = b"\0\0"
OWNED_ICON = b"\0\x1d"
UID_BYTES = 2
REMOVAL_BYTES = 28  # the length of the unread removal notice
ROSTER_AFTER_DELETE = 2
ERROR = 1
DUPLICATE_REQUEST_ID = 10
KICK_ID = 11
DELETE_ID = 12
READ_ID = 20
READ_UPPERCASE_ID = 21
ROSTER_ID = 30
LIVENESS_ID = 90
TARGET_LIVENESS_ID = 80


def account(frame: Report, label: str, lookup_key: bytes | None = None) -> None:
    """Check the reply to a read of one owned account."""
    require(
        frame["error"] == 0
        and fields(frame)
        == {
            FIELD_NAME: NAME_PREFIX + label.encode(),
            FIELD_LOGIN: complement(
                cases.KEYS[label] if lookup_key is None else lookup_key
            ),
            FIELD_PASSWORD: PRESENT_PASSWORD,
            FIELD_ACCESS_BITMAP: cases.ACCESS[label],
        },
        "Identity account record differs",
    )


def duplicate(report: Report, uppercase: bool) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    """Check that a duplicate create is refused and the original is untouched."""
    key = cases.KEYS["duplicate"]
    if uppercase:
        key = key.upper()
    require(
        reply(report, DUPLICATE_REQUEST_ID)["error"] == ERROR
        and fields(reply(report, DUPLICATE_REQUEST_ID))
        == {
            FIELD_ERROR_TEXT: b"Cannot create account \xd2"
            + key
            + b"\xd3 because there is already an account with that login."
        },
        "Duplicate create rejection differs",
    )
    account(reply(report, READ_ID), "duplicate")
    account(
        reply(report, READ_UPPERCASE_ID), "duplicate", cases.KEYS["duplicate"].upper()
    )
    require(
        reply(report, LIVENESS_ID)["error"] == 0, "Duplicate control liveness differs"
    )


def check_announcement(report: Report, label: str) -> bytes:
    """Check the target's protection mask and its announcement to the main session.

    Returns
    -------
    bytes
        The target's user ID.
    """
    subject = selected(report, "target")
    access = next(f for f in subject if f["type"] == TYPE_PRIVILEGES_NOTIFICATION)
    require(
        fields(access) == {FIELD_ACCESS_BITMAP: cases.ACCESS[label]},
        "Protection mask differs",
    )
    announce = next(
        f for f in selected(report, "main") if f["type"] == TYPE_PRESENCE_UPDATE
    )
    uid = fields(announce)[FIELD_USER_ID]
    require(
        fields(announce)
        == {
            FIELD_USER_ID: uid,
            FIELD_ICON: OWNED_ICON,
            ANNOUNCE_FLAGS_FIELD: ANNOUNCE_FLAGS,
            FIELD_NAME: NAME_PREFIX + label.encode(),
        }
        and len(uid) == UID_BYTES
        and int.from_bytes(uid, "big") > 0,
        "Owned target announcement differs",
    )
    return uid


def check_kick(report: Report, label: str) -> None:
    """Check that the kick of the protected target was refused and it stayed live."""
    kick = reply(report, KICK_ID)
    require(
        kick["error"] == ERROR
        and fields(kick)
        == {
            FIELD_ERROR_TEXT: b"You are not allowed to disconnect user \xd2Identity29-"
            + label.encode()
            + b"\xd3 (user is protected)."
        },
        "Kick protection rejection differs",
    )
    require(
        reply(report, TARGET_LIVENESS_ID, "target")["error"] == 0,
        "Protected subject lost liveness",
    )


def check_deletion_notice(report: Report, label: str) -> None:
    """Check the deletion ACK and the notice that the target received."""
    subject = selected(report, "target")
    connection = "target" if label == "self" else "main"
    ack = reply(report, DELETE_ID, connection)
    require(ack["error"] == 0 and fields(ack) == {}, "Deletion ACK differs")
    notice = next(f for f in subject if f["type"] == TYPE_MESSAGE_NOTIFICATION)
    require(
        not notice["is_reply"]
        and notice["error"] == 0
        and fields(notice)
        == {FIELD_DATA: b"You are logged in with an account which was deleted."},
        "Deletion notice differs",
    )
    if label == "self":
        require(
            subject.index(ack) < subject.index(notice),
            "Self-delete notice precedes ACK",
        )


def check_after_delete(report: Report, label: str, uid: bytes) -> None:
    """Check the deleted account's lookup failure and the stale roster."""
    require(
        reply(report, READ_ID)["error"] == ERROR
        and fields(reply(report, READ_ID))
        == {
            FIELD_ERROR_TEXT: b"No account with login \xd2"
            + cases.KEYS[label]
            + b"\xd3."
        },
        "Deleted account still readable or wrong lookup failure",
    )
    snapshot = roster(reply(report, ROSTER_ID))
    require(
        len(snapshot) == ROSTER_AFTER_DELETE
        and any(r["uid"] == int.from_bytes(uid, "big") for r in snapshot),
        "Bounded post-delete stale roster differs",
    )


def deletion(report: Report, label: str, observation: Report, tail: bytes) -> None:
    """Check one protected or self deletion against the guest's close and tail."""
    uid = check_announcement(report, label)
    check_kick(report, label)
    check_deletion_notice(report, label)
    require(
        observation["target"]["guest_server_initiated_close"]
        and observation["target"]["guest_server_close_kind"] == "FIN",
        "Protected/self-delete guest close differs",
    )
    check_after_delete(report, label, uid)
    require(len(tail) == REMOVAL_BYTES, "Unread target removal size differs")
    removed = decode_frame(tail)
    require(
        removed["type"] == TYPE_USER_LEFT
        and not removed["is_reply"]
        and removed["error"] == 0
        and fields(removed) == {FIELD_USER_ID: uid},
        "Unread target removal identity differs",
    )


def expected_inventory(baseline: list[str], labels: list[str]) -> list[str]:
    """Build the sorted enumeration that holds the baseline and ``labels``.

    Returns
    -------
    list[str]
        The baseline records and one payload per label, in hexadecimal.
    """
    return sorted(
        baseline
        + [
            payload([
                (FIELD_NAME, NAME_PREFIX + label.encode()),
                (FIELD_LOGIN, complement(cases.KEYS[label])),
                (FIELD_PASSWORD, PRESENT_PASSWORD),
                (FIELD_ACCESS_BITMAP, cases.ACCESS[label]),
            ]).hex()
            for label in labels
        ]
    )
