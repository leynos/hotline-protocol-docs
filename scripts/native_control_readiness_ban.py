"""The gates of the ban itself: the target, the notice, the readback and the probe.

Part of the capture driver's module set (``native_control_readiness.CAPTURE_MODULES``).
Each gate raises ``ValueError`` at the first thing a report gets wrong, and the
order of the checks is the order in which a capture reaches them.
"""

import typing as typ

import native_ban_control_cases as cases
from native_auth_cases import complement
from native_control_readiness_gates import (
    BASELINE_FIELDS,
    FIXTURE_FILES,
    OWNED_PASSWORD,
    SESSION_NAME,
    TARGET_FRAMES,
    field_digest,
    login_gate,
)
from native_plan import payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Frame = dict[str, typ.Any]

BAN_ROSTER_ID = 32
BAN_ID = 33
AFTER_ACCOUNTS_ID = 40
AFTER_FILES_ID = 41
AFTER_INFO_ID = 42
AFTER_ROSTER_ID = 43
TARGET_UID_BYTES = 2
PROBE_SENDS = 2  # the handshake and the 107 login
ROSTER_ROWS = 2  # the admin and the owned target
BAN_TEXT = b"You are permanently banned on this server."
ORIGINAL_ACCOUNTS = {
    "00040066000d61646d696e6973747261746f72006900059e9b929691006a000178006e0008fff3cfefff800000",
    "00040066000b666978747572652d6c6f770069000b9996878b8a8d9ad2939088006a000178006e00080000000000000000",
}

__all__ = [
    "BAN_TEXT",
    "ORIGINAL_ACCOUNTS",
    "after",
    "outcome",
    "probe",
    "target_gate",
]


def _target_login(target: list[Frame]) -> None:
    """Check the owned target's own login, privileges and agreement.

    Parameters
    ----------
    target : list[dict[str, typing.Any]]
        The frames of the ``target`` connection.
    """
    require(
        len(target) >= TARGET_FRAMES
        and target[0]["type"] == 0
        and target[0]["is_reply"] == 1
        and target[0]["error"] == 0,
        "Owned target login failed",
    )
    require(
        fields(target[1]) == {FIELD_ACCESS_BITMAP: cases.ZERO},
        "Target effective access is not zero",
    )
    require(target[2]["type"] == TYPE_LOGIN_AGREEMENT, "Target agreement missing")


def _announced_uid(main: list[Frame]) -> bytes:
    """Read the target's UID from the admin's one join announcement.

    Parameters
    ----------
    main : list[dict[str, typing.Any]]
        The frames of the ``main`` connection.

    Returns
    -------
    bytes
        The target's two-byte UID.
    """
    joins = [f for f in main if f["type"] == TYPE_PRESENCE_UPDATE and not f["is_reply"]]
    require(len(joins) == 1, "Target announcement missing or ambiguous")
    identity = fields(joins[0])
    uid = identity.get(FIELD_USER_ID, b"")
    require(
        len(uid) == TARGET_UID_BYTES
        and int.from_bytes(uid, "big") > 0
        and identity.get(FIELD_NAME) == cases.NAME,
        "Target UID/name mismatch",
    )
    return uid


def _current_roster(main: list[Frame], uid: bytes) -> None:
    """Check the admin's roster reply against the target's UID.

    Parameters
    ----------
    main : list[dict[str, typing.Any]]
        The frames of the ``main`` connection.
    uid : bytes
        The target's UID.
    """
    number = int.from_bytes(uid, "big")
    replies = [f for f in main if f["is_reply"] and f["id"] == BAN_ROSTER_ID]
    require(len(replies) == 1, "Current roster reply missing or ambiguous")
    rows = roster(replies[0])
    require(
        len(rows) == ROSTER_ROWS
        and sum(r["uid"] == number and r["name_hex"] == cases.NAME.hex() for r in rows)
        == 1,
        "Current roster target mismatch",
    )
    require(
        any(r["name_hex"] == SESSION_NAME.hex() and r["uid"] != number for r in rows),
        "Admin and target identities overlap",
    )


def target_gate(frames: list[Frame]) -> bytes:
    """Check the admin and target sessions before a ban request is sent.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        Every frame so far, each tagged with its connection.

    Returns
    -------
    bytes
        The target's UID.
    """
    main = [f for f in frames if f["connection"] == "main"]
    target = [f for f in frames if f["connection"] == "target"]
    login_gate(main)
    _target_login(target)
    uid = _announced_uid(main)
    _current_roster(main, uid)
    return uid


def outcome(report: Report) -> None:
    """Check the ban capture: the notice, the close and the readback.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The ban report.
    """
    require(report["status"] == "completed", "Ban capture incomplete")
    target = [f for f in report["frames"] if f["connection"] == "target"]
    main = [f for f in report["frames"] if f["connection"] == "main"]
    notice = [
        f
        for f in target
        if f["type"] == TYPE_MESSAGE_NOTIFICATION and not f["is_reply"]
    ]
    require(
        len(notice) == 1 and fields(notice[0]) == {FIELD_DATA: BAN_TEXT},
        "Permanent notice differs",
    )
    require(
        any(
            e["connection"] == "target" and e["event"] == "eof"
            for e in report["events"]
        ),
        "Target close missing",
    )
    acknowledged = [
        f for f in main if f["is_reply"] and f["id"] == BAN_ID and f["error"] == 0
    ]
    require(len(acknowledged) == 1, "Admin ACK missing")
    departures = [f for f in main if f["type"] == TYPE_USER_LEFT and not f["is_reply"]]
    require(len(departures) == 1, "Departure missing")
    after(report)


def probe(report: Report) -> None:
    """Check that a fresh login after the ban is refused.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The probe report.
    """
    require(report["status"] == "completed", "107 probe incomplete")
    frame = reply(report, 1)
    require(
        frame["type"] == 0
        and frame["error"] == 1
        and fields(frame) == {FIELD_ERROR_TEXT: BAN_TEXT},
        "Permanent login rejection differs",
    )
    sends = [e["hex"] for e in report["events"] if e["event"] == "send"]
    require(
        len(sends) == PROBE_SENDS
        and sends[0] == "54525450484f544c00010002"
        and sends[1].startswith("0000006b00000001"),
        "Fresh TRTP plus Login107 absent",
    )


def after(report: Report) -> None:
    """Check the admin's readback after the ban.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The ban report; the readback follows the ban in it.
    """
    require(report["status"] == "completed", "Post-ban admin readback incomplete")
    login_gate(report["frames"])
    owned = payload([
        (FIELD_NAME, cases.NAME),
        (FIELD_LOGIN, complement(cases.KEY)),
        (FIELD_PASSWORD, OWNED_PASSWORD),
        (FIELD_ACCESS_BITMAP, cases.ZERO),
    ]).hex()
    require(
        set(enumeration(reply(report, AFTER_ACCOUNTS_ID)))
        == ORIGINAL_ACCOUNTS | {owned},
        "Original or owned account changed after ban",
    )
    files = reply(report, AFTER_FILES_ID)
    require(
        len(listing(files)) == FIXTURE_FILES
        and field_digest(files) == BASELINE_FIELDS[TYPE_LIST_FILES],
        "Post-ban Files changed",
    )
    require(
        field_digest(reply(report, AFTER_INFO_ID))
        == BASELINE_FIELDS[TYPE_GET_FILE_INFO],
        "Post-ban fixture metadata changed",
    )
    require(len(roster(reply(report, AFTER_ROSTER_ID))) == 1, "Post-ban roster differs")
