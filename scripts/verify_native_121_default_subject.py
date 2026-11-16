"""The checks that follow the subject's login in the delayed-121 capture.

Part of the capture driver's module set (``verify_native_121_default.CAPTURE_MODULES``).
Each check takes the action that it gates, with the subject's UID, and raises
``ValueError`` at the first thing a report gets wrong.
"""

import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from protocol_capture import decode_frame
from verify_native_121_default_checks import (
    OBSERVER,
    Moment,
    at,
    check_auto,
    check_roster,
)
from verify_native_auth import ADMIN
from verify_native_core import require
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ROSTER_AFTER_AGREEMENT = 2  # the request ID of that roster, past the agreement's
ROSTER_AFTER_PM = 2
PM_SENT_OFFSET = 16  # the action, after a case starts, that sends the message
PM_NOTIFICATIONS = 2  # the original message and the automatic response
ORIGINAL_OPTIONS = b"\0\1"
PRIVILEGES = 11  # the offsets of one case at which a gate checks
LISTED_ROSTER = 15
AUTO_RESPONSE = 18
ORIGINAL_PM = 19
DEPARTURE = 27
CLOSING = 29

__all__ = ["SUBJECT_CHECKS"]


def _privileges(moment: Moment, uid: bytes) -> None:
    """Check the subject's own privileges notification.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    del uid
    frame = at(
        moment.report, moment.index, moment.subject(), TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(frame) == {FIELD_ACCESS_BITMAP: ADMIN},
        f"{moment.case['label']}: own 354 differs",
    )


def _listed(moment: Moment, uid: bytes) -> None:
    """Check the roster that lists the subject.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    identifier = moment.case["agreement_id"] + ROSTER_AFTER_AGREEMENT
    check_roster(moment.report, identifier, moment.own, (uid, moment.name, moment.icon))


def _auto(moment: Moment, uid: bytes) -> None:
    """Check the automatic response that the observer receives.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    frame = at(moment.report, moment.index, "main", TYPE_MESSAGE_NOTIFICATION)
    check_auto(frame, uid, moment.name)


def _original(moment: Moment, uid: bytes) -> None:
    """Check the original message that the subject receives.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    del uid
    frame = at(moment.report, moment.index, moment.subject(), TYPE_MESSAGE_NOTIFICATION)
    require(
        fields(frame)
        == {
            FIELD_USER_ID: moment.own,
            FIELD_NAME: OBSERVER,
            FIELD_OPTIONS: ORIGINAL_OPTIONS,
            FIELD_DATA: bytes.fromhex(moment.case["pm_text_hex"]),
        },
        f"{moment.case['label']}: original PM differs",
    )


def _departure(moment: Moment, uid: bytes) -> None:
    """Check the departure notice of the subject.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    frame = at(moment.report, moment.index, "main", TYPE_USER_LEFT)
    require(
        fields(frame) == {FIELD_USER_ID: uid},
        f"{moment.case['label']}: departure UID differs",
    )


def _closing(moment: Moment, uid: bytes) -> None:
    """Check the end of a case: the roster, the notices, the target and the departure.

    Parameters
    ----------
    moment : Moment
        The action.
    uid : bytes
        The subject's UID.
    """
    case, report, label = moment.case, moment.report, moment.case["label"]
    check_roster(report, case["pm_id"] + ROSTER_AFTER_PM, moment.own, None)
    window = [
        f for f in report["frames"] if case["first"] <= f["action"] <= moment.index
    ]
    notices = [
        f
        for f in window
        if f["type"] == TYPE_MESSAGE_NOTIFICATION and not f["is_reply"]
    ]
    require(len(notices) == PM_NOTIFICATIONS, f"{label}: 104 count differs")
    sent = b"".join(
        bytes.fromhex(e["hex"])
        for e in report["events"]
        if e["action"] == case["first"] + PM_SENT_OFFSET and e["event"] == "send"
    )
    require(
        fields(decode_frame(sent))[FIELD_USER_ID] == uid,
        f"{label}: PM target UID differs",
    )
    departures = [
        f
        for f in report["frames"]
        if case["first"] <= f["action"] <= moment.index and f["type"] == TYPE_USER_LEFT
    ]
    require(len(departures) == 1, f"{label}: departure count differs")


SUBJECT_CHECKS: dict[int, cabc.Callable[[Moment, bytes], None]] = {
    PRIVILEGES: _privileges,
    LISTED_ROSTER: _listed,
    AUTO_RESPONSE: _auto,
    ORIGINAL_PM: _original,
    DEPARTURE: _departure,
    CLOSING: _closing,
}
