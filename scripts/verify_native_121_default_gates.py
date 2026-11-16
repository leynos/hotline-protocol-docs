"""The stage gates of the delayed-121 default-response capture.

Part of the capture driver's module set (``verify_native_121_default.CAPTURE_MODULES``).
``gate`` checks one action of a report, live or replayed; ``semantic`` replays
every action of a completed report. A gate raises ``ValueError`` at the first
thing a report gets wrong.
"""

import hashlib
import typing as typ

from native_wire_names import (
    FIELD_DATA,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN_AGREEMENT,
)
from verify_native_121_default_checks import (
    AGREEMENT_SHA256,
    Moment,
    at,
    check_roster,
    layout,
    own_uid,
    subject_uid,
)
from verify_native_121_default_subject import SUBJECT_CHECKS
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Case = dict[str, typ.Any]

OBSERVER_ACTION = 8  # the action whose reply names the observer
FIRST_ACTION = 8
END_ACTION = 69  # exclusive: the plan's last action is 68
GATE_COUNT = 27
AGREEMENT_TEXT_BYTES = 242
MAX_OPTIONAL_122 = 1
ABSENT = "absent"
ABSENT_ROSTER_ID = 11
EMPTY_ROSTER_ID = 12
LOGIN_ACK_FIELDS = {160: b"\0\xbe", 161: b"\0\0"}  # the version and the unnamed word

# The offsets of one case at which a gate checks, by what they check.
FIRST_LOGIN = 4
AGREEMENT = 5
QUIET_ROSTER = 7
AGREEMENT_ACK = 9
ANNOUNCED = 10
PRIVILEGES = 11
SECOND_ACK = 13
LISTED_ROSTER = 15
PM_ACK = 17
AUTO_RESPONSE = 18
ORIGINAL_PM = 19
DEPARTURE = 27
CLOSING = 29
ACK_OFFSETS = {FIRST_LOGIN, AGREEMENT_ACK, SECOND_ACK, PM_ACK}
SUBJECT_OFFSETS = {PRIVILEGES, LISTED_ROSTER, AUTO_RESPONSE, ORIGINAL_PM, DEPARTURE}
GATED_OFFSETS = {
    *ACK_OFFSETS,
    *SUBJECT_OFFSETS,
    AGREEMENT,
    QUIET_ROSTER,
    ANNOUNCED,
    CLOSING,
}

__all__ = ["gate", "semantic"]


def _optional_122(moment: Moment) -> None:
    """Check that the subject received at most one 122 so far.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    case, label = moment.case, moment.case["label"]
    extra = [
        f
        for f in moment.report["frames"]
        if case["first"] <= f["action"] <= moment.index
        and f["connection"] == moment.subject()
        and f["type"] == TYPE_BANNER_METADATA
    ]
    require(len(extra) <= MAX_OPTIONAL_122, f"{label}: optional 122 count differs")


def _ack(moment: Moment) -> None:
    """Check an acknowledgement, and the optional 122 after the second.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    case, offset, label = moment.case, moment.offset, moment.case["label"]
    connection = "main" if offset == PM_ACK else moment.subject()
    identifier = {
        FIRST_LOGIN: case["login_id"],
        AGREEMENT_ACK: case["agreement_id"],
        SECOND_ACK: case["agreement_id"] + 1,
        PM_ACK: case["pm_id"],
    }[offset]
    frame = at(moment.report, moment.index, connection, 0)
    expected = LOGIN_ACK_FIELDS if offset == FIRST_LOGIN else {}
    require(
        frame["is_reply"]
        and frame["id"] == identifier
        and frame["error"] == 0
        and fields(frame) == expected,
        f"{label}: ACK {identifier} differs",
    )
    if offset == SECOND_ACK:
        _optional_122(moment)


def _agreement(moment: Moment) -> None:
    """Check the pending agreement that the subject receives.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    frame = at(moment.report, moment.index, moment.subject(), TYPE_LOGIN_AGREEMENT)
    value = fields(frame)
    require(
        set(value) == {FIELD_DATA}
        and len(value[FIELD_DATA]) == AGREEMENT_TEXT_BYTES
        and hashlib.sha256(value[FIELD_DATA]).hexdigest() == AGREEMENT_SHA256,
        f"{moment.case['label']}: pending agreement differs",
    )


def _quiet_roster(moment: Moment) -> None:
    """Check the roster taken before the subject has agreed.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    identifier = ABSENT_ROSTER_ID if moment.case["label"] == ABSENT else EMPTY_ROSTER_ID
    check_roster(moment.report, identifier, moment.own, None)


def _announced(moment: Moment) -> None:
    """Check the announcement of the subject.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    subject_uid(moment.report, moment.case, moment.own)


def _check(moment: Moment) -> None:
    """Run the check that belongs to the action's offset.

    Parameters
    ----------
    moment : Moment
        The action.
    """
    offset = moment.offset
    if offset in ACK_OFFSETS:
        _ack(moment)
    elif offset == AGREEMENT:
        _agreement(moment)
    elif offset == QUIET_ROSTER:
        _quiet_roster(moment)
    elif offset == ANNOUNCED:
        _announced(moment)
    else:
        uid = subject_uid(moment.report, moment.case, moment.own)
        SUBJECT_CHECKS[offset](moment, uid)


def gate(report: Report, plan: Report, index: int) -> str | None:
    """Check one action of a report against the plan's cases.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report, or a live recorder's frames and events.
    plan : dict[str, typing.Any]
        The plan, whose layout has been checked.
    index : int
        The action.

    Returns
    -------
    str | None
        The name of the gate that passed, or ``None`` when the action has none.
    """
    if index == OBSERVER_ACTION:
        own_uid(report)
        return "observer-identity"
    for case in plan["expectation"]["cases"]:
        offset = index - case["first"]
        if offset not in GATED_OFFSETS:
            continue
        own = own_uid(report)
        name = bytes.fromhex(case["name_hex"])
        icon = int.from_bytes(bytes.fromhex(case["icon_hex"]), "big")
        _check(Moment(report, case, index, offset, own, name, icon))
        return f"{case['label']}-{offset}"
    return None


def semantic(report: Report, plan: Report) -> Report:
    """Replay every gate of a completed capture.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified capture report.
    plan : dict[str, typing.Any]
        The capture's plan.

    Returns
    -------
    dict[str, typing.Any]
        The status and the names of the gates that passed.
    """
    require(report["status"] == "completed", "121 capture did not complete")
    layout(plan)
    passed = []
    for index in range(FIRST_ACTION, END_ACTION):
        result = gate(report, plan, index)
        if result is not None:
            passed.append(result)
    require(len(passed) == GATE_COUNT, "121 semantic gate count differs")
    return {"status": "verified", "gates": passed}
