"""The frame checks of the delayed-121 default-response gates.

Part of the capture driver's module set (``verify_native_121_default.CAPTURE_MODULES``).
Each check raises ``ValueError`` at the first thing a report gets wrong.
"""

import dataclasses as dc
import typing as typ

from native_121_default_cases import DEFAULT, observe
from native_pm_cases import BASELINE_SHA256
from native_wire_names import (
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_PRESENCE_UPDATE,
)
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Case = dict[str, typ.Any]
type Subject = tuple[bytes, bytes, int]

AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
OBSERVER = b"framing-fixture"
OBSERVER_ROSTER_ID = 10
SUBJECT_ANNOUNCED = 10  # the action, after the case starts, of the 301 that names it
SUBJECT_UID_BYTES = 2
OBSERVER_ICON = 1
AUTO_OPTION = b"\0\4"

__all__ = [
    "AGREEMENT_SHA256",
    "OBSERVER",
    "Moment",
    "at",
    "check_auto",
    "check_roster",
    "layout",
    "own_uid",
    "subject_uid",
]


@dc.dataclass(frozen=True, slots=True)
class Moment:
    """One gated action of one case.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames and events.
    case : dict[str, typing.Any]
        The case's entry in the plan's expectation.
    index : int
        The action.
    offset : int
        The action's distance from the case's first action.
    own : bytes
        The observer's UID.
    name : bytes
        The subject's name.
    icon : int
        The subject's icon.
    """

    report: Report
    case: Case
    index: int
    offset: int
    own: bytes
    name: bytes
    icon: int

    def subject(self) -> str:
        """Name the connection of the subject.

        Returns
        -------
        str
            The connection that the case's subject logs in on.
        """
        return typ.cast("str", self.case["subject_connection"])


def at(report: Report, action: int, connection: str, kind: int) -> Report:
    """Find the one frame of a kind that arrived at an action.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report, or a live recorder's frames.
    action : int
        The action at which the frame arrived.
    connection : str
        The connection that received it.
    kind : int
        The transaction type.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    found = [
        f
        for f in report["frames"]
        if (f["action"], f["connection"], f["type"]) == (action, connection, kind)
    ]
    require(len(found) == 1, f"Action {action}: expected type {kind} on {connection}")
    return found[0]


def own_uid(report: Report) -> bytes:
    """Read the observer's own UID from its first roster.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.

    Returns
    -------
    bytes
        The observer's two-byte UID.
    """
    users = roster(reply(report, OBSERVER_ROSTER_ID))
    require(
        len(users) == 1 and bytes.fromhex(users[0]["name_hex"]) == OBSERVER,
        "Initial observer identity differs",
    )
    return users[0]["uid"].to_bytes(2, "big")


def subject_uid(report: Report, case: Case, observer: bytes) -> bytes:
    """Read the subject's UID from the announcement of its login.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.
    case : dict[str, typing.Any]
        The case's entry in the plan's expectation.
    observer : bytes
        The observer's UID, which the subject must not share.

    Returns
    -------
    bytes
        The subject's two-byte UID.
    """
    frame = at(report, case["first"] + SUBJECT_ANNOUNCED, "main", TYPE_PRESENCE_UPDATE)
    value = fields(frame)
    uid = value.get(FIELD_USER_ID, b"")
    require(
        len(uid) == SUBJECT_UID_BYTES
        and uid != observer
        and value.get(FIELD_NAME) == bytes.fromhex(case["name_hex"])
        and value.get(FIELD_ICON) == bytes.fromhex(case["icon_hex"]),
        f"{case['label']}: 301 identity/name/icon differs",
    )
    return uid


def check_auto(frame: Report, uid: bytes, name: bytes) -> None:
    """Check that the automatic response is the default text from the subject.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        The 104 that the observer received.
    uid : bytes
        The subject's UID.
    name : bytes
        The subject's name.
    """
    require(
        fields(frame)
        == {
            FIELD_USER_ID: uid,
            FIELD_NAME: name,
            FIELD_OPTIONS: AUTO_OPTION,
            FIELD_DATA: DEFAULT,
        },
        "Automatic response default text/identity differs",
    )


def check_roster(
    report: Report, identifier: int, own: bytes, subject: Subject | None
) -> None:
    """Check that a roster lists the observer, and the subject when it is present.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.
    identifier : int
        The request ID of the roster.
    own : bytes
        The observer's UID.
    subject : tuple[bytes, bytes, int] | None
        The subject's UID, name and icon, or ``None`` when it must be absent.
    """
    users = roster(reply(report, identifier))
    expected = {(own, OBSERVER, OBSERVER_ICON)}
    if subject is not None:
        expected.add(subject)
    actual = {
        (u["uid"].to_bytes(2, "big"), bytes.fromhex(u["name_hex"]), u["icon"])
        for u in users
    }
    require(actual == expected, f"Roster {identifier} differs")


def layout(plan: Report) -> list[Case]:
    """Check that a plan is the prepared one and return its cases.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The plan.

    Returns
    -------
    list[dict[str, typing.Any]]
        The cases of the plan's expectation.
    """
    require(plan["expectation"]["case"] == "delayed-121-default-215", "Wrong 121 case")
    steps, expected = observe()
    require(
        plan["steps"] == steps and plan["expectation"]["cases"] == expected,
        "121 steps/cases differ",
    )
    require(
        plan["expectation"]["baseline_plan_sha256"] == BASELINE_SHA256,
        "A7 baseline pin differs",
    )
    return expected
