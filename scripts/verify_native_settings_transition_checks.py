"""The stage checks of the same-session 304 transition capture.

Part of the capture driver's module set
(``verify_native_settings_transition.CAPTURE_MODULES``). Each check raises
``ValueError`` at the first thing a report gets wrong.
"""

import typing as typ

import native_settings_transition_cases as cases
from native_wire_names import (
    FIELD_DATA,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Window = dict[str, typ.Any]

CASE = "same-session-304-transitions"
OBSERVER = b"framing-fixture"
OBSERVER_ROSTER_ID = 10
MAIN_UID = b"\0\x20"
UID_BYTES = 2
ORIGINAL_OPTIONS = b"\0\1"
AUTO_OPTIONS = b"\0\4"
RESTORE_UPDATES = 2  # the main and subject connections each see the restore
SUBJECT_ICON_AFTER_RESTORE = b"\0\1"
PM_FIELDS = {FIELD_DATA, FIELD_NAME, FIELD_USER_ID, FIELD_OPTIONS}
SAVE_UID = {"peer_uid": FIELD_USER_ID}

__all__ = [
    "CASE",
    "check_stage",
    "check_update",
    "check_updates",
    "current_uids",
    "semantic",
    "stage_frames",
]


def stage_frames(
    report: Report, window: Window, kind: int, connection: str
) -> list[Report]:
    """List the frames of a kind that a connection received in a window.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    window : dict[str, typing.Any]
        The stage's window of actions.
    kind : int
        The transaction type.
    connection : str
        The connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        The notifications of that type, in order.
    """
    return [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["type"] == kind
        and not frame["is_reply"]
        and frame["connection"] == connection
    ]


def check_update(report: Report, window: Window, uid: bytes, connection: str) -> None:
    """Check the one 301 that a connection received for a stage.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    window : dict[str, typing.Any]
        The stage's window of actions.
    uid : bytes
        The subject's UID.
    connection : str
        The connection.
    """
    label = window["label"]
    stage = next(s for s in cases.STAGES if s.label == label)
    require(len(uid) == UID_BYTES, f"{label}: subject UID length differs")
    update = stage_frames(report, window, TYPE_PRESENCE_UPDATE, connection)
    require(len(update) == 1, f"{label}: 301 count differs on {connection}")
    actual = fields(update[0])
    require(
        actual.get(FIELD_USER_ID) == uid
        and actual.get(FIELD_NAME) == stage.expected_name
        and actual.get(FIELD_ICON) == stage.expected_icon,
        f"{label}: 301 name/icon/UID differs on {connection}",
    )


def check_updates(report: Report, window: Window, uid: bytes) -> None:
    """Check the 301 that each connection received for a stage.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    window : dict[str, typing.Any]
        The stage's window of actions.
    uid : bytes
        The subject's UID.
    """
    for connection in ("main", "subject"):
        check_update(report, window, uid, connection)


def _delivered(
    report: Report, window: Window, stage: cases.Stage, main_uid: bytes
) -> None:
    """Check the notifications of the stage and the original message.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    window : dict[str, typing.Any]
        The stage's window of actions.
    stage : native_settings_transition_cases.Stage
        The stage.
    main_uid : bytes
        The observer's UID.
    """
    label = window["label"]
    notices = [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["type"] == TYPE_MESSAGE_NOTIFICATION
        and not frame["is_reply"]
    ]
    expected_total = 2 if stage.expected_auto is not None else 1
    require(
        len(notices) == expected_total, f"{label}: 104 delivery/feedback count differs"
    )
    original = stage_frames(report, window, TYPE_MESSAGE_NOTIFICATION, "subject")
    require(len(original) == 1, f"{label}: subject PM missing")
    value = fields(original[0])
    require(
        set(value) == PM_FIELDS
        and value[FIELD_OPTIONS] == ORIGINAL_OPTIONS
        and value[FIELD_USER_ID] == main_uid
        and value[FIELD_NAME] == OBSERVER
        and value[FIELD_DATA] == bytes.fromhex(window["pm_text_hex"]),
        f"{label}: original PM fields differ",
    )


def _automatic(report: Report, window: Window, stage: cases.Stage, uid: bytes) -> None:
    """Check the automatic response, when the stage has one, and only then.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    window : dict[str, typing.Any]
        The stage's window of actions.
    stage : native_settings_transition_cases.Stage
        The stage.
    uid : bytes
        The subject's UID.
    """
    label = window["label"]
    sender = stage_frames(report, window, TYPE_MESSAGE_NOTIFICATION, "main")
    require(
        len(sender) == int(stage.expected_auto is not None),
        f"{label}: auto count differs",
    )
    if sender:
        auto = fields(sender[0])
        require(
            set(auto) == PM_FIELDS
            and auto[FIELD_USER_ID] == uid
            and auto[FIELD_NAME] == stage.expected_name
            and auto[FIELD_OPTIONS] == AUTO_OPTIONS
            and auto[FIELD_DATA] == stage.expected_auto,
            f"{label}: automatic text, identity or option differs",
        )


def check_stage(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape: the plan is passed and not read
    report: Report,
    plan: Report,
    window: Window,
    uid: bytes,
    main_uid: bytes = MAIN_UID,
) -> Report:
    """Check one stage: the updates, the notices and the acknowledgement.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The plan; it is not read.
    window : dict[str, typing.Any]
        The stage's window of actions.
    uid : bytes
        The subject's UID.
    main_uid : bytes
        The observer's UID.

    Returns
    -------
    dict[str, typing.Any]
        The label, the subject's UID and the automatic text, in hexadecimal.
    """
    del plan
    check_updates(report, window, uid)
    label = window["label"]
    stage = next(s for s in cases.STAGES if s.label == label)
    _delivered(report, window, stage, main_uid)
    _automatic(report, window, stage, uid)
    replies = [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["is_reply"]
        and frame["id"] == window["pm_id"]
        and frame["connection"] == "main"
    ]
    require(
        len(replies) == 1 and replies[0]["error"] == 0 and not replies[0]["fields"],
        f"{label}: PM ACK differs",
    )
    return {
        "label": label,
        "uid_hex": uid.hex(),
        "auto_hex": stage.expected_auto.hex()
        if stage.expected_auto is not None
        else None,
    }


def current_uids(report: Report, plan: Report) -> tuple[bytes, bytes]:
    """Read the subject's and the observer's UIDs.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The plan, which saves the subject's UID in one step.

    Returns
    -------
    tuple[bytes, bytes]
        The subject's UID and the observer's.
    """
    saved = [
        i for i, step in enumerate(plan["steps"]) if step.get("save_fields") == SAVE_UID
    ]
    require(len(saved) == 1, "Subject UID save step differs")
    first = roster(reply(report, OBSERVER_ROSTER_ID))
    require(
        len(first) == 1 and bytes.fromhex(first[0]["name_hex"]) == OBSERVER,
        "Initial main roster differs",
    )
    main_uid = first[0]["uid"].to_bytes(2, "big")
    announced = [
        frame
        for frame in report["frames"]
        if frame["action"] == saved[0]
        and frame["type"] == TYPE_PRESENCE_UPDATE
        and frame["connection"] == "main"
    ]
    require(len(announced) == 1, "Initial subject announcement missing")
    values = fields(announced[0])
    require(values.get(FIELD_NAME) == cases.SUBJECT, "Initial subject identity differs")
    uid = values.get(FIELD_USER_ID, b"")
    require(len(uid) == UID_BYTES and uid != main_uid, "Subject UID differs")
    return uid, main_uid


def _restore(report: Report, windows: list[Window], uid: bytes) -> None:
    """Check the two 301 that restore the subject after the last stage.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The completed report.
    windows : list[dict[str, typing.Any]]
        The stage windows of the plan.
    uid : bytes
        The subject's UID.
    """
    tail = [
        frame
        for frame in report["frames"]
        if frame["action"] > windows[-1]["last"]
        and frame["type"] == TYPE_PRESENCE_UPDATE
        and not frame["is_reply"]
    ]
    require(len(tail) == RESTORE_UPDATES, "Owned session restore 301 count differs")
    for frame in tail:
        value = fields(frame)
        require(
            value.get(FIELD_USER_ID) == uid
            and value.get(FIELD_NAME) == cases.SUBJECT
            and value.get(FIELD_ICON) == SUBJECT_ICON_AFTER_RESTORE,
            "Owned session restore state differs",
        )


def semantic(report: Report, plan: Report, *, completed_only: bool = True) -> Report:
    """Replay every stage of a capture.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.
    plan : dict[str, typing.Any]
        The capture's plan.
    completed_only : bool
        Whether the report must be complete, and the restore after it checked.

    Returns
    -------
    dict[str, typing.Any]
        The verified stages and the subject's UID.
    """
    require(plan["expectation"]["case"] == CASE, "Wrong settings case")
    if completed_only:
        require(report["status"] == "completed", "Transition capture did not complete")
    uid, main_uid = current_uids(report, plan)
    windows = plan["expectation"]["windows"]
    require(len(windows) == len(cases.STAGES), "Transition stage count differs")
    result = [check_stage(report, plan, w, uid, main_uid) for w in windows]
    if completed_only:
        _restore(report, windows, uid)
    return {"verified_stages": result, "subject_uid_hex": uid.hex()}
