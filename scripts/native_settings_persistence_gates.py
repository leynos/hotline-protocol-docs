"""The stage gates of the settings persistence capture.

Part of the capture driver's module set
(``native_settings_persistence.CAPTURE_MODULES``). ``phase_gate`` checks one
action of a phase, live or replayed, and ``semantic`` replays every action of a
completed phase. A gate raises ``ValueError`` at the first thing a report gets
wrong.
"""

import typing as typ

import native_settings_persistence_cases as cases
from native_control_readiness import login_gate, readiness
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from verify_native_auth import ADMIN, reply, roster
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]
type Stage = dict[str, typ.Any]

CASES = {"settings-persistence-phase1", "settings-persistence-phase2"}
OBSERVER = b"framing-fixture"
OBSERVER_ROSTER_ID = 10
LOGIN_FRAMES = 3
SUBJECT_LOGIN_FRAMES = 3
UID_BYTES = 2
SUBJECT_ICON = b"\0\3"

__all__ = [
    "frame_at",
    "gate_identity",
    "gate_readiness",
    "gate_update",
    "verify_plan",
]


def frame_at(report: Report, index: int, connection: str, kind: int) -> Report:
    """Find the one notification of a kind that a connection received at an action.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    index : int
        The action.
    connection : str
        The connection.
    kind : int
        The transaction type.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    found = [
        frame
        for frame in report["frames"]
        if (frame["action"], frame["connection"], frame["type"], frame["is_reply"])
        == (index, connection, kind, 0)
    ]
    require(len(found) == 1, f"Action {index}: expected one {kind} on {connection}")
    return found[0]


def gate_readiness(report: Report, plan: Plan) -> None:
    """Check the readiness capture that must precede a phase.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The readiness report.
    plan : dict[str, typing.Any]
        The readiness plan.

    Raises
    ------
    ValueError
        With the first failure, prefixed ``readiness:``.
    """
    try:
        require(report["status"] == "completed", "capture failed")
        require(plan["expectation"]["case"] == "control-readiness", "wrong case")
        require(plan["steps"] == cases.control.plans()["readiness"], "steps differ")
        readiness(report)
    except (KeyError, ValueError) as error:
        message = f"readiness: {error}"
        raise ValueError(message) from error


def _observer(report: Report) -> bytes:
    """Check the observer's login and roster, and read its UID.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.

    Returns
    -------
    bytes
        The observer's UID.
    """
    login_gate(report["frames"][:LOGIN_FRAMES])
    users = roster(reply(report, OBSERVER_ROSTER_ID))
    require(
        len(users) == 1 and bytes.fromhex(users[0]["name_hex"]) == OBSERVER,
        "Initial observer identity differs",
    )
    return users[0]["uid"].to_bytes(UID_BYTES, "big")


def gate_identity(report: Report, plan: Plan) -> tuple[bytes, bytes]:
    """Check both sessions' identities and read their UIDs.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The phase's plan.

    Returns
    -------
    tuple[bytes, bytes]
        The subject's UID and the observer's.
    """
    own = _observer(report)
    subject_frames = [f for f in report["frames"] if f["connection"] == "subject"]
    require(
        len(subject_frames) >= SUBJECT_LOGIN_FRAMES
        and subject_frames[0]["is_reply"]
        and subject_frames[0]["id"] == 1
        and subject_frames[0]["error"] == 0
        and fields(subject_frames[1]) == {FIELD_ACCESS_BITMAP: ADMIN}
        and subject_frames[2]["type"] == TYPE_LOGIN_AGREEMENT,
        "Subject login/privileges/agreement differ",
    )
    announced = fields(
        frame_at(
            report, plan["expectation"]["identity_action"], "main", TYPE_PRESENCE_UPDATE
        )
    )
    uid = announced.get(FIELD_USER_ID, b"")
    require(
        len(uid) == UID_BYTES
        and uid != own
        and announced.get(FIELD_NAME) == cases.BASELINE_NAME
        and announced.get(FIELD_ICON) == SUBJECT_ICON,
        "Subject identity/name/icon differs",
    )
    return uid, own


def gate_update(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the callers' shape: the plan, the UID and the stage, as the phase gate passes them
    report: Report,
    plan: Plan,
    uid: bytes,
    stage: Stage | None = None,
    *,
    both: bool = True,
) -> None:
    """Check the 301 that the subject's settings change sends.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The phase's plan.
    uid : bytes
        The subject's UID.
    stage : dict[str, typing.Any] | None
        The stage; the plan's first stage when omitted.
    both : bool
        Whether the subject's own connection has received it as well.
    """
    stage = stage or plan["expectation"]["stages"][0]
    index = stage["update_action"]
    names = ("main", "subject") if both else ("main",)
    for offset, name in enumerate(names):
        value = fields(frame_at(report, index + offset, name, TYPE_PRESENCE_UPDATE))
        require(
            value.get(FIELD_USER_ID) == uid
            and value.get(FIELD_NAME) == bytes.fromhex(stage["name_hex"])
            and value.get(FIELD_ICON) == bytes.fromhex(stage["icon_hex"]),
            f"{stage['label']} 301 update differs on {name}",
        )


def verify_plan(plan: Plan) -> int:
    """Check that a plan is the one the planner prepares, and read its phase.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The plan.

    Returns
    -------
    int
        The phase number.
    """
    validate_plan(plan)
    case = plan["expectation"]["case"]
    require(case in CASES, "Wrong case")
    phase = int(case[-1])
    env = plan["environment"]
    port = plan["endpoints"]["control"]["port"]
    require(plan == cases.plans(env, port)[f"phase{phase}"], "Prepared plan changed")
    require(
        env["fixture_profile"] == "control-only"
        and env["full_file_baseline"] == "not_exercised"
        and plan["oracle_sha256"] == ORACLE_SHA256,
        "Profile/oracle differs",
    )
    return phase
