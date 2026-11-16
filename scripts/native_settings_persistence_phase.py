"""The message and phase gates of the settings persistence capture.

Part of the capture driver's module set
(``native_settings_persistence.CAPTURE_MODULES``). ``gate_pm`` checks a private
message, ``phase_gate`` checks one action of a phase, live or replayed, and
``semantic`` replays every action of a completed phase. A gate raises
``ValueError`` at the first thing a report gets wrong.
"""

import dataclasses as dc
import typing as typ

import native_settings_persistence_cases as cases
from native_settings_persistence_gates import (
    OBSERVER,
    gate_identity,
    gate_update,
    verify_plan,
)
from native_wire_names import (
    FIELD_DATA,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
)
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]
type Stage = dict[str, typ.Any]

BASELINE_PM_ID = 60
BEFORE_TEXT = b"a41-before"  # the baseline message of the first phase
AFTER_TEXT = b"a41-after-restart"  # and of the second, after the restart
ORIGINAL_OPTIONS = b"\0\1"
AUTO_OPTIONS = b"\0\4"
BASELINE_DELIVERY = 2  # offsets, after a message starts, of its gates
BASELINE_BARRIER = 8
AUTO_DELIVERY = 3
PLAIN_DELIVERY = 2
AUTO_BARRIER = 9
PLAIN_BARRIER = 8

__all__ = ["gate_pm", "phase_gate", "semantic"]


def _message_text(stage: Stage | None, phase: int) -> tuple[int, bytes]:
    """Name the message that a gate checks.

    Parameters
    ----------
    stage : dict[str, typing.Any] | None
        The stage, or ``None`` for the baseline message.
    phase : int
        The phase number.

    Returns
    -------
    tuple[int, bytes]
        The request ID and the text of the message.
    """
    if stage:
        return stage["pm_id"], bytes.fromhex(stage["pm_text_hex"])
    return BASELINE_PM_ID, BEFORE_TEXT if phase == 1 else AFTER_TEXT


def gate_pm(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the callers' shape: the report, the start, both UIDs, the phase and the stage
    report: Report,
    start: int,
    uid: bytes,
    own: bytes,
    *,
    phase: int,
    stage: Stage | None = None,
) -> None:
    """Check a private message: the acknowledgement, the delivery and the response.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    start : int
        The action that starts the message.
    uid : bytes
        The subject's UID.
    own : bytes
        The observer's UID.
    phase : int
        The phase number, which names the baseline text.
    stage : dict[str, typing.Any] | None
        The stage, or ``None`` for the baseline message.
    """
    identifier, text = _message_text(stage, phase)
    window = [
        f
        for f in report["frames"]
        if start <= f["action"] <= report["completed_actions"]
    ]
    ack = [
        f
        for f in window
        if f["connection"] == "main" and f["is_reply"] and f["id"] == identifier
    ]
    require(
        len(ack) == 1 and ack[0]["error"] == 0 and not ack[0]["fields"],
        "PM ACK differs",
    )
    original = [
        f
        for f in window
        if f["connection"] == "subject"
        and f["type"] == TYPE_MESSAGE_NOTIFICATION
        and not f["is_reply"]
    ]
    require(
        len(original) == 1
        and fields(original[0])
        == {
            FIELD_USER_ID: own,
            FIELD_NAME: OBSERVER,
            FIELD_OPTIONS: ORIGINAL_OPTIONS,
            FIELD_DATA: text,
        },
        "Original PM delivery differs",
    )
    _automatic(window, uid, stage)


def _automatic(window: list[Report], uid: bytes, stage: Stage | None) -> None:
    """Check that the observer received the automatic response if and only if it is on.

    Parameters
    ----------
    window : list[dict[str, typing.Any]]
        The frames from the start of the message.
    uid : bytes
        The subject's UID.
    stage : dict[str, typing.Any] | None
        The stage, or ``None`` for the baseline message.
    """
    automatic = [
        f
        for f in window
        if f["connection"] == "main"
        and f["type"] == TYPE_MESSAGE_NOTIFICATION
        and not f["is_reply"]
    ]
    active = bool(stage and stage["auto"])
    expected = (
        {
            FIELD_USER_ID: uid,
            FIELD_NAME: bytes.fromhex(stage["name_hex"]),
            FIELD_OPTIONS: AUTO_OPTIONS,
            FIELD_DATA: cases.MARKER_TEXT,
        }
        if active and stage
        else None
    )
    require(
        len(automatic) == int(active)
        and (not active or fields(automatic[0]) == expected),
        "Automatic PM feedback differs",
    )


@dc.dataclass(frozen=True, slots=True)
class Probe:
    """One action of a phase, with what the gates there need.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The phase's plan.
    index : int
        The action.
    phase : int
        The phase number.
    uid : bytes
        The subject's UID.
    own : bytes
        The observer's UID.
    """

    report: Report
    plan: Plan
    index: int
    phase: int
    uid: bytes
    own: bytes


def _baseline(probe: Probe) -> str | None:
    """Gate the baseline message, if the action is one of its gates.

    Parameters
    ----------
    probe : Probe
        The action.

    Returns
    -------
    str | None
        The gate that passed, or ``None``.
    """
    baseline = probe.plan["expectation"]["baseline_pm_action"]
    if probe.index not in {baseline + BASELINE_DELIVERY, baseline + BASELINE_BARRIER}:
        return None
    gate_pm(probe.report, baseline, probe.uid, probe.own, phase=probe.phase)
    return (
        "baseline-pm"
        if probe.index == baseline + BASELINE_BARRIER
        else "baseline-delivery"
    )


def _stage(probe: Probe, stage: Stage) -> str | None:
    """Gate one stage, if the action is one of its gates.

    Parameters
    ----------
    probe : Probe
        The action.
    stage : dict[str, typing.Any]
        The stage.

    Returns
    -------
    str | None
        The gate that passed, or ``None``.
    """
    update = stage["update_action"]
    if probe.index in {update, update + 1}:
        both = probe.index == update + 1
        gate_update(probe.report, probe.plan, probe.uid, stage, both=both)
        return f"{stage['label']}-301-{probe.index - update + 1}"
    pm = stage["pm_action"]
    delivery = pm + (AUTO_DELIVERY if stage["auto"] else PLAIN_DELIVERY)
    last = pm + (AUTO_BARRIER if stage["auto"] else PLAIN_BARRIER)
    if probe.index not in {delivery, last}:
        return None
    gate_pm(probe.report, pm, probe.uid, probe.own, phase=probe.phase, stage=stage)
    return f"{stage['label']}-{'barrier' if probe.index == last else 'delivery'}"


def phase_gate(report: Report, plan: Plan, index: int) -> str | None:
    """Check one action of a phase.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report, or a live recorder's frames.
    plan : dict[str, typing.Any]
        The phase's plan.
    index : int
        The action.

    Returns
    -------
    str | None
        The name of the gate that passed, or ``None`` when the action has none.
    """
    phase = int(plan["expectation"]["case"][-1])
    identity = plan["expectation"]["identity_action"]
    if index == identity:
        gate_identity(report, plan)
        return "identity"
    if index < identity:
        return None
    uid, own = gate_identity(report, plan)
    probe = Probe(report, plan, index, phase, uid, own)
    named = _baseline(probe)
    if named is not None:
        return named
    for stage in plan["expectation"].get("stages", []):
        named = _stage(probe, stage)
        if named is not None:
            return named
    return None


def semantic(report: Report, plan: Plan) -> Report:
    """Replay every stage gate of a phase; a completed phase still needs shutdown proof.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified capture report.
    plan : dict[str, typing.Any]
        The phase's plan.

    Returns
    -------
    dict[str, typing.Any]
        The status, the gates that passed and that no guest shutdown is proven.
    """
    verify_plan(plan)
    require(report["status"] == "completed", "Phase capture incomplete")
    require(report["completed_actions"] == len(plan["steps"]), "Quit EOF count differs")
    passed = []
    for index in range(plan["expectation"]["observation_actions"]):
        result = phase_gate(
            {"frames": report["frames"], "completed_actions": index + 1}, plan, index
        )
        if result is not None:
            passed.append(result)
    require(passed == report["gates"], "Live and replayed stage gates differ")
    eof = [event for event in report["events"] if event["event"] == "eof"]
    count = plan["expectation"]["observation_actions"]
    require(
        [(event["action"], event["connection"]) for event in eof]
        == [(count, "subject"), (count + 1, "main")],
        "Owned socket EOFs differ",
    )
    return {
        "status": "verified_phase_only",
        "gates": passed,
        "guest_shutdown_proven": False,
    }
