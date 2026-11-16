"""Check what the liveness frames must show and perform the scheduled actions.

Part of the liveness runner (``native_liveness_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import dataclasses as dc
import time
import typing as typ

import native_liveness_cases as cases
from native_liveness_control_timeline import Report, Timeline, digest, need

if typ.TYPE_CHECKING:
    import datetime as dt

from native_wire_names import (
    FIELD_DATA,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import roster
from verify_native_shx import fields

AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
LOGIN_REPLY_ID = 1
# The reply that B's incomplete accept-agreement frame must never receive.
INCOMPLETE_REPLY_ID = 2
CHECK_WINDOW_SECONDS = 1
PARTIAL_WAIT_SECONDS = 1
POLL_SLICE_SECONDS = 0.05
OBSERVER_QUIET_SECONDS = 0.25
FLOWS = ("a", "b", "f", "s35", "s75", "s120")
PARTIAL_BODY_LABEL = "b121-partial-body"


def matching(frames: list[Report], name: str, identifier: int) -> list[Report]:
    """Select the type-0 replies of one flow to one request.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching reply frames, in order.
    """
    return [
        frame
        for frame in frames
        if frame["connection"] == name
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["id"] == identifier
    ]


def successful(frames: list[Report], name: str, identifier: int) -> bool:
    """Say whether a flow got exactly one reply to a request, and it succeeded.

    Returns
    -------
    bool
        ``True`` for one reply with error zero.
    """
    replies = matching(frames, name, identifier)
    return len(replies) == 1 and replies[0]["error"] == 0


def agreement_ok(frames: list[Report], name: str) -> bool:
    """Say whether a flow received exactly the controlled agreement notice.

    Returns
    -------
    bool
        ``True`` when one 109 notice carries the controlled text.
    """
    notices = [
        f
        for f in frames
        if f["connection"] == name and f["type"] == TYPE_LOGIN_AGREEMENT
    ]
    return (
        len(notices) == 1
        and notices[0]["is_reply"] == 0
        and set(fields(notices[0])) == {FIELD_DATA}
        and digest(fields(notices[0])[FIELD_DATA]) == AGREEMENT_SHA256
    )


def _went_online(frames: list[Report], name: str) -> bool:
    """Say whether a flow received a privileges notice, which marks it online.

    Returns
    -------
    bool
        ``True`` when such a notice is among the frames.
    """
    return any(
        f["connection"] == name and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
        for f in frames
    )


def check_observer(timeline: Timeline) -> None:
    """Require the observer to have logged in, come online and read the agreement."""
    need(successful(timeline.frames, "o", LOGIN_REPLY_ID), "Observer107 failed")
    need(_went_online(timeline.frames, "o"), "Observer did not become online")
    need(
        agreement_ok(timeline.frames, "o"),
        "Observer agreement differs from controlled 242 bytes",
    )


def check_b_preonline(timeline: Timeline) -> None:
    """Require B to have logged in without coming online and to be off the roster."""
    frames = timeline.frames
    need(successful(frames, "b", LOGIN_REPLY_ID), "B valid107 did not succeed")
    need(agreement_ok(frames, "b"), "B controlled agreement differs")
    need(not _went_online(frames, "b"), "B became online before complete121")
    rosters = matching(frames, "o", cases.ABSENT_OBSERVER_IDENTIFIER)
    need(len(rosters) == 1 and rosters[0]["error"] == 0, "Observer300 missing")
    need(
        all(
            bytes.fromhex(row["name_hex"]) != cases.NAME_B for row in roster(rosters[0])
        ),
        "B appeared in preonline roster",
    )


def check_failure(timeline: Timeline) -> None:
    """Require F's failed login to have exactly one non-zero reply."""
    replies = matching(timeline.frames, "f", LOGIN_REPLY_ID)
    need(len(replies) == 1 and replies[0]["error"] != 0, "F failure107 differs")


def check_complete(timeline: Timeline) -> None:
    """Require the frames inside the window to show the whole expected timeline."""
    view = Timeline(timeline.plan, time.monotonic() + CHECK_WINDOW_SECONDS)
    view.frames = timeline.frames[: timeline.window_frame_count]
    view.window_status = timeline.window_status
    check_observer(view)
    check_b_preonline(view)
    check_failure(view)
    step = cases.PACKET_STEP_SECONDS
    for at in range(step, cases.MAX_SECONDS - step + 1, step):
        need(
            successful(view.frames, "o", cases.OUTBOUND_IDENTIFIER_BASE + at // step),
            f"O500 {at} failed",
        )
    need(
        not any(
            f["connection"] == "b" and f["is_reply"] and f["id"] == INCOMPLETE_REPLY_ID
            for f in view.frames
        ),
        "Incomplete B121 received a reply",
    )
    for name in ("a", "b", "f", "s35", "s75", "s120"):
        need(name in timeline.window_status, f"Missing window observation: {name}")


def perform_operation(timeline: Timeline, op: Report, end: float) -> None:
    """Execute one generated injection or bounded observation.

    Parameters
    ----------
    timeline : Timeline
        The timeline that holds the sockets.
    op : dict[str, typing.Any]
        The scheduled operation.
    end : float
        The monotonic time by which the run must be over.

    Raises
    ------
    ValueError
        If the operation is not one the generator makes.
    """
    name = op["connection"]
    match op["op"]:
        case "admit" | "stimulus":
            timeline.connect(name)
            if op["hex"]:
                timeline.send(name, op["hex"])
            if op["op"] == "stimulus":
                timeline.poll(OBSERVER_QUIET_SECONDS)
                timeline.close(name)
                timeline.terminals.setdefault(
                    name, "client_closed_after_bounded_observation"
                )
        case "send":
            if op["label"] == PARTIAL_BODY_LABEL:
                timeline.wait_for(
                    lambda: bool(
                        matching(timeline.frames, "o", cases.ABSENT_OBSERVER_IDENTIFIER)
                    ),
                    min(PARTIAL_WAIT_SECONDS, end - time.monotonic()),
                    "observer300 at T46",
                )
                check_b_preonline(timeline)
            timeline.send(name, op["hex"])
        case "checkpoint":
            timeline.poll(0)
        case _:
            message = "Unrecognised schedule action"
            raise ValueError(message)


@dc.dataclass(slots=True)
class Epoch:
    """What the schedule is run against, and how far the window got."""

    plan: Report
    receipt: Report
    deadline_utc: dt.datetime
    end: float
    window_completed: bool = False
    window_elapsed_ns: int | None = None


def has_type(frames: list[Report], kind: int) -> bool:
    """Say whether the observer received a frame of one type.

    Returns
    -------
    bool
        ``True`` when such a frame is among the frames.
    """
    return any(f["connection"] == "o" and f["type"] == kind for f in frames)


def observer_online(timeline: Timeline) -> bool:
    """Say whether the observer has logged in, come online and read the agreement.

    Returns
    -------
    bool
        ``True`` when its 107 reply, a 354 and a 109 have all arrived.
    """
    frames = timeline.frames
    return all([
        successful(frames, "o", 1),
        has_type(frames, TYPE_PRIVILEGES_NOTIFICATION),
        has_type(frames, TYPE_LOGIN_AGREEMENT),
    ])


def perform_schedule(timeline: Timeline, epoch: Epoch, t0: float) -> None:
    """Perform each scheduled operation at its time and record where it fell."""
    for op in epoch.plan["schedule"]["operations"]:
        event_start, frame_start = (
            len(timeline.recorder.events),
            len(timeline.frames),
        )
        target = t0 + op["at_seconds"]
        need(target < epoch.end, "Scheduled action past global deadline")
        while time.monotonic() < target:
            timeline.poll(min(POLL_SLICE_SECONDS, target - time.monotonic()))
        perform_operation(timeline, op, epoch.end)
        timeline.operations.append({
            "label": op["label"],
            "at_seconds": op["at_seconds"],
            "actual_elapsed_ns": time.monotonic_ns() - timeline.recorder.started,
            "event_range": [event_start, len(timeline.recorder.events)],
            "frame_range": [frame_start, len(timeline.frames)],
            "terminals": dict(timeline.terminals),
        })
