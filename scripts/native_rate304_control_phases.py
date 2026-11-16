"""Run and check one 26-update phase of a 304 subject.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below.
"""

import time
import typing as typ

import native_rate304_cases as cases
from native_rate304_control_frames import (
    BURST_BARRIERS,
    BURST_REQUESTS,
    ICON_FIRST,
    ICON_TERMINAL,
    PACED_BARRIERS,
    PACED_REQUESTS,
    ROSTER_ID,
    TRIAL_SECONDS,
    UID_BYTES,
    UPDATES,
    Report,
    exact_fields,
    need,
    one,
    subject_identity,
    successful,
    update_frame,
)
from native_wire_names import (
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_GET_USER_ROSTER,
    TYPE_PRESENCE_UPDATE,
)
from verify_native_auth import roster

if typ.TYPE_CHECKING:
    from native_rate304_control_wire import Wire

ROSTER_WAIT_SECONDS = 2
CONTROL_WAIT_SECONDS = 3
OBSERVER_SOLO = 1
OBSERVER_CONTROL_TYPE = 303
MAX_UID = 65535


def _bases(name: str) -> tuple[int, int]:
    """Give the request and barrier identifier bases of a subject.

    Returns
    -------
    tuple[int, int]
        The first request identifier and the first barrier identifier.
    """
    if name == "paced":
        return PACED_REQUESTS, PACED_BARRIERS
    return BURST_REQUESTS, BURST_BARRIERS


def _updates_to(wire: Wire, receiver: str, uid: int, icon: int) -> list[Report]:
    """List a receiver's 301 updates that give a subject one icon.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching updates, in arrival order.
    """
    return [
        f
        for f in wire.frames
        if f["connection"] == receiver
        and f["type"] == TYPE_PRESENCE_UPDATE
        and exact_fields(f).get(FIELD_USER_ID) == uid.to_bytes(UID_BYTES, "big")
        and exact_fields(f).get(FIELD_ICON) == icon.to_bytes(UID_BYTES, "big")
    ]


def update_and_barrier(wire: Wire, name: str, index: int, uid: int) -> None:
    """Send one ordered pair; its replies are checked at phase completion."""
    del uid
    requests, barriers = _bases(name)
    icon = index + ICON_FIRST
    wire.send(name, cases.update(requests + index, icon), f"{name}-304-{index:02d}")
    wire.send(name, cases.barrier(barriers + index), f"{name}-500-{index:02d}")


def phase_complete(wire: Wire, name: str, uid: int) -> bool:
    """Say whether the phase is ready; full cardinality and grammar follow.

    Returns
    -------
    bool
        ``True`` when every update and barrier ACK of the phase has arrived.
    """
    expected_uid = uid.to_bytes(UID_BYTES, "big")
    barriers = _bases(name)[1]
    for index in range(UPDATES):
        icon = (index + ICON_FIRST).to_bytes(UID_BYTES, "big")
        for receiver in ("observer", name):
            if not any(
                f["connection"] == receiver
                and f["type"] == TYPE_PRESENCE_UPDATE
                and f["is_reply"] == 0
                and exact_fields(f).get(FIELD_USER_ID) == expected_uid
                and exact_fields(f).get(FIELD_ICON) == icon
                for f in wire.frames
            ):
                return False
        if not wire.match(name, 0, barriers + index, 1):
            return False
    return True


def _foreign_updates(wire: Wire, name: str, uid: int, started_frames: int) -> None:
    """Require every 301 of the phase to be about the subject, within its icons."""
    for frame in wire.frames[started_frames:]:
        if (
            frame["connection"] in {"observer", name}
            and frame["type"] == TYPE_PRESENCE_UPDATE
        ):
            content = exact_fields(frame)
            need(
                content.get(FIELD_USER_ID) == uid.to_bytes(UID_BYTES, "big")
                and ICON_FIRST
                <= int.from_bytes(content.get(FIELD_ICON, b""), "big")
                <= ICON_TERMINAL - 1,
                f"{name} foreign 301 during phase",
            )


def _exact_pairs(wire: Wire, name: str, uid: int) -> None:
    """Require one update per receiver and one barrier ACK for each icon."""
    barriers = _bases(name)[1]
    for index in range(UPDATES):
        icon = index + ICON_FIRST
        for receiver in ("observer", name):
            matches = _updates_to(wire, receiver, uid, icon)
            need(len(matches) == 1, f"{receiver} duplicate 301 icon{icon}")
            update_frame(matches[0], uid, icon)
        successful(one(wire.frames, name, 0, barriers + index, 1))


def run_update_phase(
    wire: Wire, name: str, uid: int, seconds: float = TRIAL_SECONDS
) -> Report:
    """Pipeline exact requests, then drain all owned sockets until complete.

    Parameters
    ----------
    wire : Wire
        The collector.
    name : str
        The subject, ``paced`` or ``burst``.
    uid : int
        The subject's user id.
    seconds : float
        The host-time bracket of the whole phase.

    Returns
    -------
    dict[str, typing.Any]
        The phase receipt with its three elapsed times.
    """
    started = time.monotonic()
    started_ns = time.monotonic_ns() - wire.recorder.started
    started_frames = len(wire.frames)
    for index in range(UPDATES):
        update_and_barrier(wire, name, index, uid)
        need(time.monotonic() - started <= seconds, f"{name}26 send window exceeded")
    sent_ns = time.monotonic_ns() - wire.recorder.started
    wire.wait_for(
        lambda: phase_complete(wire, name, uid),
        max(0, seconds - (time.monotonic() - started)),
        f"{name} 26 subject/observer301 and500 ACKs",
    )
    completed_ns = time.monotonic_ns() - wire.recorder.started
    need(time.monotonic() - started <= seconds, f"{name}26 host bracket exceeded")
    _foreign_updates(wire, name, uid, started_frames)
    _exact_pairs(wire, name, uid)
    return {
        "mode": wire.plan["schedule"]["phase_mode"],
        "started_elapsed_ns": started_ns,
        "all_pairs_sent_elapsed_ns": sent_ns,
        "completed_elapsed_ns": completed_ns,
    }


def validated_phase_progress(wire: Wire, name: str, uid: int) -> int:
    """Count only the contiguous exact pairs present in a partial capture.

    Returns
    -------
    int
        The number of leading pairs that are complete and exact.
    """
    barriers = _bases(name)[1]
    for index in range(UPDATES):
        try:
            for receiver in ("observer", name):
                matches = _updates_to(wire, receiver, uid, index + ICON_FIRST)
                need(len(matches) == 1, "Missing/duplicate update")
                update_frame(matches[0], uid, index + ICON_FIRST)
            successful(one(wire.frames, name, 0, barriers + index, 1))
        except ValueError, KeyError, IndexError:
            return index
    return UPDATES


def roster_uid(wire: Wire, name: str) -> int:
    """Ask a subject for the roster and return its own user id.

    Returns
    -------
    int
        The subject's user id.
    """
    wire.send(
        name, cases.observer_control(TYPE_GET_USER_ROSTER, ROSTER_ID), f"{name}-roster"
    )
    wire.wait_for(
        lambda: bool(wire.match(name, 0, ROSTER_ID, 1)),
        ROSTER_WAIT_SECONDS,
        f"{name} roster",
    )
    return subject_identity(wire.frames, name)


def _await_control(wire: Wire, identifier: int, kind: int) -> Report:
    """Wait for one observer control's reply and require it to succeed.

    Returns
    -------
    dict[str, typing.Any]
        The reply.
    """
    wire.wait_for(
        lambda: bool(wire.match("observer", 0, identifier, 1)),
        CONTROL_WAIT_SECONDS,
        f"observer control {kind}",
    )
    reply = one(wire.frames, "observer", 0, identifier, 1)
    successful(reply)
    return reply


def observer_baseline(wire: Wire, plan: Report) -> None:
    """Take each retained observer control once more, after the ban."""
    observer_uid = wire.identities["observer_uid"]
    for kind_text, identifier in plan["request_ids"]["observer_controls"].items():
        kind = int(kind_text)
        wire.send(
            "observer",
            cases.observer_control(
                kind,
                identifier,
                observer_uid if kind == OBSERVER_CONTROL_TYPE else None,
            ),
            f"observer-{kind}",
        )
        reply = _await_control(wire, identifier, kind)
        if kind == TYPE_GET_USER_ROSTER:
            rows = roster(reply)
            need(
                len(rows) == OBSERVER_SOLO and rows[0]["uid"] == observer_uid,
                "Observer post-ban roster UID differs before 303",
            )
