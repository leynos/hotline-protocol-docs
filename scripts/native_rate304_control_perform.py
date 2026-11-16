"""Perform the whole 304 reset and limit schedule on the wire.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below.
"""

import time
import typing as typ

import native_rate304_cases as cases
from native_rate304_control_frames import (
    BURST_REQUESTS,
    ICON_TERMINAL,
    MAX_UID,
    PACED_BARRIERS,
    PACED_REQUESTS,
    QUIET_SECONDS,
    ROSTER_ID,
    TRIAL_SECONDS,
    UID_BYTES,
    Report,
    exact_fields,
    need,
    one,
    successful,
    update_frame,
)
from native_rate304_control_phases import (
    observer_baseline,
    roster_uid,
    run_update_phase,
)
from native_wire_names import (
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_GET_USER_ROSTER,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from verify_native_auth import roster

if typ.TYPE_CHECKING:
    from native_rate304_control_wire import Wire

POLL_SLICE_SECONDS = 0.05
IDLE_INTERVAL_SECONDS = 5
QUIET_MARGIN_SECONDS = 30
ROSTER_WAIT_SECONDS = 2
AFTER_QUIET_WAIT_SECONDS = 5
DEPARTURE_WAIT_PACED = 2
DEPARTURE_WAIT_BURST = 3
TERMINAL_WAIT_SECONDS = 3
PROBE_WAIT_SECONDS = 3
# The request and barrier that follow the quiet interval, and the burst's last.
AFTER_QUIET_REQUEST = PACED_REQUESTS + 26
AFTER_QUIET_BARRIER = PACED_BARRIERS + 26
TERMINAL_REQUEST = BURST_REQUESTS + 26
TERMINAL_ICON_BYTES = ICON_TERMINAL.to_bytes(UID_BYTES, "big")


def _observer_solo(wire: Wire) -> None:
    """Log the observer in and require it to be alone in its own roster."""
    wire.connect_login("observer")
    wire.send(
        "observer",
        cases.observer_control(TYPE_GET_USER_ROSTER, ROSTER_ID),
        "observer-roster-initial",
    )
    wire.wait_for(
        lambda: bool(wire.match("observer", 0, ROSTER_ID, 1)),
        ROSTER_WAIT_SECONDS,
        "initial observer roster",
    )
    need(
        len(roster(one(wire.frames, "observer", 0, ROSTER_ID, 1))) == 1,
        "Observer roster not solo",
    )
    observer_row = roster(one(wire.frames, "observer", 0, ROSTER_ID, 1))[0]
    need(
        bytes.fromhex(observer_row["name_hex"]) == cases.OBS_NAME,
        "Observer identity differs",
    )
    need(1 <= observer_row["uid"] <= MAX_UID, "Observer UID invalid")
    wire.identities["observer_uid"] = observer_row["uid"]


def _idle_barrier(wire: Wire, plan: Report) -> None:
    """Send the observer's next idle barrier and require its ACK."""
    number = sum(
        action["label"].startswith("observer-idle500-") for action in wire.actions
    )
    identifier = plan["request_ids"]["observer_500_start"] + number
    wire.send("observer", cases.barrier(identifier), f"observer-idle500-{number:02d}")
    wire.wait_for(
        lambda: bool(wire.match("observer", 0, identifier, 1)),
        ROSTER_WAIT_SECONDS,
        "observer idle500 ACK",
    )
    successful(one(wire.frames, "observer", 0, identifier, 1))


def _quiet_interval(wire: Wire, plan: Report) -> float:
    """Keep the subject quiet for 70 seconds, with the observer's idle barriers.

    Returns
    -------
    float
        The monotonic time of the subject's last request.
    """
    last_subject_request = time.monotonic()
    next_observer = last_subject_request + IDLE_INTERVAL_SECONDS
    while time.monotonic() - last_subject_request < QUIET_SECONDS:
        need(
            time.monotonic() < wire.deadline - QUIET_MARGIN_SECONDS,
            "Quiet interval cannot finish",
        )
        wire.poll(min(POLL_SLICE_SECONDS, max(0, next_observer - time.monotonic())))
        if time.monotonic() >= next_observer:
            _idle_barrier(wire, plan)
            next_observer += IDLE_INTERVAL_SECONDS
    return last_subject_request


def _has_update(wire: Wire, receiver: str, uid: int, icon: bytes) -> bool:
    """Say whether a receiver got the 301 that gives a subject one icon.

    Returns
    -------
    bool
        ``True`` when such an update is among the frames.
    """
    return any(
        f["connection"] == receiver
        and f["type"] == TYPE_PRESENCE_UPDATE
        and exact_fields(f).get(FIELD_USER_ID) == uid.to_bytes(UID_BYTES, "big")
        and exact_fields(f).get(FIELD_ICON) == icon
        for f in wire.frames
    )


def _after_quiet(wire: Wire, paced_uid: int) -> None:
    """Send the 27th paced update and require its broadcast and ACK."""
    wire.send(
        "paced",
        cases.update(AFTER_QUIET_REQUEST, ICON_TERMINAL),
        "paced-304-after-quiet",
    )
    wire.send("paced", cases.barrier(AFTER_QUIET_BARRIER), "paced-500-after-quiet")
    wire.wait_for(
        lambda: (
            all(
                _has_update(wire, receiver, paced_uid, TERMINAL_ICON_BYTES)
                for receiver in ("observer", "paced")
            )
            and bool(wire.match("paced", 0, AFTER_QUIET_BARRIER, 1))
        ),
        AFTER_QUIET_WAIT_SECONDS,
        "paced 27th subject/observer301 and500 ACK",
    )
    for receiver in ("observer", "paced"):
        updates = [
            f
            for f in wire.frames
            if f["connection"] == receiver
            and f["type"] == TYPE_PRESENCE_UPDATE
            and exact_fields(f).get(FIELD_USER_ID)
            == paced_uid.to_bytes(UID_BYTES, "big")
            and exact_fields(f).get(FIELD_ICON) == TERMINAL_ICON_BYTES
        ]
        need(len(updates) == 1, f"{receiver} duplicate post-quiet301")
        update_frame(updates[0], paced_uid, ICON_TERMINAL)
    successful(one(wire.frames, "paced", 0, AFTER_QUIET_BARRIER, 1))


def _await_departure(wire: Wire, uid: int, seconds: float, label: str) -> None:
    """Wait for the observer's 302 about a subject."""
    wire.wait_for(
        lambda: any(
            f["connection"] == "observer"
            and f["type"] == TYPE_USER_LEFT
            and exact_fields(f).get(FIELD_USER_ID) == uid.to_bytes(UID_BYTES, "big")
            for f in wire.frames
        ),
        seconds,
        label,
    )


def _paced(wire: Wire, plan: Report) -> tuple[int, Report, float, float]:
    """Run the paced subject: its phase, the quiet interval and its last update.

    Returns
    -------
    tuple[int, dict[str, typing.Any], float, float]
        The subject's user id, the phase receipt, the phase's host seconds and
        the quiet seconds.
    """
    wire.connect_login("paced")
    paced_uid = roster_uid(wire, "paced")
    wire.identities["paced_uid"] = paced_uid
    first_paced = time.monotonic()
    paced_phase = run_update_phase(wire, "paced", paced_uid)
    paced_trial = time.monotonic() - first_paced
    need(paced_trial <= TRIAL_SECONDS, "Paced26 exceeded host20s bracket")
    last_subject_request = _quiet_interval(wire, plan)
    quiet = time.monotonic() - last_subject_request
    _after_quiet(wire, paced_uid)
    wire.shutdown_and_close("paced")
    _await_departure(wire, paced_uid, DEPARTURE_WAIT_PACED, "paced departure302")
    return paced_uid, paced_phase, paced_trial, quiet


def _burst(wire: Wire) -> tuple[int, Report, float]:
    """Run the burst subject to the limiter's close.

    Returns
    -------
    tuple[int, dict[str, typing.Any], float]
        The subject's user id, the phase receipt and the phase's host seconds.
    """
    wire.connect_login("burst")
    burst_uid = roster_uid(wire, "burst")
    wire.identities["burst_uid"] = burst_uid
    first_burst = time.monotonic()
    burst_phase = run_update_phase(wire, "burst", burst_uid)
    burst_trial = time.monotonic() - first_burst
    need(burst_trial <= TRIAL_SECONDS, "Burst26 exceeded host20s bracket")
    wire.send(
        "burst", cases.update(TERMINAL_REQUEST, ICON_TERMINAL), "burst-304-terminal"
    )
    wire.wait_for(
        lambda: wire.terminals.get("burst") in {"eof", "rst"},
        TERMINAL_WAIT_SECONDS,
        "terminal limiter close",
    )
    wire.shutdown_and_close("burst")
    _await_departure(wire, burst_uid, DEPARTURE_WAIT_BURST, "burst departure302")
    return burst_uid, burst_phase, burst_trial


def _probe(wire: Wire) -> None:
    """Log the probe in and require the temporary-ban refusal."""
    wire.connect_login_probe("probe")
    wire.wait_for(
        lambda: bool(wire.match("probe", 0, 1, 1)),
        PROBE_WAIT_SECONDS,
        "single ban login reply",
    )
    probe = one(wire.frames, "probe", 0, 1, 1)
    need(
        probe["error"] == 1
        and exact_fields(probe) == {FIELD_ERROR_TEXT: cases.TEMPORARY_BAN},
        "Fresh Login107 not refused by known temporary-ban path",
    )


def perform(wire: Wire, plan: Report) -> Report:
    """Run the observer, the paced subject, the burst subject and the probe.

    Parameters
    ----------
    wire : Wire
        The collector.
    plan : dict[str, typing.Any]
        The prepared plan.

    Returns
    -------
    dict[str, typing.Any]
        The user ids, the phase receipts and the host timing.
    """
    _observer_solo(wire)
    paced_uid, paced_phase, paced_trial, quiet = _paced(wire, plan)
    burst_uid, burst_phase, burst_trial = _burst(wire)
    _probe(wire)
    observer_baseline(wire, plan)
    return {
        "paced_uid": paced_uid,
        "burst_uid": burst_uid,
        "phase_receipts": {"paced": paced_phase, "burst": burst_phase},
        "timing": {
            "paced_trial_seconds": paced_trial,
            "burst_trial_seconds": burst_trial,
            "subject_quiet_seconds": quiet,
            "native_60_seconds_proven": False,
        },
    }
