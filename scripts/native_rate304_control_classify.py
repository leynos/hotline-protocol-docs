"""Classify the measured semantic chain of the 304 reset and limit experiment.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. The checks run
in a fixed order, so a fault is reported by the first check that finds it. They
never invent a native clock or an EOF proof.
"""

import native_rate304_cases as cases
from native_control_readiness import BASELINE_FIELDS, field_digest
from native_rate304_control_frames import (
    BURST_BARRIERS,
    BURST_REQUESTS,
    ICON_FIRST,
    ICON_TERMINAL,
    MAX_UID,
    PACED_BARRIERS,
    PACED_REQUESTS,
    QUIET_SECONDS,
    ROSTER_ID,
    TRIAL_SECONDS,
    UID_BYTES,
    UPDATES,
    Report,
    exact_fields,
    login_identity,
    need,
    one,
    subject_identity,
    successful,
    update_frame,
)
from native_wire_names import (
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_GET_USER_ROSTER,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from verify_native_auth import ADMIN, roster

PHASES = (
    ("paced", PACED_REQUESTS, PACED_BARRIERS),
    ("burst", BURST_REQUESTS, BURST_BARRIERS),
)
# Each subject's 301 count at the observer, and the totals the limiter allows.
EXPECTED_301 = {"observer": 55, "paced": 27, "burst": 26}
TERMINAL_ICON_BYTES = ICON_TERMINAL.to_bytes(UID_BYTES, "big")
NOTIFICATIONS = frozenset({
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
    TYPE_MESSAGE_NOTIFICATION,
})


def _action_time(report: Report, label: str) -> int:
    """Find when the runner took the action with a label.

    Returns
    -------
    int
        The elapsed time of the action, in nanoseconds.
    """
    return next(a["elapsed_ns"] for a in report["actions"] if a["label"] == label)


def _observer(frames: list[Report]) -> int:
    """Require the observer's login and its solo initial roster.

    Returns
    -------
    int
        The observer's user id.
    """
    login_identity(frames, "observer", ADMIN)
    initial_rows = roster(one(frames, "observer", 0, ROSTER_ID, 1))
    need(
        len(initial_rows) == 1
        and bytes.fromhex(initial_rows[0]["name_hex"]) == cases.OBS_NAME,
        "Initial observer roster differs",
    )
    observer_uid = initial_rows[0]["uid"]
    need(1 <= observer_uid <= MAX_UID, "Initial observer UID invalid")
    return observer_uid


def _subject_updates(frames: list[Report], receiver: str, uid: int) -> list[Report]:
    """List the 301 updates about a subject that a receiver got.

    Returns
    -------
    list[dict[str, typing.Any]]
        The updates, in arrival order.
    """
    return [
        f
        for f in frames
        if f["connection"] == receiver
        and f["type"] == TYPE_PRESENCE_UPDATE
        and not f["is_reply"]
        and exact_fields(f).get(FIELD_USER_ID) == uid.to_bytes(UID_BYTES, "big")
    ]


def _phase(
    frames: list[Report],
    phase: tuple[str, int, int],
    uid: int,
    burst_start: int,
) -> None:
    """Check one subject's updates, barrier ACKs and absence of a direct 304 ACK."""
    name, prefix, bars = phase
    expected_subject = (
        list(range(ICON_FIRST, ICON_TERMINAL + 1))
        if name == "paced"
        else list(range(ICON_FIRST, ICON_TERMINAL))
    )
    for receiver, expected_icons in (
        ("observer", [1, *expected_subject]),
        (name, expected_subject),
    ):
        updates = [
            f
            for f in _subject_updates(frames, receiver, uid)
            if receiver != "observer"
            or (f["arrival_elapsed_ns"] < burst_start) == (name == "paced")
        ]
        need(
            len(updates) == len(expected_icons),
            f"{name}/{receiver} 301 cardinality differs",
        )
        for frame, icon in zip(updates, expected_icons, strict=True):
            update_frame(frame, uid, icon)
    for offset in range(UPDATES + (name == "paced")):
        successful(one(frames, name, 0, bars + offset, 1))
    need(
        not any(
            f["connection"] == name
            and f["is_reply"]
            and f["id"] in range(prefix, prefix + UPDATES + 1)
            for f in frames
        ),
        "304 unexpectedly has a direct ACK",
    )


def _notification_counts(frames: list[Report]) -> list[Report]:
    """Require the 301 counts per receiver, and no foreign recipient.

    Returns
    -------
    list[dict[str, typing.Any]]
        The 301, 302 and 104 notifications.
    """
    notifications = [f for f in frames if f["type"] in NOTIFICATIONS]
    for receiver, count in EXPECTED_301.items():
        need(
            sum(
                f["type"] == TYPE_PRESENCE_UPDATE and f["connection"] == receiver
                for f in notifications
            )
            == count,
            f"Unexpected/foreign {receiver} 301",
        )
    need(
        not any(
            f["type"] == TYPE_PRESENCE_UPDATE and f["connection"] not in EXPECTED_301
            for f in notifications
        ),
        "Foreign 301 recipient",
    )
    return notifications


def _departures(
    notifications: list[Report],
    uids: dict[str, int],
    times: tuple[int, int],
) -> None:
    """Require the departures of the two subjects and at most one probe.

    Parameters
    ----------
    notifications : list[dict[str, typing.Any]]
        The 301, 302 and 104 notifications.
    uids : dict[str, int]
        The user ids of the observer, the paced and the burst subject.
    times : tuple[int, int]
        The start of the burst and of the probe, in nanoseconds.
    """
    burst_start, probe_start = times
    departures = [f for f in notifications if f["type"] == TYPE_USER_LEFT]
    need(
        all(
            f["connection"] == "observer"
            and f["flags"] == 0
            and f["is_reply"] == 0
            and f["error"] == 0
            and set(exact_fields(f)) == {FIELD_USER_ID}
            and len(exact_fields(f)[FIELD_USER_ID]) == UID_BYTES
            for f in departures
        ),
        "Unexpected departure302 grammar/recipient",
    )
    paced_leave = [f for f in departures if f["arrival_elapsed_ns"] < burst_start]
    burst_leave = [
        f for f in departures if burst_start <= f["arrival_elapsed_ns"] < probe_start
    ]
    probe_leave = [f for f in departures if f["arrival_elapsed_ns"] >= probe_start]
    known = {uid.to_bytes(UID_BYTES, "big") for uid in uids.values()}
    need(
        len(paced_leave) == len(burst_leave) == 1
        and exact_fields(paced_leave[0])[FIELD_USER_ID]
        == uids["paced_uid"].to_bytes(UID_BYTES, "big")
        and exact_fields(burst_leave[0])[FIELD_USER_ID]
        == uids["burst_uid"].to_bytes(UID_BYTES, "big")
        and len(probe_leave) <= 1
        and all(exact_fields(f)[FIELD_USER_ID] not in known for f in probe_leave),
        "Known departure or optional unassigned probe302 differs",
    )


def _notices(notifications: list[Report], terminal_start: int) -> None:
    """Require at most one 104, from the burst subject after its terminal 304."""
    notices = [f for f in notifications if f["type"] == TYPE_MESSAGE_NOTIFICATION]
    need(
        len(notices) <= 1
        and all(
            f["connection"] == "burst"
            and f["flags"] == 0
            and f["is_reply"] == 0
            and f["error"] == 0
            and f["arrival_elapsed_ns"] >= terminal_start
            and bool(exact_fields(f))
            for f in notices
        ),
        "Unexpected 104 outside bounded terminal-burst phase",
    )


def _probe(frames: list[Report]) -> None:
    """Require the probe's login to be refused with the temporary-ban text."""
    probe = one(frames, "probe", 0, 1, 1)
    need(
        probe["flags"] == 0
        and probe["error"] == 1
        and exact_fields(probe) == {FIELD_ERROR_TEXT: cases.TEMPORARY_BAN},
        "Fresh Login107 does not match published temporary-ban error",
    )
    need(
        not any(
            f["connection"] == "probe" and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
            for f in frames
        ),
        "Ban probe unexpectedly gained access",
    )


def _controls(frames: list[Report], plan: Report, observer_uid: int) -> None:
    """Require each retained observer control to match its baseline."""
    controls = plan["request_ids"]["observer_controls"]
    for kind_text, identifier in controls.items():
        kind = int(kind_text)
        reply = one(frames, "observer", 0, identifier, 1)
        successful(reply)
        if kind in BASELINE_FIELDS:
            need(
                field_digest(reply) == BASELINE_FIELDS[kind],
                "Observer baseline hash differs",
            )
        if kind == TYPE_GET_USER_ROSTER:
            rows = roster(reply)
            need(
                len(rows) == 1 and bytes.fromhex(rows[0]["name_hex"]) == cases.OBS_NAME,
                "Observer post-ban roster differs",
            )
            need(rows[0]["uid"] == observer_uid, "Observer post-ban roster UID differs")


def _timing(plan: Report, report: Report) -> None:
    """Require the host timing, the clock claim and the terminal labels."""
    timing = report["timing"]
    need(
        timing["paced_trial_seconds"] <= TRIAL_SECONDS
        and timing["burst_trial_seconds"] <= TRIAL_SECONDS
        and timing["subject_quiet_seconds"] >= QUIET_SECONDS,
        "Trial/reset host timing differs",
    )
    need(
        timing["native_60_seconds_proven"] is False,
        "Native clock cannot be inferred from host timing",
    )
    need(
        report["terminals"].get("burst") in {"eof", "rst"},
        "Burst limiter close not observed",
    )
    need(
        all(name in report["terminals"] for name in plan["schedule"]["flows"]),
        "Missing finite terminal classification",
    )


def classify(plan: Report, report: Report) -> None:
    """Check measured semantic chain; never invent native clock or EOF proof.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The run's report.
    """
    frames = report["frames"]
    observer_uid = _observer(frames)
    paced_uid = subject_identity(frames, "paced")
    burst_uid = subject_identity(frames, "burst")
    burst_start = _action_time(report, "burst-login")
    uids = {
        "observer_uid": observer_uid,
        "paced_uid": paced_uid,
        "burst_uid": burst_uid,
    }
    need(report["identities"] == uids, "Reported dynamic UIDs differ")
    for phase, uid in zip(PHASES, (paced_uid, burst_uid), strict=True):
        _phase(frames, phase, uid, burst_start)
    need(
        not any(
            f["connection"] in {"observer", "burst"}
            and f["type"] == TYPE_PRESENCE_UPDATE
            and f["arrival_elapsed_ns"] >= burst_start
            and exact_fields(f).get(FIELD_USER_ID)
            == burst_uid.to_bytes(UID_BYTES, "big")
            and exact_fields(f).get(FIELD_ICON) == TERMINAL_ICON_BYTES
            for f in frames
        ),
        "Terminal 27th 304 unexpectedly broadcast 301",
    )
    notifications = _notification_counts(frames)
    probe_start = _action_time(report, "probe-login")
    terminal_start = _action_time(report, "burst-304-terminal")
    _departures(notifications, uids, (burst_start, probe_start))
    _notices(notifications, terminal_start)
    _probe(frames)
    _controls(frames, plan, observer_uid)
    _timing(plan, report)
