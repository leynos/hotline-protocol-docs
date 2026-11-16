"""Check the observed presence, trials and quiet bracket of the failed rate304 case.

The checks run in a fixed order, and the first one that fails names the error, so
the helpers below are called in the order they are listed in
:func:`observed_prefix`. The update and reply checks change the recorded frames in
place, and the order of those changes is part of the check.
"""

import typing as typ

from native_wire_names import (
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_rate304_sequence_constants import (
    BURST_BARRIER_ID,
    BURST_BARS,
    BURST_UID,
    FINAL_REQUEST_SIZE,
    FINAL_REQUEST_TYPE,
    HOST_TRIAL_BOUND_NS,
    MISSING_CLIENT,
    PACED_BARS,
    PACED_UID,
    QUIET_MARK_ID,
    QUIET_MAX_NS,
    QUIET_MIN_NS,
    TEMP_ERROR,
    UPDATE_STATUS_FIELD,
)
from verify_native_rate304_sequence_support import need

if typ.TYPE_CHECKING:
    from types import ModuleType

    from verify_native_rate304_sequence_support import Modules, Report


def _check_identities(report: Report, control: ModuleType) -> tuple[int, int]:
    """Check the observer login, the subject identities and the 301 recipients.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    control : types.ModuleType
        The loaded frozen rate304 control module.

    Returns
    -------
    tuple[int, int]
        The paced and the burst user identifiers.
    """
    frames = report["frames"]
    control.login_identity(frames, "observer", control.ADMIN)
    paced_uid = control.subject_identity(frames, "paced")
    burst_uid = control.subject_identity(frames, "burst")
    need(
        (paced_uid, burst_uid) == (PACED_UID, BURST_UID)
        and report["identities"] == {"paced_uid": PACED_UID, "burst_uid": BURST_UID},
        "Dynamic roster UID differs",
    )
    counts = {
        name: sum(
            f["type"] == TYPE_PRESENCE_UPDATE and f["connection"] == name
            for f in frames
        )
        for name in ("observer", "paced", "burst")
    }
    need(
        counts == {"observer": 55, "paced": 27, "burst": 26},
        "301 recipient inventory differs",
    )
    return paced_uid, burst_uid


def _trial_arrivals(
    frames: list[Report], control: ModuleType, subject: tuple[str, int, int]
) -> list[int]:
    """Apply the icon updates of one subject and return the arrival of each reply.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case, updated in place.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    subject : tuple[str, int, int]
        The subject's name, its user identifier and its base request identifier.

    Returns
    -------
    list[int]
        The arrival time of each update and each numbered acknowledgement.
    """
    name, uid, bars = subject
    arrivals = []
    for icon in range(2, 28):
        for receiver in (name, "observer"):
            matches = [
                f
                for f in frames
                if f["connection"] == receiver
                and f["type"] == TYPE_PRESENCE_UPDATE
                and control.exact_fields(f).get(FIELD_USER_ID) == uid.to_bytes(2, "big")
                and control.exact_fields(f).get(FIELD_ICON) == icon.to_bytes(2, "big")
            ]
            need(len(matches) == 1, f"{name}/{receiver} update301 icon{icon} differs")
            control.update_frame(matches[0], uid, icon)
            need(
                control.exact_fields(matches[0])[UPDATE_STATUS_FIELD] == b"\x00\x20",
                "Update301 status differs",
            )
            arrivals.append(matches[0]["arrival_elapsed_ns"])
        ack = control.one(frames, name, 0, bars + icon - 2, 1)
        control.successful(ack)
        need(control.exact_fields(ack) == {}, "Numbered500 ACK fields differ")
        arrivals.append(ack["arrival_elapsed_ns"])
    return arrivals


def _check_trials(
    frames: list[Report],
    actions: dict[str, int],
    control: ModuleType,
    uids: tuple[int, int],
) -> dict[str, int]:
    """Check the host trial bound of each subject and record the trial durations.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case, updated in place.
    actions : dict[str, int]
        The elapsed time of each action, by label.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    uids : tuple[int, int]
        The paced and the burst user identifiers.

    Returns
    -------
    dict[str, int]
        The duration of each subject's trial, in nanoseconds.
    """
    paced_uid, burst_uid = uids
    timing: dict[str, int] = {}
    for subject in (
        ("paced", paced_uid, PACED_BARS),
        ("burst", burst_uid, BURST_BARS),
    ):
        name = subject[0]
        first = actions[f"{name}-304-00"]
        last = max(_trial_arrivals(frames, control, subject))
        need(
            0 <= last - first <= HOST_TRIAL_BOUND_NS,
            f"{name} host trial bound differs",
        )
        timing[f"{name}_trial_ns"] = last - first
    return timing


def _check_quiet(
    report: Report, actions: dict[str, int], control: ModuleType
) -> tuple[int, int]:
    """Check the host quiet bracket and that no subject request falls inside it.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    actions : dict[str, int]
        The elapsed time of each action, by label.
    control : types.ModuleType
        The loaded frozen rate304 control module.

    Returns
    -------
    tuple[int, int]
        The start and the end of the quiet bracket, in nanoseconds.
    """
    quiet_start = max(
        f["arrival_elapsed_ns"]
        for f in report["frames"]
        if f["connection"] in {"observer", "paced"}
        and (
            (
                f["type"] == TYPE_PRESENCE_UPDATE
                and control.exact_fields(f).get(FIELD_USER_ID) == b"\x00\x03"
                and control.exact_fields(f).get(FIELD_ICON) == b"\x00\x1b"
            )
            or (f["type"] == 0 and f["id"] == QUIET_MARK_ID)
        )
    )
    quiet_end = actions["paced-304-after-quiet"]
    need(
        QUIET_MIN_NS <= quiet_end - quiet_start < QUIET_MAX_NS,
        "70-second host quiet bracket differs",
    )
    need(
        not any(
            a["connection"] == "paced" and quiet_start < a["elapsed_ns"] < quiet_end
            for a in report["actions"]
        ),
        "Subject request inside quiet bracket",
    )
    return quiet_start, quiet_end


def _late_updates(frames: list[Report], paced_uid: int, control: ModuleType) -> None:
    """Apply the post-quiet icon update and check the burst terminal and ban notice.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case, updated in place.
    paced_uid : int
        The paced user identifier.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    """
    for receiver in ("observer", "paced"):
        late = [
            f
            for f in frames
            if f["connection"] == receiver
            and f["type"] == TYPE_PRESENCE_UPDATE
            and control.exact_fields(f).get(FIELD_USER_ID) == b"\x00\x03"
            and control.exact_fields(f).get(FIELD_ICON) == b"\x00\x1c"
        ]
        need(len(late) == 1, "Post-quiet icon28 update differs")
        control.update_frame(late[0], paced_uid, 28)
    control.successful(control.one(frames, "paced", 0, 2026, 1))
    need(
        not any(
            f["type"] == TYPE_PRESENCE_UPDATE
            and control.exact_fields(f).get(FIELD_USER_ID) == b"\x00\x04"
            and control.exact_fields(f).get(FIELD_ICON) == b"\x00\x1c"
            for f in frames
        ),
        "Burst terminal icon28 unexpectedly delivered",
    )
    need(
        not any(
            f["connection"] == "burst" and f["id"] == BURST_BARRIER_ID for f in frames
        ),
        "Burst terminal barrier unexpectedly replied",
    )
    need(
        not any(f["type"] == TYPE_MESSAGE_NOTIFICATION for f in frames),
        "Unexpected ban notice104",
    )


def _check_probe(frames: list[Report], control: ModuleType) -> None:
    """Check the fresh probe's temporary-ban response and that it gained no access.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    """
    probe = control.one(frames, "probe", 0, 1, 1)
    need(
        (probe["flags"], probe["error"]) == (0, 1)
        and control.exact_fields(probe) == {FIELD_ERROR_TEXT: TEMP_ERROR},
        "Fresh107 temporary-ban response differs",
    )
    need(
        not any(
            f["connection"] == "probe" and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
            for f in frames
        ),
        "Banned probe gained access",
    )


def _check_observer_reads(
    frames: list[Report], control: ModuleType, cases: ModuleType
) -> None:
    """Check the observer's four baseline requests and the retained roster.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    cases : types.ModuleType
        The loaded frozen rate304 cases module.
    """
    for kind, identifier in (
        (TYPE_ENUMERATE_ACCOUNTS, 6000),
        (TYPE_LIST_FILES, 6001),
        (TYPE_GET_FILE_INFO, 6002),
        (TYPE_GET_USER_ROSTER, 6003),
    ):
        reply = control.one(frames, "observer", 0, identifier, 1)
        control.successful(reply)
        if kind in {TYPE_ENUMERATE_ACCOUNTS, TYPE_LIST_FILES}:
            need(
                control.field_digest(reply) == control.BASELINE_FIELDS[kind],
                f"Observer {kind} baseline differs",
            )
        if kind == TYPE_GET_USER_ROSTER:
            rows = control.roster(reply)
            need(
                len(rows) == 1 and bytes.fromhex(rows[0]["name_hex"]) == cases.OBS_NAME,
                "Retained roster differs",
            )


def _check_final_request(report: Report, plan: Report, control: ModuleType) -> None:
    """Check the observer's final request, its error and the socket EOF labels.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    plan : dict[str, typing.Any]
        The prepared plan.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    """
    frames = report["frames"]
    final = control.one(frames, "observer", 0, 6004, 1)
    need(
        (final["flags"], final["error"]) == (0, 1)
        and control.exact_fields(final) == {FIELD_ERROR_TEXT: MISSING_CLIENT},
        "Final303 error differs",
    )
    raw = bytes.fromhex(
        next(a["hex"] for a in report["actions"] if a["label"] == "observer-303")
    )
    need(
        len(raw) == FINAL_REQUEST_SIZE
        and int.from_bytes(raw[:4], "big") == FINAL_REQUEST_TYPE
        and raw[-2:] == b"\x00\x00",
        "Final303 was not fieldless",
    )
    need(
        report["terminals"] == dict.fromkeys(plan["schedule"]["flows"], "eof"),
        "Socket EOF labels differ",
    )


def observed_prefix(report: Report, plan: Report, modules: Modules) -> Report:
    """Check the observed presence, the host trials and the quiet bracket.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``; its frames are updated in place.
    plan : dict[str, typing.Any]
        The prepared plan.
    modules : tuple[types.ModuleType, ...]
        The frozen modules yielded by the ``frozen`` context manager.

    Returns
    -------
    dict[str, typing.Any]
        The duration of each subject's trial and of the subject quiet bracket, in
        nanoseconds.
    """
    control, cases, _, _, _ = modules
    frames = report["frames"]
    uids = _check_identities(report, control)
    actions = {a["label"]: a["elapsed_ns"] for a in report["actions"]}
    timing = _check_trials(frames, actions, control, uids)
    quiet_start, quiet_end = _check_quiet(report, actions, control)
    _late_updates(frames, uids[0], control)
    _check_probe(frames, control)
    _check_observer_reads(frames, control, cases)
    _check_final_request(report, plan, control)
    timing["subject_quiet_ns"] = quiet_end - quiet_start
    return timing
