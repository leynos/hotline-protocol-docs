"""Fake frames, roster records, the fake report and the report's readings.

The builders make the frames that the fake wire emits and the report that the
control verifies. The readings derive the phase membership, the phase receipt
and the per-connection streams of a run. Nothing here asserts.
"""

import typing as typ

import native_rate304_cases as cases
import native_rate304_control as control
from native_plan import packet, payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_UNNAMED_WORD,
    FIELD_USER_ID,
    FIELD_USER_RECORD,
    FIELD_VERSION,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from protocol_capture import decode_frame
from verify_classic_native_baseline import AGREEMENT
from verify_native_auth import ADMIN

if typ.TYPE_CHECKING:
    from rate304_wire import Trace

ENV = {
    "fixture_profile": "control-only",
    "emulator_pid": 100,
    "emulator_starttime": "123",
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 456,
    "owned_working_image": "/ignored/working.dsk",
    "owned_working_image_inode": 789,
}
UPDATE_FLAG_FIELD = 112  # the zero byte that each presence update carries
ROSTER_REQUEST_ID = 10  # the identifier of the 300 roster request and its reply
PRIVILEGES_REPLY_IDENTIFIER = 0  # the identifier of the 354 privileges notice
LOGIN_AGREEMENT_IDENTIFIER = 0  # the identifier of the 109 agreement notice
FIRST_UPDATE_ICON = 2  # the first of the 26 ordered presence icons
LAST_UPDATE_ICON = 27  # the last of the 26 ordered presence icons


def frame(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the fakes name the reply, error and arrival fields
    name: str,
    kind: int,
    identifier: int,
    fields: list[tuple[int, bytes]],
    *,
    reply: int = 0,
    error: int = 0,
    when: int = 0,
) -> dict[str, typ.Any]:
    """Build one fake frame with its raw bytes and its decoded fields.

    Returns
    -------
    dict[str, typ.Any]
        The connection, the raw hex, the arrival time and the decoded frame.
    """
    raw = bytes.fromhex(
        packet(kind, identifier, payload(fields), reply=reply, error=error)
    )
    return {
        "connection": name,
        "raw_hex": raw.hex(),
        "arrival_elapsed_ns": when,
        **decode_frame(raw),
    }


def roster(uid: int, icon: int, name: bytes) -> bytes:
    """Pack one roster record: UID, icon, a zero status and the name.

    Returns
    -------
    bytes
        The packed roster record.
    """
    return (
        uid.to_bytes(2, "big")
        + icon.to_bytes(2, "big")
        + b"\0\0"
        + len(name).to_bytes(2, "big")
        + name
    )


def update(uid: int, icon: int) -> list[tuple[int, bytes]]:
    """Return the fields of one presence update for a user.

    Returns
    -------
    list[tuple[int, bytes]]
        The user identifier, icon, flag and name fields of the update.
    """
    return [
        (FIELD_USER_ID, uid.to_bytes(2, "big")),
        (FIELD_ICON, icon.to_bytes(2, "big")),
        (UPDATE_FLAG_FIELD, b"\0"),
        (FIELD_NAME, cases.SUBJECT_NAME),
    ]


def fake_report(plan: dict[str, typ.Any], observer_uid: int = 1) -> dict[str, typ.Any]:
    """Build the frames, identities, actions, timing and terminals of a fake run.

    Returns
    -------
    dict[str, typ.Any]
        The fake report that the control classifies.
    """
    frames: list[dict[str, typ.Any]] = []

    def add(
        name: str,
        kind: int,
        identifier: int,
        fields: list[tuple[int, bytes]],
        **options: int,
    ) -> None:
        """Append one frame, with its reply, error and arrival options."""
        frames.append(frame(name, kind, identifier, fields, **options))

    for name, access, when in (
        ("observer", ADMIN, 0),
        ("paced", bytes(8), 100),
        ("burst", bytes(8), 1100),
    ):
        add(
            name,
            0,
            1,
            [(FIELD_VERSION, b"\0\xbe"), (FIELD_UNNAMED_WORD, b"\0\0")],
            reply=1,
            when=when,
        )
        add(
            name,
            TYPE_PRIVILEGES_NOTIFICATION,
            PRIVILEGES_REPLY_IDENTIFIER,
            [(FIELD_ACCESS_BITMAP, access)],
            when=when,
        )
        add(
            name,
            TYPE_LOGIN_AGREEMENT,
            LOGIN_AGREEMENT_IDENTIFIER,
            [(FIELD_DATA, AGREEMENT)],
            when=when,
        )
    add(
        "observer",
        0,
        ROSTER_REQUEST_ID,
        [(FIELD_USER_RECORD, roster(observer_uid, 1, cases.OBS_NAME))],
        reply=1,
        when=0,
    )
    for name, uid, when in (("paced", 2, 100), ("burst", 3, 1100)):
        add(
            name,
            0,
            ROSTER_REQUEST_ID,
            [
                (FIELD_USER_RECORD, roster(observer_uid, 1, cases.OBS_NAME)),
                (FIELD_USER_RECORD, roster(uid, 1, cases.SUBJECT_NAME)),
            ],
            reply=1,
            when=when,
        )
        add("observer", TYPE_PRESENCE_UPDATE, 0, update(uid, 1), when=when)
        for index in range(26):
            add(
                "observer",
                TYPE_PRESENCE_UPDATE,
                0,
                update(uid, index + 2),
                when=when + index + 1,
            )
            add(
                name,
                TYPE_PRESENCE_UPDATE,
                0,
                update(uid, index + 2),
                when=when + index + 1,
            )
            add(
                name,
                0,
                (2000 if name == "paced" else 4000) + index,
                [],
                reply=1,
                when=when + index + 1,
            )
    add("observer", TYPE_PRESENCE_UPDATE, 0, update(2, 28), when=1000)
    add("paced", TYPE_PRESENCE_UPDATE, 0, update(2, 28), when=1000)
    add("paced", 0, 2026, [], reply=1, when=1000)
    add("observer", 302, 0, [(FIELD_USER_ID, b"\0\2")], when=1001)
    add("observer", 302, 0, [(FIELD_USER_ID, b"\0\3")], when=1400)
    add(
        "probe",
        0,
        1,
        [(FIELD_ERROR_TEXT, cases.TEMPORARY_BAN)],
        reply=1,
        error=1,
        when=1500,
    )
    for kind, identifier in plan["request_ids"]["observer_controls"].items():
        if kind == "300":
            data = [(FIELD_USER_RECORD, roster(observer_uid, 1, cases.OBS_NAME))]
        else:
            data = [(FIELD_DATA, b"fixture")]
        add("observer", 0, identifier, data, reply=1, when=1600)
    return {
        "frames": frames,
        "identities": {"observer_uid": observer_uid, "paced_uid": 2, "burst_uid": 3},
        "actions": [
            {"label": "burst-login", "elapsed_ns": 1050},
            {"label": "burst-304-terminal", "elapsed_ns": 1350},
            {"label": "probe-login", "elapsed_ns": 1450},
        ],
        "timing": {
            "paced_trial_seconds": 9,
            "burst_trial_seconds": 9,
            "subject_quiet_seconds": 71,
            "native_60_seconds_proven": False,
        },
        "terminals": {
            "observer": "bounded_no_eof",
            "paced": "bounded_no_eof",
            "burst": "eof",
            "probe": "bounded_no_eof",
        },
    }


def in_phase(record: dict[str, typ.Any], name: str) -> bool:
    """Tell whether an observed frame belongs to the phase of one subject.

    Returns
    -------
    bool
        True for a presence notice of the subject, or a reply of its phase.
    """
    return (
        record["connection"] in {name, "observer"}
        and record["type"] == TYPE_PRESENCE_UPDATE
        and control.exact_fields(record).get(FIELD_USER_ID)
        == (2 if name == "paced" else 3).to_bytes(2, "big")
        and FIRST_UPDATE_ICON
        <= int.from_bytes(control.exact_fields(record).get(FIELD_ICON, b"\0\0"), "big")
        <= LAST_UPDATE_ICON
    ) or (
        record["connection"] == name
        and record["type"] == 0
        and record["is_reply"] == 1
        and record["id"]
        in range(2000 if name == "paced" else 4000, 2026 if name == "paced" else 4026)
    )


def phase_receipt(
    plan: dict[str, typ.Any], trace: Trace, name: str
) -> dict[str, typ.Any]:
    """Build the phase receipt of one subject from the run.

    Returns
    -------
    dict[str, typ.Any]
        The mode and the start, send and completion times of the phase.
    """
    sent = next(
        a["elapsed_ns"] for a in trace.actions if a["label"] == f"{name}-500-25"
    )
    return {
        "mode": plan["schedule"]["phase_mode"],
        "started_elapsed_ns": next(
            a["elapsed_ns"] for a in trace.actions if a["label"] == f"{name}-304-00"
        )
        - 1,
        "all_pairs_sent_elapsed_ns": sent,
        "completed_elapsed_ns": max(
            sent,
            *(
                record["arrival_elapsed_ns"]
                for record in trace.observed
                if in_phase(record, name)
            ),
        ),
    }


def stream_bytes(events: list[dict[str, typ.Any]]) -> dict[str, dict[str, str]]:
    """Join the sent and received bytes of each connection from the events.

    Returns
    -------
    dict[str, dict[str, str]]
        Per connection, the sent and the received hex text.
    """
    streams: dict[str, dict[str, str]] = {}
    for event in events:
        view = streams.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        match event["event"]:
            case "send":
                view["sent_hex"] += event["hex"]
            case "receive":
                view["received_hex"] += event["hex"]
    return streams
