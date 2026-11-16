"""Fault tables of the rate 304 tests: each mutation and the message it must raise.

The tables are data. The test module applies each mutation to a copy of a
fake report and checks that the control rejects it with the stated message.
"""

import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from rate304_support import frame, update
from verify_native_auth import ADMIN

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type FrameMutation = cabc.Callable[[dict[str, typ.Any]], object]
UNSOLICITED_302 = "Known departure or optional unassigned probe302 differs"


def _index(frames: list[dict[str, typ.Any]], **want: object) -> int:
    """Return the position of the first frame whose keys match ``want``.

    Returns
    -------
    int
        The position of the first matching frame.
    """
    return next(
        i
        for i, f in enumerate(frames)
        if all(f[key] == value for key, value in want.items())
    )


def classify_faults() -> list[tuple[FrameMutation, str]]:
    """Return the semantic faults of the classifier, with their messages.

    Returns
    -------
    list[tuple[FrameMutation, str]]
        Each mutation of a fake report and the message it must be rejected with.
    """
    return [
        (
            lambda r: r["frames"].pop(
                _index(r["frames"], connection="paced", type=301)
            ),
            "paced/paced 301 cardinality differs",
        ),
        (
            lambda r: r["frames"].pop(_index(r["frames"], connection="paced", id=2026)),
            "Missing/duplicate paced/0/2026",
        ),
        (
            lambda r: r["frames"].__setitem__(
                _index(r["frames"], connection="probe"),
                frame("probe", 0, 1, [], reply=1, when=1500),
            ),
            "Fresh Login107 does not match published temporary-ban error",
        ),
        (
            lambda r: r["timing"].__setitem__("subject_quiet_seconds", 60),
            "Trial/reset host timing differs",
        ),
        (
            lambda r: r["timing"].__setitem__("burst_trial_seconds", 22),
            "Trial/reset host timing differs",
        ),
        (
            lambda r: r["terminals"].__setitem__("burst", "bounded_no_eof"),
            "Burst limiter close not observed",
        ),
        (
            lambda r: r["identities"].__setitem__("paced_uid", 4),
            "Reported dynamic UIDs differ",
        ),
        (
            lambda r: r["frames"].__setitem__(
                _index(r["frames"], connection="paced", type=354),
                frame("paced", 354, 0, [(FIELD_ACCESS_BITMAP, ADMIN)], when=100),
            ),
            "Login access/354 differs",
        ),
        (
            lambda r: r["frames"].pop(
                _index(r["frames"], connection="observer", id=6000)
            ),
            "Missing/duplicate observer/0/6000",
        ),
        (
            lambda r: r["frames"].append(
                frame("observer", TYPE_PRESENCE_UPDATE, 0, update(3, 28), when=1200)
            ),
            "burst/observer 301 cardinality differs",
        ),
        (
            lambda r: r["frames"].append(
                frame("paced", 0, 1000, [], reply=1, when=150)
            ),
            "304 unexpectedly has a direct ACK",
        ),
    ]


def report_faults() -> list[tuple[FrameMutation, str]]:
    """Return the report-level faults, with the message each must raise.

    Returns
    -------
    list[tuple[FrameMutation, str]]
        Each mutation of a completed report and its expected rejection.
    """
    return [
        (
            lambda r: r.__setitem__("source_sha256", "0" * 64),
            "As-run plan/source/oracle identity differs",
        ),
        (
            lambda r: r.update(native_clock_calibrated=True),
            "Native clock not calibrated",
        ),
        (
            lambda r: r["actions"][10].__setitem__("label", "reordered"),
            "As-run request action schedule differs",
        ),
        (
            lambda r: r["streams"]["paced"].__setitem__("received_hex", "00"),
            "Stream bytes differ from events",
        ),
        (
            lambda r: r["terminals"].__setitem__("burst", "bounded_no_eof"),
            "Terminal label differs from bytes/events",
        ),
        (lambda r: r["frames"].pop(), "Received bytes omitted/reordered"),
        (
            lambda r: r["unparsed_hex"].__setitem__("paced", "aa"),
            "Received bytes omitted/reordered",
        ),
        (
            lambda r: r["phase_receipts"]["paced"].__setitem__(
                "completed_elapsed_ns", 99_000_000_000
            ),
            "paced pipeline timing receipt differs",
        ),
        (
            lambda r: r["phase_progress"].__setitem__("paced", 25),
            "Incomplete phase progress",
        ),
    ]


def extra_notifications() -> list[tuple[str, int, list[tuple[int, bytes]], str | None]]:
    """Return the extra notifications, each with its rejection or None if accepted.

    Returns
    -------
    list[tuple[str, int, list[tuple[int, bytes]], str | None]]
        The connection, type, fields and expected message of each notification.
    """
    return [
        (
            "observer",
            TYPE_PRESENCE_UPDATE,
            update(77, 9),
            "Unexpected/foreign observer 301",
        ),
        (
            "observer",
            TYPE_MESSAGE_NOTIFICATION,
            [(FIELD_DATA, b"unsolicited")],
            "Unexpected 104 outside bounded terminal-burst phase",
        ),
        ("observer", TYPE_USER_LEFT, [(FIELD_USER_ID, b"\0\1")], UNSOLICITED_302),
        ("observer", TYPE_USER_LEFT, [(FIELD_USER_ID, b"\0\2")], UNSOLICITED_302),
        ("observer", TYPE_USER_LEFT, [(FIELD_USER_ID, b"\0\3")], UNSOLICITED_302),
        ("observer", TYPE_USER_LEFT, [(FIELD_USER_ID, b"\0\4")], None),
    ]
