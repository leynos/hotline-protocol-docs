"""Check each controlled queue case: modes, cancellation, ordering and expiry.

Each check reads the report of one capture, returns the queue positions that the
case promises, and fails with a message that names what differed.
"""

import dataclasses as dc
import typing as typ

from native_wire_names import (
    FIELD_FILE_SIZE,
    FIELD_QUEUE_POSITION,
    FIELD_TRANSFER_SIZE,
    FRAME_HEADER_BYTES,
)
from verify_native_core import require
from verify_native_forks import fields
from verify_native_queue_support import check_download, frame_time, reply

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]
type Positions = dict[str, int | None]
type Notes = dict[str, list[int]]

HEX_PER_BYTE = 2
HEADER_HEX_CHARS = FRAME_HEADER_BYTES * HEX_PER_BYTE
ID_START = 4  # the request ID is header bytes 4 to 8
ID_END = 8
TIMED_OUT = "queue-pending-timeout"

# transfer-contracts.md, "Queue" mode table: the six queued modes follow one
# blocker, and the sizes are those of the ordinary, preview and empty fixtures.
MODE_FIRST = 11
MODE_LAST = 16
MODE_PREVIEW = 15
MODE_EMPTY = 16
ZERO_PREVIEW_REQUEST = 17
FORK_TRANSFER_BYTES = 510
PREVIEW_TRANSFER_BYTES = 13
EMPTY_TRANSFER_BYTES = 181
LOGICAL_BYTES = 330
NONOWNER_REQUEST = 26
CLEANUP_REQUESTS = [30, 31, 32, 33]
ACK_PAYLOAD_HEX = "0000"
PAUSE_COUNT = 12
PAUSE_SECONDS = 45
NANOSECONDS_PER_SECOND = 1e9
MICROSECONDS_PER_SECOND = 1e6
# The pending entry ages out after 500 seconds; the observation is bounded.
MIN_PENDING_AGE = 490
MAX_PENDING_AGE = 570
QUIET_EVENTS = 2
TIMER_SCOPE = "Host observer timing; no exact Mac-clock deadline claimed"


@dc.dataclass(frozen=True, slots=True)
class Capture:
    """One queue capture and what has been read out of it.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The retained capture report.
    plan : dict[str, typing.Any]
        The retained plan.
    packets : dict[str, typing.Any]
        The packet observations of each connection.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    refs : dict[str, dict[str, typing.Any]]
        The saved references.
    notes : dict[str, list[dict[str, typing.Any]]]
        The queue notifications of each reference.
    """

    report: Report
    plan: Report
    packets: dict[str, typ.Any]
    guest: list[dict[str, typ.Any]]
    refs: dict[str, dict[str, typ.Any]]
    notes: dict[str, list[dict[str, typ.Any]]]


@dc.dataclass(frozen=True, slots=True)
class Expected:
    """What a case promises about queue positions, and any timing it measured.

    Attributes
    ----------
    initial : dict[str, int | None]
        The queue position in each initial ACK, or ``None`` when omitted.
    notes : dict[str, list[int]]
        The positions of the notifications that each transfer receives.
    timing : dict[str, typing.Any]
        Extra observations to report.
    """

    initial: Positions
    notes: Notes
    timing: dict[str, typ.Any] = dc.field(default_factory=dict)


def _mode_transfer_bytes(index: int) -> int:
    """Return the advertised size of the queued mode at ``index``.

    Returns
    -------
    int
        The size that transfer-contracts.md gives for that mode.
    """
    if index == MODE_PREVIEW:
        return PREVIEW_TRANSFER_BYTES
    return EMPTY_TRANSFER_BYTES if index == MODE_EMPTY else FORK_TRANSFER_BYTES


def check_mode_matrix(capture: Capture) -> Expected:
    """Check the six queued modes behind one blocker.

    Returns
    -------
    Expected
        The positions that the six modes and the blocker are promised.
    """
    indexes = range(MODE_FIRST, MODE_LAST + 1)
    zero = fields(reply(capture.report, "a", ZERO_PREVIEW_REQUEST))
    require(
        set(zero) == {FIELD_TRANSFER_SIZE} and zero[FIELD_TRANSFER_SIZE] == b"\0\0",
        "Empty preview queued or allocated reference",
    )
    for index in indexes:
        values = capture.refs[f"m{index}"]["values"]
        require(
            int.from_bytes(values[FIELD_TRANSFER_SIZE], "big")
            == _mode_transfer_bytes(index),
            "Mode transfer size differs",
        )
        require(
            int.from_bytes(values[FIELD_FILE_SIZE], "big")
            == (0 if index == MODE_EMPTY else LOGICAL_BYTES),
            "Mode logical size differs",
        )
        check_download(
            capture.report,
            capture.refs,
            f"m{index}",
            preview=index == MODE_PREVIEW,
            empty=index == MODE_EMPTY,
        )
    return Expected(
        {"blocker": None, **{f"m{i}": i - MODE_FIRST + 1 for i in indexes}},
        {
            "blocker": [],
            **{f"m{i}": list(range(i - MODE_FIRST, -1, -1)) for i in indexes},
        },
    )


def check_cancel_position(capture: Capture) -> Expected:
    """Check that cancelling a queued transfer closes it and moves the rest up.

    Returns
    -------
    Expected
        The positions of the four queued transfers.
    """
    require(
        not capture.report["streams"]["a3"]["received_hex"],
        "Cancelled queued transfer delivered data",
    )
    require(
        capture.packets["a3"]["guest_server_initiated_close"],
        "Queued cancellation did not close native data transport",
    )
    check_download(capture.report, capture.refs, "a4")
    return Expected(
        {"a1": None, "a2": 1, "a3": 2, "a4": 3},
        {"a1": [], "a2": [], "a3": [], "a4": [2, 1, 0]},
    )


def check_two_owner_order(capture: Capture) -> Expected:
    """Check that an eligible later owner advances before an earlier one.

    Returns
    -------
    Expected
        The positions of the five queued transfers.
    """
    report, notes = capture.report, capture.notes
    require(
        frame_time(report, notes["b2"][0]["frame"], capture.guest)
        < frame_time(report, notes["a2"][0]["frame"], capture.guest),
        "Eligible later owner did not advance first",
    )
    check_download(report, capture.refs, "b2")
    check_download(report, capture.refs, "a3")
    denied = reply(report, "b", NONOWNER_REQUEST)
    quiet = [
        e for e in report["events"] if e["event"] == "quiet" and e["connection"] == "a3"
    ]
    require(
        len(quiet) == QUIET_EVENTS
        and any(e["action"] > denied["action"] for e in quiet),
        "No queued-data silence after nonowner214",
    )
    for identifier in CLEANUP_REQUESTS:
        require(
            reply(report, "a", identifier)["payload_hex"] == ACK_PAYLOAD_HEX,
            "Duplicate/absent/zero/unknown cleanup ACK differs",
        )
    return Expected(
        {"a1": None, "a2": 1, "a3": 2, "b1": None, "b2": 3},
        {"a1": [], "a2": [0], "a3": [1, 0], "b1": [], "b2": [0]},
    )


def check_pending_timeout(capture: Capture) -> Expected:
    """Check that an unattached reference expires and the next one is admitted.

    Returns
    -------
    Expected
        The positions of the two transfers and the measured pending age.
    """
    report, refs = capture.report, capture.refs
    require(
        not report["streams"]["expired"]["received_hex"]
        and capture.packets["expired"]["guest_server_initiated_close"],
        "Expired reference still delivered data",
    )
    check_download(report, refs, "waiting")
    pauses = [e for e in report["events"] if e["event"] == "pause"]
    require(len(pauses) == PAUSE_COUNT, "Missing timed queue observation windows")
    for event in pauses:
        prior = [e for e in report["events"] if e["action"] < event["action"]][-1]
        require(
            event["elapsed_ns"] - prior["elapsed_ns"]
            >= PAUSE_SECONDS * NANOSECONDS_PER_SECOND,
            "Shortened timed queue window",
        )
    admission_us = frame_time(
        report, capture.notes["waiting"][0]["frame"], capture.guest
    )
    created_us = frame_time(report, refs["expired"]["frame"], capture.guest)
    age = (admission_us - created_us) / MICROSECONDS_PER_SECOND
    require(
        MIN_PENDING_AGE <= age <= MAX_PENDING_AGE,
        "Pending timeout outside bounded observation",
    )
    return Expected(
        {"expired": None, "waiting": 1},
        {"expired": [], "waiting": [0]},
        {"admission_after_initial_ack_host_seconds": age, "scope": TIMER_SCOPE},
    )


CASE_CHECKS: dict[str, cabc.Callable[[Capture], Expected]] = {
    "queue-mode-matrix": check_mode_matrix,
    "queue-cancel-position": check_cancel_position,
    "queue-two-owner-order": check_two_owner_order,
    TIMED_OUT: check_pending_timeout,
}


def check_positions(capture: Capture, expected: Expected) -> None:
    """Check each initial ACK position and each notification sequence."""
    for ref_name, position in expected.initial.items():
        values = capture.refs[ref_name]["values"]
        require(
            (FIELD_QUEUE_POSITION in values) == (position is not None),
            "Initial queue-position presence differs",
        )
        if position is not None:
            require(
                int.from_bytes(values[FIELD_QUEUE_POSITION], "big") == position,
                "Initial queue position differs",
            )
    require(
        {key: [n["position"] for n in ns] for key, ns in capture.notes.items()}
        == expected.notes,
        "Queue notification sequence differs",
    )


def check_inventory(report: Report, plan: Report) -> None:
    """Check that every request of every owner has exactly one error-free reply."""
    for frame in report["frames"]:
        if frame["is_reply"]:
            require(frame["error"] == 0, "Unexpected error reply")
    for owner in {f["connection"] for f in report["frames"]}:
        requests = [
            int.from_bytes(
                bytes.fromhex(step["hex"][:HEADER_HEX_CHARS])[ID_START:ID_END], "big"
            )
            for step in plan["steps"]
            if step["op"] == "send"
            and step["connection"] == owner
            and len(step["hex"]) >= HEADER_HEX_CHARS
        ]
        replies = [
            f["id"]
            for f in report["frames"]
            if f["connection"] == owner and f["is_reply"]
        ]
        require(
            sorted(requests) == sorted(replies), "Queue request/reply inventory differs"
        )
