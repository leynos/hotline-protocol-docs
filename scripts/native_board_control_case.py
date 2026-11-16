"""Run the whole board case: logins, reads, thirteen posts, barriers and reads.

Part of the board runner (``native_board_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. Each step fails
closed with a ``ValueError`` that names what differed.
"""

import dataclasses as dc
import time

import native_board_cases as cases
from native_board_control_flows import login, post, read_board, read_denied, success
from native_board_control_report import READ_POSTS
from native_board_control_wire import Report, Wire, need, one
from native_plan import packet
from native_wire_names import TYPE_EMPTY_ACK
from verify_native_auth import ADMIN

MAX_POST_BYTES = 8192
BOARD_LIMIT = 65535
PACE_SLICE_SECONDS = 0.1
NS_PER_SECOND = 1e9
ACCESS_BY_ACTOR = (
    ("sender", ADMIN),
    ("eligible", ADMIN),
    ("denied", bytes(8)),
    ("waiting", None),
)


@dc.dataclass(slots=True)
class CaseResults:
    """What a board case collects as it runs."""

    segments: list[bytes] = dc.field(default_factory=list)
    payloads: list[bytes] = dc.field(default_factory=list)
    reads: dict[str, str] = dc.field(default_factory=dict)


def _next_data(
    index: int, source: Report, results: CaseResults, overhead: int | None
) -> bytes:
    """Work out the data of one post and require it to be the planned one.

    Returns
    -------
    bytes
        The post data; post 10 is tuned so that the board ends at 65535 bytes.

    Raises
    ------
    ValueError
        If the overhead of the rendered segments is not yet measured.
    """
    unmeasured = index == cases.UNMEASURED_POST
    if unmeasured:
        aggregate = b"".join(reversed(results.segments))
        if overhead is None:
            message = "Missing measured segment overhead"
            raise ValueError(message)
        tuned = BOARD_LIMIT - len(aggregate) - overhead
        need(0 <= tuned <= MAX_POST_BYTES, "Dynamic P10 filler outside post bounds")
        prefix = b"P10:"
        data = prefix + b"K" * (tuned - len(prefix))
        need(len(data) == tuned, "Dynamic filler too short")
    else:
        data = cases.post_data(index)
    need(
        source["data_hex"] == (None if unmeasured else data.hex())
        and source["hex"] == (None if unmeasured else cases.post_packet(index, data))
        and source["request_id"] == cases.POST_ID + index,
        "Prepared board post bytes differ",
    )
    return data


def _await_barrier(wire: Wire, name: str, ident: int, before: int) -> None:
    """Wait for the barrier ACK of one actor and check it."""
    frames = wire.recorder.frames
    wire.until(
        lambda: any(
            f["connection"] == name and f["is_reply"] == 1 and f["id"] == ident
            for f in frames[before:]
        )
    )
    success(one(frames[before:], name, 0, ident, 1), ident)


def _barriers(wire: Wire, source: Report, index: int) -> None:
    """Send the barrier of a post to both observers and wait for each ACK."""
    for barrier, (name, ident) in zip(
        source["barriers"],
        (
            ("eligible", cases.BARRIER_ID + 2 * index),
            ("denied", cases.BARRIER_ID + 1 + 2 * index),
        ),
        strict=True,
    ):
        need(
            barrier == {"connection": name, "hex": packet(TYPE_EMPTY_ACK, ident)},
            "Barrier source differs",
        )
        wire.mark(name, f"p{index:02d}-barrier-{name}")
        before = len(wire.recorder.frames)
        wire.send(name, bytes.fromhex(barrier["hex"]))
        _await_barrier(wire, name, ident, before)


def _read_after(wire: Wire, source: Report, index: int, results: CaseResults) -> None:
    """Read the board after a post and keep what it returns."""
    need(
        source["read_after_hex"] == packet(101, cases.READ_AFTER_ID + index),
        "Board read source differs",
    )
    wire.mark("sender", f"p{index:02d}-read")
    board = b"".join(reversed(results.segments))
    actual = read_board(wire, "sender", cases.READ_AFTER_ID + index, board)
    results.reads[str(index)] = actual.hex()


def _logins(wire: Wire, plan: Report, results: CaseResults) -> None:
    """Log every actor in and take the empty and the denied reads."""
    for name, access in ACCESS_BY_ACTOR:
        wire.mark(name, f"login-{name}")
        login(wire, name, bytes.fromhex(plan["login_hex"][name]), access)
    wire.mark("sender", "initial101")
    read_board(wire, "sender", cases.INITIAL_READ_ID, b"")
    results.reads["initial"] = ""
    wire.mark("denied", "denied101")
    read_denied(wire, "denied", cases.DENIED_READ_ID)


def _pace(last_post: float, pace_seconds: float) -> None:
    """Wait until ``pace_seconds`` have passed since the last post."""
    while time.monotonic() - last_post < pace_seconds:
        time.sleep(
            min(PACE_SLICE_SECONDS, pace_seconds - (time.monotonic() - last_post))
        )


@dc.dataclass(slots=True)
class Pacing:
    """The state that one post hands to the next."""

    operations: dict[str, Report]
    pace_seconds: float
    last_post: float
    overhead: int | None = None


def _round(wire: Wire, index: int, results: CaseResults, pacing: Pacing) -> None:
    """Run one post, then its barriers, the waiting close and its read."""
    source = pacing.operations[f"p{index:02d}"]
    need(
        time.monotonic() - wire.recorder.started / NS_PER_SECOND < cases.WINDOW_SECONDS,
        "Board case window expired",
    )
    _pace(pacing.last_post, pacing.pace_seconds)
    data = _next_data(index, source, results, pacing.overhead)
    results.payloads.append(data)
    wire.mark("sender", f"p{index:02d}")
    segment, pacing.overhead = post(wire, index, data, pacing.overhead)
    pacing.last_post = time.monotonic()
    if index != cases.REJECTED_POST:
        results.segments.append(segment)
    if index < cases.BARRIER_POSTS:
        _barriers(wire, source, index)
    if index == cases.WAITING_CLOSE_POST:
        wire.mark("waiting", "waiting-close")
        need(
            pacing.operations["waiting-close"]["op"] == "close_waiting",
            "Waiting close source differs",
        )
        wire.close("waiting")
    if index in READ_POSTS:
        _read_after(wire, source, index, results)


def execute_case(
    wire: Wire,
    plan: Report,
    results: CaseResults,
    pace_seconds: float = 1.0,
) -> None:
    """Run the whole case: logins, reads, thirteen posts, barriers and reads.

    Parameters
    ----------
    wire : Wire
        The sockets of the case.
    plan : dict[str, typing.Any]
        The prepared plan.
    results : CaseResults
        Receives the segments, the post data and the reads as they are made.
    pace_seconds : float
        The least time between two posts.
    """
    operations = {item["label"]: item for item in plan["operations"]}
    need(
        operations["initial101"]["hex"] == packet(101, cases.INITIAL_READ_ID)
        and operations["denied101"]["hex"] == packet(101, cases.DENIED_READ_ID),
        "Initial board request source differs",
    )
    _logins(wire, plan, results)
    pacing = Pacing(operations, pace_seconds, time.monotonic() - 1)
    for index in range(cases.POST_COUNT):
        _round(wire, index, results, pacing)
    need(
        len(results.segments) == cases.POST_COUNT - 1,
        "Board successful-post count differs",
    )
