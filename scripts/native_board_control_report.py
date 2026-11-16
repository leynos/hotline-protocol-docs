"""Check a finished board report offline, against its plan and its own events.

Part of the board runner (``native_board_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. The checks run
in a fixed order, so a fault is reported by the first check that finds it.
"""

import json

import native_board_cases as cases
from native_board_control_flows import (
    AGREEMENT_SHA,
    TYPE_BOARD_UPDATE,
    TYPE_READ_BOARD,
    success,
)
from native_board_control_wire import Report, frame_fields, need, one, sha, strict
from native_plan import packet
from native_wire_names import (
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    TYPE_EMPTY_ACK,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import ADMIN

SEGMENTS = cases.POST_COUNT - 1
READ_POSTS = (0, 1, 2, 9, 10, 11, 12)
MAX_POST_BYTES = 8192
WHOLE_BOARD_MIN = 65535
NS_PER_SECOND = 1e9
TIMING_SLACK_NS = 1_000_000
ACTORS = ("sender", "eligible", "denied", "waiting")
LOGIN_ACK = {160: b"\0\xbe", 161: b"\0\0"}
BARRIER_NAMES = ("eligible", "denied")
OVERSIZE_ID = cases.POST_ID + cases.REJECTED_POST


def _frames(report: Report, name: str, kind: int) -> list[Report]:
    """List the frames of one flow with one type.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching frames, in order.
    """
    return [
        f for f in report["frames"] if f["connection"] == name and f["type"] == kind
    ]


def _bounds(plan: Report, report: Report) -> None:
    """Require the plan hash, the status, the bounds and the baseline claims."""
    need(
        report["plan_sha256"] == sha((json.dumps(plan, indent=2) + "\n").encode()),
        "Plan hash changed",
    )
    need(report["status"] == "completed", "Board case incomplete")
    need(
        report["elapsed_seconds"] <= cases.WINDOW_SECONDS
        and report["byte_count"] <= cases.MAX_CAPTURE_BYTES
        and len(report["frames"]) <= cases.MAX_FRAMES,
        "Board case bound exceeded",
    )
    need(
        report["full_a7"] == "not_exercised"
        and report["storage"] == "requires_stopped_guest_fork",
        "Storage/full baseline claim differs",
    )


def _board(report: Report) -> tuple[list[bytes], list[bytes]]:
    """Require the posts, the segments, the whole board and the reads to agree.

    Returns
    -------
    tuple[list[bytes], list[bytes]]
        The post data and the segments.
    """
    need(len(report["segments_hex"]) == SEGMENTS, "Board segment count differs")
    data = [bytes.fromhex(x) for x in report["post_data_hex"]]
    need(
        len(data) == cases.POST_COUNT
        and all(len(x) <= MAX_POST_BYTES for x in data[:SEGMENTS])
        and len(data[SEGMENTS]) == cases.REJECTED_BYTES,
        "Post boundary differs",
    )
    segments = [bytes.fromhex(x) for x in report["segments_hex"]]
    for index, segment in enumerate(segments):
        need(
            segment.startswith(b"From ")
            and segment.endswith(data[index] + cases.SEPARATOR),
            "Board segment corrupt",
        )
    whole = b"".join(reversed(segments))
    need(
        report["whole_board_sha256"] == sha(whole) and len(whole) > WHOLE_BOARD_MIN,
        "Whole board reconstruction differs",
    )
    need(
        report["reads"]
        == {
            str(k): (b"".join(reversed(segments[: k + 1]))[:WHOLE_BOARD_MIN]).hex()
            for k in READ_POSTS
        }
        | {"initial": ""},
        "Board read/prefix mismatch",
    )
    need(
        len(whole) - len(segments[SEGMENTS - 1]) == WHOLE_BOARD_MIN,
        "Inclusive board boundary differs",
    )
    return data, segments


def _expected_sends(plan: Report, data: list[bytes]) -> dict[str, str]:
    """Work out the bytes that the plan makes each actor send.

    Returns
    -------
    dict[str, str]
        The expected sent hex by actor.
    """
    expected = {name: cases.HELLO + plan["login_hex"][name] for name in ACTORS}
    expected["sender"] += packet(TYPE_READ_BOARD, cases.INITIAL_READ_ID)
    expected["denied"] += packet(TYPE_READ_BOARD, cases.DENIED_READ_ID)
    for index, value in enumerate(data):
        expected["sender"] += cases.post_packet(index, value)
        if index < cases.BARRIER_POSTS:
            expected["eligible"] += packet(TYPE_EMPTY_ACK, cases.BARRIER_ID + 2 * index)
            expected["denied"] += packet(
                TYPE_EMPTY_ACK, cases.BARRIER_ID + 1 + 2 * index
            )
        if index in READ_POSTS:
            expected["sender"] += packet(TYPE_READ_BOARD, cases.READ_AFTER_ID + index)
    return expected


def _requests(report: Report, expected: dict[str, str]) -> None:
    """Require the sent bytes and the event times to match the plan."""
    actual_sends = dict.fromkeys(expected, "")
    for event in report["events"]:
        if event["event"] == "send":
            need(event["connection"] in expected, "Unexpected board socket")
            actual_sends[event["connection"]] += event["hex"]
        need(
            0
            <= event["elapsed_ns"]
            <= int(report["elapsed_seconds"] * NS_PER_SECOND) + TIMING_SLACK_NS,
            "Event timing outside window",
        )
    need(actual_sends == expected, "Board request bytes/order differ")


def _labels(report: Report, expected: dict[str, str]) -> None:
    """Require the operation labels to be those of the plan, in its order."""
    labels = [f"login-{name}" for name in expected]
    labels += ["initial101", "denied101"]
    for index in range(cases.POST_COUNT):
        labels.append(f"p{index:02d}")
        if index < cases.BARRIER_POSTS:
            labels += [f"p{index:02d}-barrier-{name}" for name in BARRIER_NAMES]
        if index == cases.WAITING_CLOSE_POST:
            labels.append("waiting-close")
        if index in READ_POSTS:
            labels.append(f"p{index:02d}-read")
    need(
        [e["label"] for e in report["events"] if e["event"] == "operation"] == labels,
        "Board operation labels/order differ",
    )


def streams_of(events: list[Report]) -> dict[str, dict[str, str]]:
    """Rebuild each flow's sent and received hex from the raw events.

    Returns
    -------
    dict[str, dict[str, str]]
        ``sent_hex`` and ``received_hex`` by flow name.
    """
    result: dict[str, dict[str, str]] = {}
    for event in events:
        name = event["connection"]
        if name:
            entry = result.setdefault(name, {"sent_hex": "", "received_hex": ""})
            match event["event"]:
                case "send":
                    entry["sent_hex"] += event["hex"]
                case "receive":
                    entry["received_hex"] += event["hex"]
    return result


def _raw_frames(report: Report) -> None:
    """Require each frame to match its raw bytes, and each stream its frames."""
    for frame in report["frames"]:
        need(
            all(
                frame[key] == value
                for key, value in strict(bytes.fromhex(frame["raw_hex"])).items()
            ),
            "Captured frame raw mismatch",
        )
    need(report["streams"] == streams_of(report["events"]), "Raw stream/event mismatch")
    for name, stream in report["streams"].items():
        raw = stream["received_hex"]
        need(raw.startswith(cases.HELLO_REPLY), "Missing TRTP reply bytes")
        frames_raw = "".join(
            frame["raw_hex"]
            for frame in report["frames"]
            if frame["connection"] == name
        )
        need(
            raw[len(cases.HELLO_REPLY) :] == frames_raw,
            "Received bytes/frame inventory differs",
        )


def _actors(report: Report, expected: dict[str, str]) -> None:
    """Require each actor's login, privileges and agreement."""
    frames = report["frames"]
    for name, acl in (("sender", ADMIN), ("eligible", ADMIN), ("denied", bytes(8))):
        need(
            success(one(frames, name, 0, 1, 1), 1) == LOGIN_ACK,
            "Login ACK fields differ",
        )
        access_frames = _frames(report, name, TYPE_PRIVILEGES_NOTIFICATION)
        need(
            len(access_frames) == 1 and frame_fields(access_frames[0]) == {110: acl},
            "Actor access proof differs",
        )
    for name in expected:
        notices = _frames(report, name, TYPE_LOGIN_AGREEMENT)
        need(
            len(notices) == 1
            and sha(frame_fields(notices[0]).get(FIELD_DATA, b"")) == AGREEMENT_SHA,
            "Actor agreement proof differs",
        )
    need(
        success(one(frames, "waiting", 0, 1, 1), 1) == LOGIN_ACK,
        "Waiting login differs",
    )
    need(
        not _frames(report, "waiting", TYPE_PRIVILEGES_NOTIFICATION),
        "Waiting actor online",
    )


def _reads_and_barriers(report: Report) -> None:
    """Require the denied read, the empty initial board and the barrier ACKs."""
    frames = report["frames"]
    denied = one(frames, "denied", 0, cases.DENIED_READ_ID, 1)
    need(frame_fields(denied).keys() == {FIELD_ERROR_TEXT}, "Denied read error absent")
    need(
        one(frames, "denied", 0, cases.DENIED_READ_ID, 1)["error"] == 1,
        "Denied read status differs",
    )
    need(
        success(
            one(frames, "sender", 0, cases.INITIAL_READ_ID, 1), cases.INITIAL_READ_ID
        )
        == {},
        "Initial board was not empty",
    )
    for index in range(cases.BARRIER_POSTS):
        for name, ident in (
            ("eligible", cases.BARRIER_ID + 2 * index),
            ("denied", cases.BARRIER_ID + 1 + 2 * index),
        ):
            need(
                success(one(frames, name, 0, ident, 1), ident) == {},
                "Board barrier ACK differs",
            )


def _waiting_updates(report: Report, segments: list[bytes]) -> None:
    """Require the waiting actor to see only updates of the first three posts."""
    waiting = _frames(report, "waiting", TYPE_BOARD_UPDATE)
    indexes = [
        next(
            (
                i
                for i, segment in enumerate(segments[: cases.BARRIER_POSTS])
                if frame_fields(f) == {FIELD_DATA: segment}
            ),
            -1,
        )
        for f in waiting
    ]
    need(
        indexes == sorted(set(indexes)) and all(i >= 0 for i in indexes),
        "Waiting update outside first three posts",
    )


def _updates(report: Report, segments: list[bytes]) -> None:
    """Require each post's ACK and the updates its recipients received."""
    frames = report["frames"]
    sender_updates = _frames(report, "sender", TYPE_BOARD_UPDATE)
    eligible_updates = _frames(report, "eligible", TYPE_BOARD_UPDATE)
    need(
        len(sender_updates) == len(eligible_updates) == SEGMENTS,
        "Board update cardinality differs",
    )
    _waiting_updates(report, segments)
    for index, segment in enumerate(segments):
        ident = cases.POST_ID + index
        need(
            success(one(frames, "sender", 0, ident, 1), ident) == {},
            "Post ACK differs",
        )
        sender, eligible = sender_updates[index], eligible_updates[index]
        need(
            sender["is_reply"] == eligible["is_reply"] == 0
            and sender["error"] == eligible["error"] == 0,
            "Update header differs",
        )
        need(
            frame_fields(sender) == frame_fields(eligible) == {FIELD_DATA: segment},
            "Update recipient segment differs",
        )
        need(
            not _frames(report, "denied", TYPE_BOARD_UPDATE),
            "Denied update present",
        )
    rejected = one(frames, "sender", 0, OVERSIZE_ID, 1)
    need(
        rejected["error"] == 1 and set(frame_fields(rejected)) == {FIELD_ERROR_TEXT},
        "Oversize post rejection differs",
    )
    for index in READ_POSTS:
        reply = one(frames, "sender", 0, cases.READ_AFTER_ID + index, 1)
        need(
            success(reply, cases.READ_AFTER_ID + index).get(FIELD_DATA, b"").hex()
            == report["reads"][str(index)],
            "Read reply bytes differ",
        )


def verify_report(plan: Report, report: Report) -> None:
    """Check a finished board report against its plan and its own events.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The report that the run built.
    """
    _bounds(plan, report)
    data, segments = _board(report)
    expected = _expected_sends(plan, data)
    _requests(report, expected)
    _labels(report, expected)
    _raw_frames(report)
    _actors(report, expected)
    _reads_and_barriers(report)
    _updates(report, segments)
