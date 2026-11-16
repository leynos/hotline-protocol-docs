"""Check the numbered coordinator report of the failed first pair."""

from native_wire_names import (
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_PRESENCE_UPDATE,
    TYPE_SET_CLIENT_INFO,
    TYPE_USER_LEFT,
)
from verify_native_rate304_partial_core import (
    CASES,
    DATA,
    PLAN,
    RUNNER,
    fields,
    need,
)

LOGIN_ID = 1  # the request identifier of each login
ROSTER_ID = 10  # the request identifier of each roster request
PACED_304_ID = 1000  # the first numbered 304 request of the paced subject
PACED_500_ID = 2000  # the first numbered 500 barrier of the paced subject
SENT_KINDS = [
    TYPE_LOGIN,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_GET_USER_ROSTER,
    TYPE_SET_CLIENT_INFO,
    TYPE_EMPTY_ACK,
]
SENT_IDS = [LOGIN_ID, ROSTER_ID, LOGIN_ID, ROSTER_ID, PACED_304_ID, PACED_500_ID]
FRAME_COUNT = 12  # the frames that the failed case reports
SHUTDOWN_MIN_NS = 1_300_000_000  # the earliest observer shutdown write
SHUTDOWN_MAX_NS = 1_500_000_000  # the latest observer shutdown write
UPDATE_MIN_NS = 1_500_000_000  # the earliest late paced update
UPDATE_MAX_NS = 1_700_000_000  # the latest late paced update


def action_boundary(actions: list[dict]) -> None:
    """Check the action labels, then the kind and identifier of each request."""
    need(
        [action["label"] for action in actions]
        == [
            "observer-login",
            "observer-roster-initial",
            "paced-login",
            "paced-roster",
            "paced-304-00",
            "paced-500-00",
        ],
        "Case action boundary differs",
    )
    for action, kind, identifier in zip(actions, SENT_KINDS, SENT_IDS, strict=True):
        raw = bytes.fromhex(action["hex"])
        need(
            int.from_bytes(raw[:4], "big") == kind
            and int.from_bytes(raw[4:8], "big") == identifier,
            "Sent request kind or ID differs",
        )


def failed_status(report: dict) -> None:
    """Check the failed status, the error text and the source identities."""
    need(
        report["status"] == "failed"
        and report["error"]
        == "ValueError: Missing paced subject/observer301 and500 ACK icon2"
        and report["plan_sha256"] == PLAN
        and report["source_sha256"] == RUNNER
        and report["cases_sha256"] == CASES
        and report["oracle_sha256"] == DATA
        and report["native_clock_calibrated"] is False,
        "Failed-case status or source differs",
    )


def frame_check(report: dict) -> tuple[dict, dict, dict]:
    """Check the frame count and the single join, update, ACK and departure.

    Returns
    -------
    tuple[dict, dict, dict]
        The paced update, the paced ACK and the paced departure frames.
    """
    frames = report["frames"]
    need(len(frames) == FRAME_COUNT, "Case frame count differs")
    join = [
        f
        for f in frames
        if f["connection"] == "observer" and f["type"] == TYPE_PRESENCE_UPDATE
    ]
    update = [
        f
        for f in frames
        if f["connection"] == "paced" and f["type"] == TYPE_PRESENCE_UPDATE
    ]
    ack = [
        f
        for f in frames
        if f["connection"] == "paced" and f["type"] == 0 and f["id"] == PACED_500_ID
    ]
    departure = [
        f for f in frames if f["connection"] == "paced" and f["type"] == TYPE_USER_LEFT
    ]
    need(
        len(join) == len(update) == len(ack) == len(departure) == 1
        and fields(join[0])[FIELD_USER_ID] == b"\x00\x03"
        and fields(join[0])[FIELD_ICON] == b"\x00\x01"
        and fields(update[0])[FIELD_USER_ID] == b"\x00\x03"
        and fields(update[0])[FIELD_ICON] == b"\x00\x02"
        and fields(departure[0])[FIELD_USER_ID] == b"\x00\x02"
        and (ack[0]["flags"], ack[0]["is_reply"], ack[0]["error"]) == (0, 1, 0)
        and ack[0]["fields"] == [],
        "Initial join, late update, ACK or cleanup departure differs",
    )
    return update[0], ack[0], departure[0]


def timing_check(
    report: dict, actions: list[dict], roles: tuple[dict, dict, dict]
) -> None:
    """Check the order of the observer shutdown, the departure and the late update."""
    update, ack, departure = roles
    frames = report["frames"]
    events = report["events"]
    shutdown = next(
        e["elapsed_ns"]
        for e in events
        if e["connection"] == "observer" and e["event"] == "shutdown_write"
    )
    need(
        actions[4]["elapsed_ns"]
        < actions[5]["elapsed_ns"]
        < shutdown
        < departure["arrival_elapsed_ns"]
        < update["arrival_elapsed_ns"]
        < ack["arrival_elapsed_ns"]
        and not any(
            f["connection"] == "observer"
            and f["type"] == TYPE_PRESENCE_UPDATE
            and fields(f).get(FIELD_ICON) == b"\x00\x02"
            for f in frames
        )
        and SHUTDOWN_MIN_NS < shutdown < SHUTDOWN_MAX_NS
        and UPDATE_MIN_NS < update["arrival_elapsed_ns"] < UPDATE_MAX_NS,
        "First-pair timing or client cleanup differs",
    )


def terminal_check(report: dict, actions: list[dict]) -> None:
    """Check the terminal status, the 304 value and the barrier identifier."""
    need(
        report["terminals"] == {"observer": "eof", "paced": "eof"}
        and bytes.fromhex(actions[4]["hex"])[-2:] == b"\x00\x02"
        and bytes.fromhex(actions[5]["hex"])[4:8] == PACED_500_ID.to_bytes(4, "big"),
        "304 value, barrier or terminal status differs",
    )


def numbered(report: dict) -> None:
    """Check the numbered coordinator report in the order of the case."""
    actions = report["actions"]
    action_boundary(actions)
    failed_status(report)
    roles = frame_check(report)
    timing_check(report, actions, roles)
    terminal_check(report, actions)
