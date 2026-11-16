"""Check a finished liveness report offline, against its plan and its own events.

Part of the liveness runner (``native_liveness_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. The check is not the generic ``verify_capture``: it knows the schedule.
It runs the checks in a fixed order, so a fault is reported by the first check
that finds it.
"""

import json
import time
import typing as typ

import native_liveness_cases as cases
from native_liveness_control_checks import check_complete
from native_liveness_control_timeline import Report, Timeline, digest, need
from protocol_capture import ORACLE_SHA256, decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc

NS_PER_SECOND = 1_000_000_000
SCHEDULE_LATE_NS = 5 * NS_PER_SECOND
SCHEDULE_EARLY_NS = 5_000_000  # Float seconds to monotonic-ns conversion allowance.
WINDOW_NS = cases.MAX_SECONDS * NS_PER_SECOND
FLOW_NAMES = ("o", "a", "b", "f", "s35", "s75", "s120")
SELF_CHECK_SECONDS = 1
STIMULI = frozenset({"admit", "stimulus"})
TERMINAL_EVENTS = frozenset({"eof", "rst"})
CLIENT_CLOSED = "client_closed_after_bounded_observation"


def _rebuilt_streams(events: list[Report]) -> dict[str, dict[str, str]]:
    """Rebuild each flow's sent and received hex from the raw events.

    Returns
    -------
    dict[str, dict[str, str]]
        ``sent_hex`` and ``received_hex`` by flow name.
    """
    rebuilt: dict[str, dict[str, str]] = {}
    for event in events:
        stream = rebuilt.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        match event["event"]:
            case "send":
                stream["sent_hex"] += event["hex"]
            case "receive":
                stream["received_hex"] += event["hex"]
    return rebuilt


def _expected_sends(plan: Report) -> dict[str, str]:
    """Work out the bytes that the schedule injects on each flow.

    Returns
    -------
    dict[str, str]
        The expected sent hex by flow name.
    """
    expected = dict.fromkeys(FLOW_NAMES, cases.HELLO)
    expected["o"] += plan["observer_login_hex"]
    for op in plan["schedule"]["operations"]:
        if op["connection"]:
            expected[op["connection"]] += op["hex"]
    return expected


def _operation_labels(report: Report, plan: Report) -> list[Report]:
    """Require the as-run operation log to follow the schedule.

    Returns
    -------
    list[dict[str, typing.Any]]
        The as-run operation log.
    """
    operation_log = report["operations"]
    schedule = plan["schedule"]["operations"]
    need(
        len(operation_log) == len(schedule) + 1
        and operation_log[0]["label"] == "t0"
        and [item["label"] for item in operation_log[1:]]
        == [op["label"] for op in schedule],
        "As-run schedule labels differ",
    )
    return operation_log


def _window_timing(report: Report, operation_log: list[Report]) -> tuple[int, int]:
    """Require the window to last its 135 seconds, within the allowances.

    Returns
    -------
    tuple[int, int]
        The start of the schedule and the end of the window, in nanoseconds.
    """
    t0 = operation_log[0]["elapsed_ns"]
    window = report["window_elapsed_ns"]
    need(
        isinstance(t0, int)
        and isinstance(window, int)
        and 0 <= t0 < window
        and t0 + WINDOW_NS - SCHEDULE_EARLY_NS
        <= window
        <= t0 + WINDOW_NS + SCHEDULE_LATE_NS,
        "135-second window timing differs",
    )
    return t0, window


def _monotonic_events(events: list[Report]) -> None:
    """Require the raw event times never to run backwards."""
    prior_event_ns = -1
    for event in events:
        elapsed = event["elapsed_ns"]
        need(
            isinstance(elapsed, int) and prior_event_ns <= elapsed,
            "Raw event times are not monotonic",
        )
        prior_event_ns = elapsed


def _check_operation(
    report: Report, item: Report, op: Report, bounds: tuple[int, int, int]
) -> int:
    """Check one as-run operation against its scheduled one.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report.
    item : dict[str, typing.Any]
        The as-run record of the operation.
    op : dict[str, typing.Any]
        The scheduled operation.
    bounds : tuple[int, int, int]
        The start of the schedule, the end of the window and the time of the
        previous operation, in nanoseconds.

    Returns
    -------
    int
        The as-run time of the operation.
    """
    t0, window, previous = bounds
    events = report["events"]
    first, last = item["event_range"]
    actual = item["actual_elapsed_ns"]
    target = t0 + op["at_seconds"] * NS_PER_SECOND
    need(
        isinstance(actual, int)
        and previous <= actual <= window
        and target - SCHEDULE_EARLY_NS <= actual <= target + SCHEDULE_LATE_NS
        and all(
            previous <= event["elapsed_ns"] <= actual for event in events[first:last]
        ),
        f"Scheduled time differs at {op['label']}",
    )
    injected = "".join(
        event["hex"] for event in events[first:last] if event["event"] == "send"
    )
    planned = (cases.HELLO if op["op"] in STIMULI else "") + op["hex"]
    need(injected == planned, f"Injected bytes differ at {op['label']}")
    return actual


def _operations(
    report: Report, plan: Report, operation_log: list[Report], bounds: tuple[int, int]
) -> int:
    """Check every as-run operation: ranges, times and injected bytes.

    Returns
    -------
    int
        The event index at which the last operation ended.
    """
    t0, window = bounds
    event_cursor = operation_log[1]["event_range"][0]
    frame_cursor = operation_log[1]["frame_range"][0]
    previous = t0
    scheduled = plan["schedule"]["operations"]
    for item, op in zip(operation_log[1:], scheduled, strict=True):
        first, last = item["event_range"]
        front, back = item["frame_range"]
        need(
            first == event_cursor <= last <= len(report["events"])
            and front == frame_cursor <= back <= len(report["frames"]),
            "As-run ranges are gapped or overlapping",
        )
        previous = _check_operation(report, item, op, (t0, window, previous))
        event_cursor, frame_cursor = last, back
    return event_cursor


def _no_frames() -> list[Report]:
    """Start an empty list of frames.

    Returns
    -------
    list[dict[str, typing.Any]]
        A new empty list.
    """
    return []


def _frames_by_flow(report: Report) -> dict[str, list[Report]]:
    """Require each frame to match its raw bytes and group the frames by flow.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The frames of each flow, in order.
    """
    by_name = {name: _no_frames() for name in FLOW_NAMES}
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(key) == value for key, value in decode_frame(raw).items()),
            "Decoded frame differs from raw",
        )
        by_name[frame["connection"]].append(frame)
    return by_name


def _received_streams(report: Report, by_name: dict[str, list[Report]]) -> None:
    """Require each received stream to be the hello reply, the frames, the tail."""
    for name, stream in report["streams"].items():
        raw = stream["received_hex"]
        need(raw.startswith(cases.HELLO_REPLY), "TRTP reply missing")
        parsed = "".join(frame["raw_hex"] for frame in by_name[name])
        need(
            raw[len(cases.HELLO_REPLY) :] == parsed + report["unparsed_hex"][name],
            "Received bytes omitted or reordered",
        )


def _terminal_events(
    events: list[Report], name: str, *, until: int | None = None
) -> list[str]:
    """List the EOF and reset events of a flow, up to an optional time.

    Returns
    -------
    list[str]
        The names of the events, in order.
    """
    return [
        event["event"]
        for event in events
        if event["connection"] == name
        and (until is None or event["elapsed_ns"] <= until)
        and event["event"] in TERMINAL_EVENTS
    ]


def _flow_outcomes(report: Report, name: str, window: int) -> None:
    """Require a flow's recorded outcomes to follow from its events."""
    events = report["events"]
    terminal = _terminal_events(events, name, until=window)
    need(len(terminal) <= 1, f"Conflicting terminal events: {name}")
    closed = any(
        event["connection"] == name
        and event["elapsed_ns"] <= window
        and event["event"] == "close"
        for event in events
    )
    _window_outcome(report, name, terminal, closed=closed)
    _final_outcome(report, name, closed=closed)


def _window_outcome(
    report: Report, name: str, terminal: list[str], *, closed: bool
) -> None:
    """Require a flow's window status to follow from its events."""
    if terminal:
        observed = terminal[0]
    elif closed:
        observed = CLIENT_CLOSED
    else:
        observed = "bounded_no_eof_through_window"
    need(
        report["window_status"][name] == observed,
        f"Window socket outcome differs from events: {name}",
    )


def _final_outcome(report: Report, name: str, *, closed: bool) -> None:
    """Require a flow's final terminal to follow from its events."""
    full_terminal = _terminal_events(report["events"], name)
    need(len(full_terminal) <= 1, f"Conflicting full terminal events: {name}")
    if full_terminal:
        final_observed = full_terminal[0]
    elif closed:
        final_observed = CLIENT_CLOSED
    else:
        final_observed = "bounded_no_eof"
    need(
        report["terminals"].get(name) == final_observed,
        f"Final socket outcome differs from events: {name}",
    )


def _identified(
    report: Report, identified: cabc.Callable[[Report], bool], plan: Report
) -> None:
    """Require the report to name this plan, these scripts and this oracle."""
    source = (json.dumps(plan, indent=2) + "\n").encode()
    need(
        report["plan_sha256"] == digest(source)
        and identified(report)
        and report["oracle_sha256"] == ORACLE_SHA256,
        "As-run source identity changed",
    )


def verify_report(
    plan: Report, report: Report, identified: cabc.Callable[[Report], bool]
) -> None:
    """Check a complete custom report; this is not generic verify_capture.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The report that the run built.
    identified : collections.abc.Callable[[dict[str, typing.Any]], bool]
        Says whether the report names the live scripts that are checking it.
    """
    need(
        report["status"] == "completed" and report["window_completed"],
        "Case incomplete",
    )
    need(report["native_conformance"] is False, "Unexpected conformance claim")
    _identified(report, identified, plan)
    events = report["events"]
    need(
        _rebuilt_streams(events) == report["streams"], "Raw streams differ from events"
    )
    expected = _expected_sends(plan)
    need(
        set(report["streams"]) == set(expected)
        and all(
            report["streams"][name]["sent_hex"] == raw for name, raw in expected.items()
        ),
        "Injected TCP bytes differ from generated schedule",
    )
    operation_log = _operation_labels(report, plan)
    t0, window = _window_timing(report, operation_log)
    _monotonic_events(events)
    event_cursor = _operations(report, plan, operation_log, (t0, window))
    need(
        all(event["elapsed_ns"] >= window for event in events[event_cursor:]),
        "Teardown event predates window boundary",
    )
    need(
        all(item["arrival_elapsed_ns"] >= 0 for item in report["frames"]),
        "Missing frame arrival timing",
    )
    _received_streams(report, _frames_by_flow(report))
    need(
        all(name in report["window_status"] for name in expected),
        "Missing finite socket status",
    )
    need(set(report["window_status"]) == set(expected), "Extra window socket status")
    for name in expected:
        _flow_outcomes(report, name, window)
    need(
        isinstance(report["window_frame_count"], int)
        and 0 <= report["window_frame_count"] <= len(report["frames"]),
        "Window frame boundary missing",
    )
    view = Timeline(plan, time.monotonic() + SELF_CHECK_SECONDS)
    view.frames = report["frames"]
    view.window_status = report["window_status"]
    view.window_frame_count = report["window_frame_count"]
    check_complete(view)
