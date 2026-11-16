"""Check the recorded events, actions and frames of the failed rate304 sequence.

The checks run in a fixed order, and the first one that fails names the error, so
the helpers below are called in the order they are listed in
:func:`events_and_actions`.
"""

import typing as typ

from capture_acceptance import role_in
from verify_native_rate304_sequence_constants import (
    ACTION_COUNT,
    CASES,
    DATA,
    EVENT_COUNT,
    FRAME_COUNT,
    IDLE_CONTROL_COUNT,
    PLAN,
    RUNNER,
)
from verify_native_rate304_sequence_support import need

if typ.TYPE_CHECKING:
    from types import ModuleType

    from verify_native_rate304_sequence_support import Modules, Report


def _check_status(report: Report, plan: Report) -> None:
    """Check the status, the timing, the pins and the terminals of the failed case.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    plan : dict[str, typing.Any]
        The prepared plan.
    """
    need(
        report["status"] == "failed"
        and report["error"] == "ValueError: Reply is not direct success"
        and report["timing"] == {}
        and report["phase_receipts"] == {}
        and report["phase_progress"] == {"paced": 26, "burst": 26}
        and report["native_clock_calibrated"] is False
        and report["plan_sha256"] == PLAN
        and role_in(report, "cases", {CASES})
        and role_in(report, "source", {RUNNER})
        and report["oracle_sha256"] == DATA
        and report["terminals"] == dict.fromkeys(plan["schedule"]["flows"], "eof"),
        "Failed case status/timing/source differs",
    )


def _check_schedule(report: Report, plan: Report, control: ModuleType) -> None:
    """Check the event, action and frame counts and the as-run request schedule.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    plan : dict[str, typing.Any]
        The prepared plan.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    """
    events, actions, frames = report["events"], report["actions"], report["frames"]
    need(
        len(events) == EVENT_COUNT
        and len(actions) == ACTION_COUNT
        and len(frames) == FRAME_COUNT,
        "Raw event/action/frame boundary differs",
    )
    idle_count = sum(a["label"].startswith("observer-idle500-") for a in actions)
    need(idle_count == IDLE_CONTROL_COUNT, "Observed idle control count differs")
    need(
        [(a["label"], a["connection"], a["hex"]) for a in actions]
        == control.expected_actions(plan, idle_count),
        "As-run request schedule/bytes differ",
    )


def _check_event_order(report: Report) -> None:
    """Check that the event times never regress and rebuild the recorded streams.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    """
    rebuilt: dict[str, dict[str, str]] = {}
    last = -1
    for event in report["events"]:
        need(event["elapsed_ns"] >= last, "Event time regressed")
        last = event["elapsed_ns"]
        stream = rebuilt.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        match event["event"]:
            case "send":
                stream["sent_hex"] += event["hex"]
            case "receive":
                stream["received_hex"] += event["hex"]
    need(rebuilt == report["streams"], "Recorder event/stream bytes differ")


def _check_actions(report: Report, expected: dict[str, str]) -> None:
    """Check each action against its own send events and add its bytes to ``expected``.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    expected : dict[str, str]
        The request bytes expected on each connection, updated in place.
    """
    events = report["events"]
    for action in report["actions"]:
        first, end = action["event_range"]
        need(first < end < len(events), "Action event range differs")
        own_sends = [
            e
            for e in events[first:end]
            if e["event"] == "send" and e["connection"] == action["connection"]
        ]
        need(bool(own_sends), "Action has no own send event")
        need(
            own_sends[-1]["elapsed_ns"]
            <= action["elapsed_ns"]
            <= events[end]["elapsed_ns"],
            "Action causal timestamp differs",
        )
        sent = "".join(e["hex"] for e in own_sends)
        need(sent == action["hex"], "Action/send event bytes differ")
        expected[action["connection"]] += action["hex"]


def _check_streams(report: Report, expected: dict[str, str], cases: ModuleType) -> None:
    """Check the sent bytes, the response and the frame tail of each stream.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    expected : dict[str, str]
        The request bytes expected on each connection.
    cases : types.ModuleType
        The loaded frozen rate304 cases module.
    """
    frames = report["frames"]
    for name, stream in report["streams"].items():
        need(stream["sent_hex"] == expected[name], "Injected request bytes differ")
        need(
            stream["received_hex"].startswith(cases.HELLO_REPLY),
            "TRTP response differs",
        )
        parsed = "".join(f["raw_hex"] for f in frames if f["connection"] == name)
        need(
            stream["received_hex"]
            == cases.HELLO_REPLY + parsed + report["unparsed_hex"][name]
            and report["unparsed_hex"][name] == "",  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # the value is a hex string; == also fails a non-string
            "Received frame/tail bytes differ",
        )


def _check_decoded(frames: list[Report], capture: ModuleType) -> None:
    """Check that each recorded frame decodes to the fields recorded with it.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The parsed frames of the case.
    capture : types.ModuleType
        The loaded frozen protocol capture module.
    """
    for frame in frames:
        decoded = capture.decode_frame(bytes.fromhex(frame["raw_hex"]))
        need(
            all(frame.get(k) == v for k, v in decoded.items()),
            "Raw frame decode differs",
        )


def _receive_events(events: list[Report]) -> dict[str, list[tuple[int, int]]]:
    """Map each connection to the cumulative received size at each receive event.

    Parameters
    ----------
    events : list[dict[str, typing.Any]]
        The parsed events of the case.

    Returns
    -------
    dict[str, list[tuple[int, int]]]
        For each connection, the cumulative received size and the event index.
    """
    receive_events: dict[str, list[tuple[int, int]]] = {}
    cumulative: dict[str, int] = {}
    for index, event in enumerate(events):
        if event["event"] == "receive":
            connection = event["connection"]
            cumulative[connection] = cumulative.get(connection, 0) + len(
                bytes.fromhex(event["hex"])
            )
            receive_events.setdefault(connection, []).append((
                cumulative[connection],
                index,
            ))
    return receive_events


def _check_frame_timing(
    report: Report, expected: dict[str, str], reply_size: int
) -> None:
    """Check the completing receive and the causal timestamp of each frame.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    expected : dict[str, str]
        The request bytes expected on each connection; its keys name the streams.
    reply_size : int
        The byte length of the fixed reply that precedes the frames.
    """
    events, frames = report["events"], report["frames"]
    receive_events = _receive_events(events)
    offsets = dict.fromkeys(expected, reply_size)
    for frame in frames:
        connection = frame["connection"]
        offsets[connection] += len(bytes.fromhex(frame["raw_hex"]))
        completed = next(
            (
                index
                for size, index in receive_events[connection]
                if size >= offsets[connection]
            ),
            None,
        )
        need(
            completed is not None and completed + 1 < len(events),
            "Frame has no completing receive event",
        )
        completed = typ.cast("int", completed)
        need(
            events[completed]["elapsed_ns"]
            <= frame["arrival_elapsed_ns"]
            <= events[completed + 1]["elapsed_ns"],
            "Frame causal timestamp differs",
        )
    need(
        all(
            offsets[name] == len(bytes.fromhex(stream["received_hex"]))
            for name, stream in report["streams"].items()
        ),
        "Frame receive offset differs",
    )


def _check_terminals(report: Report, plan: Report) -> None:
    """Check that each socket ends with the terminal event that the report names.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    plan : dict[str, typing.Any]
        The prepared plan.
    """
    events = report["events"]
    for name in plan["schedule"]["flows"]:
        terminal = [
            e["event"]
            for e in events
            if e["connection"] == name and e["event"] in {"eof", "rst"}
        ]
        need(terminal == [report["terminals"][name]], "Socket terminal/event differs")


def events_and_actions(report: Report, plan: Report, modules: Modules) -> None:
    """Check the recorded events, actions and frames of the failed case.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    plan : dict[str, typing.Any]
        The prepared plan.
    modules : tuple[types.ModuleType, ...]
        The frozen modules yielded by the ``frozen`` context manager.
    """
    control, cases, _, capture, _ = modules
    _check_status(report, plan)
    _check_schedule(report, plan, control)
    _check_event_order(report)
    expected = dict.fromkeys(plan["schedule"]["flows"], cases.HELLO)
    _check_actions(report, expected)
    _check_streams(report, expected, cases)
    _check_decoded(report["frames"], capture)
    _check_frame_timing(report, expected, len(bytes.fromhex(cases.HELLO_REPLY)))
    _check_terminals(report, plan)
