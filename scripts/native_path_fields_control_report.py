"""Check a finished path-fields report offline, against its plan and its events.

Part of the path-fields runner (``native_path_fields_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. The checks run in a fixed order, so a fault is reported by the first
check that finds it.
"""

import json
import typing as typ

import native_path_fields_cases as cases
from native_path_fields_control_classify import REQUESTS, classify_views
from native_path_fields_control_frames import (
    Report,
    file_info,
    login_gate,
    need,
    one,
    record_view,
    sha,
)
from protocol_capture import ORACLE_SHA256, decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc

TERMINAL_EVENTS = frozenset({"eof", "rst"})
SETTLED_PHASES = frozenset({"initial", "setup-view", "final"})
FINITE_TERMINALS = frozenset({"eof", "rst", "bounded_no_eof"})


def _streams_of(events: list[Report]) -> dict[str, dict[str, str]]:
    """Require monotonic event times and rebuild each flow's streams.

    Returns
    -------
    dict[str, dict[str, str]]
        ``sent_hex`` and ``received_hex`` by flow name.
    """
    streams: dict[str, dict[str, str]] = {}
    prior_ns = -1
    for event in events:
        need(event["elapsed_ns"] >= prior_ns, "Nonmonotonic event")
        prior_ns = event["elapsed_ns"]
        s = streams.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        match event["event"]:
            case "send":
                s["sent_hex"] += event["hex"]
            case "receive":
                s["received_hex"] += event["hex"]
    return streams


def _arrivals(report: Report) -> None:
    """Require each frame to arrive within the receive event that completes it."""
    events = report["events"]
    received_end = 0
    event_boundaries: list[tuple[int, int]] = []
    for event_index, event in enumerate(events):
        if event["event"] != "receive":
            continue
        received_end += len(bytes.fromhex(event["hex"]))
        event_boundaries.append((received_end, event_index))
    frame_end = len(bytes.fromhex(cases.HELLO_REPLY))
    for frame in report["frames"]:
        frame_end += len(bytes.fromhex(frame["raw_hex"]))
        containing = next(
            (index for end, index in event_boundaries if end >= frame_end), None
        )
        need(
            containing is not None
            and events[containing]["elapsed_ns"] <= frame["arrival_elapsed_ns"]
            and (
                containing + 1 == len(events)
                or frame["arrival_elapsed_ns"] <= events[containing + 1]["elapsed_ns"]
            ),
            "Frame arrival outside captured receive bracket",
        )


def _action_bracket(report: Report, action: Report, prior_end: int) -> None:
    """Require one action to own a range of send events inside its time bracket."""
    events = report["events"]
    first, last = action["event_range"]
    need(
        prior_end <= first < last <= len(events)
        and action["connection"] == "main"
        and events[last - 1]["elapsed_ns"] <= action["elapsed_ns"]
        and (last == len(events) or action["elapsed_ns"] <= events[last]["elapsed_ns"])
        and "".join(e["hex"] for e in events[first:last] if e["event"] == "send")
        == action["hex"],
        "Action/send event or time bracket differs",
    )


def _main_stream(report: Report, streams: dict[str, dict[str, str]]) -> None:
    """Require the main flow's bytes, tail and terminal to follow from its events."""
    events = report["events"]
    connection = "main"
    sent = cases.HELLO
    prior_end = 0
    for action in report["actions"]:
        _action_bracket(report, action, prior_end)
        sent += action["hex"]
        prior_end = action["event_range"][1]
    need(streams[connection]["sent_hex"] == sent, "Sent request stream differs")
    received = streams[connection]["received_hex"]
    parsed = "".join(
        f["raw_hex"] for f in report["frames"] if f["connection"] == connection
    )
    need(
        received
        == cases.HELLO_REPLY + parsed + report["unparsed_hex"].get(connection, ""),
        "Received bytes omitted",
    )
    terminals = [
        e["event"]
        for e in events
        if e["connection"] == connection and e["event"] in TERMINAL_EVENTS
    ]
    need(len(terminals) <= 1, "Contradictory socket terminals")
    need(
        report["terminals"].get(connection)
        == (terminals[0] if terminals else "bounded_no_eof"),
        "Terminal label differs from events",
    )


def _requests(plan: Report, report: Report) -> None:
    """Require each request's bytes, reply and recorded view to be the planned ones."""
    need(
        len(report["actions"]) == REQUESTS
        and report["actions"][0]["label"] == "main-login",
        "Action ledger differs",
    )
    views = {v["label"]: v for v in report["views"]}
    need(len(views) == len(report["views"]), "Duplicate retained view")
    for action, spec in zip(report["actions"][1:], plan["requests"], strict=True):
        need(
            action["label"] == spec["label"] and action["connection"] == "main",
            "Request label/phase differs",
        )
        parent = (
            bytes.fromhex(action["dynamic_parent_hex"])
            if spec["fields"] is None
            else None
        )
        need(
            action["hex"] == cases.raw_request(spec, parent), "Request fields/ID differ"
        )
        reply = one(report["frames"], action["connection"], spec["id"])
        need(
            reply["flags"] == 0 and reply["type"] == 0 and reply["is_reply"] == 1,
            "Non-direct reply",
        )
        label = spec["label"]
        if spec["phase"] in SETTLED_PHASES or label.startswith("after-view-"):
            need(
                views.get(label) == record_view([], label, reply),
                "View/raw reply differs",
            )
        if label.startswith(("before-info-", "after-info-")):
            file_info(
                reply,
                bytes.fromhex(spec["marker_hex"] or spec["fields"][0][1]),
            )


def verify_report(
    plan: Report, report: Report, identified: cabc.Callable[[Report], bool]
) -> None:
    """Check a finished report against its plan and its own events.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The report that the run built.
    identified : collections.abc.Callable[[dict[str, typing.Any]], bool]
        Says whether the report names the live scripts that are checking it.
    """
    need(report["status"] == "completed", "Path matrix incomplete")
    need(
        report["plan_sha256"] == sha((json.dumps(plan, indent=2) + "\n").encode())
        and identified(report)
        and report["oracle_sha256"] == ORACLE_SHA256,
        "Plan/source/oracle differs",
    )
    streams = _streams_of(report["events"])
    need(streams == report["streams"], "Raw stream/event mismatch")
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(k) == v for k, v in decode_frame(raw).items()),
            "Frame/raw mismatch",
        )
    _arrivals(report)
    _main_stream(report, streams)
    _requests(plan, report)
    login_gate(report["frames"], "main")
    classify_views(plan, report)
    need(
        report["terminals"].get("main") in FINITE_TERMINALS,
        "Missing finite terminal",
    )
    need(
        all(not value for value in report["unparsed_hex"].values()),
        "Completed case has partial frame",
    )
