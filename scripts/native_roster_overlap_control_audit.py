"""Replay an as-run overlap report against the source plan it claims to follow.

The replay confirms that every recorded event and frame belongs to a source
operation, and that the recorded TCP streams are the bytes of the events.
"""

import json

from native_roster_overlap_control_checks import need, sha
from protocol_capture import decode_frame


def verify_operation_map(plan: dict, report: dict) -> None:
    """Replay source operation labels and retained event/stream provenance.

    Parameters
    ----------
    plan : dict
        The source plan that the as-run report claims to have followed.
    report : dict
        The as-run report, with its operation map, events, frames and streams.
    """
    schedule = plan["coordinator"]
    need(
        report["plan_sha256"] == sha((json.dumps(plan, indent=2) + "\n").encode()),
        "As-run plan source changed",
    )
    need(
        schedule["schema_version"] == 1 and schedule["drain_action"] == -1,
        "Coordinator schema differs",
    )
    need(
        report["coordinator_sha256"]
        == sha(json.dumps(schedule, sort_keys=True).encode()),
        "Coordinator source changed",
    )
    mapped = report["operation_map"]
    need(
        [entry["label"] for entry in mapped]
        == ["setup", *[op["label"] for op in schedule["operations"]], "teardown"],
        "Operation map labels differ",
    )
    events, frames = report["events"], report["frames"]
    cursor = (0, 0)
    for entry in mapped:
        cursor = _check_bounds(entry, cursor, events, frames)
        _check_operation(plan, entry, events, frames)
    need(cursor == (len(events), len(frames)), "Unmapped as-run event or frame")
    _check_streams(report)


def _check_bounds(
    entry: dict, cursor: tuple[int, int], events: list[dict], frames: list[dict]
) -> tuple[int, int]:
    """Check that an operation's ranges continue from the cursor.

    Parameters
    ----------
    entry : dict
        One entry of the operation map.
    cursor : tuple[int, int]
        The event and frame positions that the previous entry ended at.
    events : list[dict]
        The as-run events.
    frames : list[dict]
        The as-run frames.

    Returns
    -------
    tuple[int, int]
        The event and frame positions that this entry ends at.
    """
    begin, end = entry["event_range"]
    first, last = entry["frame_range"]
    event_cursor, frame_cursor = cursor
    need(
        begin == event_cursor <= end <= len(events)
        and first == frame_cursor <= last <= len(frames),
        "Operation map bounds differ",
    )
    return end, last


def _check_operation(
    plan: dict, entry: dict, events: list[dict], frames: list[dict]
) -> None:
    """Check the events and frames of one operation against its source.

    Parameters
    ----------
    plan : dict
        The source plan.
    entry : dict
        One entry of the operation map, already checked for bounds.
    events : list[dict]
        The as-run events.
    frames : list[dict]
        The as-run frames.
    """
    begin, end = entry["event_range"]
    first, last = entry["frame_range"]
    source = next(
        (
            op
            for op in plan["coordinator"]["operations"]
            if op["label"] == entry["label"]
        ),
        None,
    )
    if source and source["op"] == "send":
        _check_send(plan, source, events[begin:end])
    if source and source["op"] == "drain":
        _check_drain(events[begin:end], frames[first:last])
    if source and source["op"] == "quiet":
        _check_quiet(events[begin:end], source)


def _check_send(plan: dict, source: dict, span: list[dict]) -> None:
    """Check that the sent events of a request are the request's bytes.

    Parameters
    ----------
    plan : dict
        The source plan, which holds the request bytes.
    source : dict
        The source operation, a send.
    span : list[dict]
        The events of the operation.
    """
    chunks = [event for event in span if event["event"] == "send"]
    need(
        len(chunks) >= 1
        and all(e["connection"] == source["connection"] for e in chunks)
        and "".join(e["hex"] for e in chunks) == plan["overlap"][source["packet_key"]],
        "Injected request bytes differ",
    )


def _check_drain(span: list[dict], frames: list[dict]) -> None:
    """Check the provenance of a drain's events and frames.

    Parameters
    ----------
    span : list[dict]
        The events of the drain.
    frames : list[dict]
        The frames of the drain.
    """
    need(
        all(e["action"] == -1 for e in span)
        and all(
            f["action"] == -1
            and f["raw_hex"]
            and decode_frame(bytes.fromhex(f["raw_hex"]))["id"] == f["id"]
            for f in frames
        ),
        "Custom drain event/frame provenance differs",
    )
    for label in ("a", "b"):
        wire = "".join(
            e["hex"]
            for e in span
            if e["event"] == "receive" and e["connection"] == label
        )
        parsed = "".join(f["raw_hex"] for f in frames if f["connection"] == label)
        need(wire == parsed, "Custom drain raw frames differ from bytes")


def _check_quiet(span: list[dict], source: dict) -> None:
    """Check that a quiet observation was made on its own connection.

    Parameters
    ----------
    span : list[dict]
        The events of the observation.
    source : dict
        The source operation, a quiet observation.
    """
    need(
        len(span) == 1
        and span[0]["connection"] == source["connection"]
        and span[0]["event"] in {"quiet", "receive", "eof"},
        "Quiet observation connection differs",
    )


def _check_streams(report: dict) -> None:
    """Check that the recorded TCP streams are the bytes of the raw events.

    Parameters
    ----------
    report : dict
        The as-run report, with its events and streams.
    """
    rebuilt: dict[str, dict[str, str]] = {}
    for event in report["events"]:
        label = event["connection"]
        if not label:
            continue
        stream = rebuilt.setdefault(label, {"sent_hex": "", "received_hex": ""})
        match event["event"]:
            case "send":
                stream["sent_hex"] += event["hex"]
            case "receive":
                stream["received_hex"] += event["hex"]
    need(rebuilt == report["streams"], "Recorded TCP streams differ from raw events")
