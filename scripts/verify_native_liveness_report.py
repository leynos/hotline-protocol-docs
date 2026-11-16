"""Check the generic control reports and the coordinator's custom case report."""

import typing as typ

from native_wire_names import FIELD_USER_ID, TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT
from verify_native_liveness_checks import Report, need, read, sha
from verify_native_liveness_pins import CASES, EXPECTED_302, PLAN, RUNNER

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

ACTIONS = 18  # the actions of each unchanged generic control
EMPTY_TEXT = ""  # the error text of a coordinator report that completed cleanly
OPERATIONS = 48  # the operations of the coordinator's custom case
FRAMES = 39  # the frames that the coordinator recorded in its window
EVENTS = 103  # the events that the coordinator recorded
DEPARTURES = 6  # the observer 302 frames that the window must contain
DEPARTURE_BYTES = 28  # the raw length of each observer 302 frame
DEPARTURE_FLOW = "o"  # the connection whose departures are observed
WINDOW_NS = 135_000_159_328  # the measured window, in nanoseconds
NS_PER_SECOND = 1e9  # nanoseconds in a second, as a float for the EOF division
EOF_TOLERANCE = 0.000001  # the allowed error of an EOF time, in seconds
EOF_TARGETS = (
    ("f", 35.138506),
    ("a", 65.116360),
    ("b", 110.017097),
    ("o", 135.008015),
)  # the measured EOF time of each connection, in seconds


def _check_capture(
    raw: Path,
    label: str,
    capture: types.ModuleType,
    readiness: types.ModuleType,
) -> None:
    """Check one generic 18-action control and its plan.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    label : str
        The control folder, ``readiness`` or ``postflight``.
    capture : typing.Any
        The capture verifier module.
    readiness : typing.Any
        The readiness module.
    """
    folder = raw / label
    report = capture.verify_capture(folder)
    need(
        report["status"] == "completed"
        and report["completed_actions"] == ACTIONS
        and sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json"),
        f"{label} generic 18-action control differs",
    )
    readiness.readiness(report)


def _coordinator_matches(raw: Path, report: Report) -> bool:
    """Return whether the coordinator report has the complete custom case identity.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    report : dict[str, typing.Any]
        The coordinator report.

    Returns
    -------
    bool
        Whether the status, the counts and the recorded digests match.
    """
    return (
        report["status"] == "completed"
        and report["error"] == EMPTY_TEXT
        and report["window_completed"] is True
        and len(report["operations"]) == OPERATIONS
        and len(report["frames"]) == FRAMES
        and len(report["events"]) == EVENTS
        and report["window_frame_count"] == FRAMES
        and report["plan_sha256"] == PLAN
        and report["receipt_sha256"] == sha(raw / "capture-ready.json")
        and report["source_sha256"] == RUNNER
        and report["cases_sha256"] == CASES
    )


def _window_matches(report: Report, t0: int) -> bool:
    """Return whether the measured window and the EOF labels are as recorded.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The coordinator report.
    t0 : int
        The elapsed time of the first operation, in nanoseconds.

    Returns
    -------
    bool
        Whether the window length and the terminal labels match.
    """
    return (
        report["window_elapsed_ns"] - t0 == WINDOW_NS
        and report["window_status"]["o"] == "bounded_no_eof_through_window"
        and report["terminals"]["o"] == "eof"
        and report["window_status"]["a"] == "eof"
        and report["window_status"]["b"] == "eof"
        and report["window_status"]["f"] == "eof"
    )


def _check_eof(report: Report, t0: int) -> None:
    """Check the EOF time of each connection against its measured target.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The coordinator report.
    t0 : int
        The elapsed time of the first operation, in nanoseconds.
    """
    for name, target in EOF_TARGETS:
        events = [
            event
            for event in report["events"]
            if event["connection"] == name and event["event"] == "eof"
        ]
        need(
            len(events) == 1
            and abs((events[0]["elapsed_ns"] - t0) / NS_PER_SECOND - target)
            < EOF_TOLERANCE,
            f"{name} EOF timing differs",
        )


def _check_departure(report: Report) -> None:
    """Check the observer 302 departures and that no 301 was inserted.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The coordinator report.
    """
    departure = [
        frame
        for frame in report["frames"]
        if frame["connection"] == DEPARTURE_FLOW and frame["type"] == TYPE_USER_LEFT
    ]
    need(
        len(departure) == DEPARTURES
        and all(
            (
                frame["flags"],
                frame["is_reply"],
                frame["error"],
                len(bytes.fromhex(frame["raw_hex"])),
            )
            == (0, 0, 0, DEPARTURE_BYTES)
            and len(frame["fields"]) == 1
            and frame["fields"][0]["id"] == FIELD_USER_ID
            for frame in departure
        )
        and tuple(frame["fields"][0]["hex"] for frame in departure) == EXPECTED_302,
        "Observer 302 UID, header or raw length differs",
    )
    need(
        not any(frame["type"] == TYPE_PRESENCE_UPDATE for frame in report["frames"]),
        "Unexpected observer 301 was inserted",
    )


def report_gate(corpus: Path, modules: tuple[typ.Any, ...], plan: Report) -> Report:
    """Check the generic controls and the coordinator report, and return the report.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[typing.Any, ...]
        The frozen modules, as yielded by ``frozen``.
    plan : dict[str, typing.Any]
        The generated plan, as returned by ``source_gate``.

    Returns
    -------
    dict[str, typing.Any]
        The coordinator report.
    """
    raw = corpus / "raw"
    control, _, readiness, capture, _ = modules
    for label in ("readiness", "postflight"):
        _check_capture(raw, label, capture, readiness)
    report = read(raw / "coordinator/report.json")
    need(
        _coordinator_matches(raw, report),
        "Complete custom case identity or counts differ",
    )
    control.verify_report(plan, report)
    t0 = report["operations"][0]["elapsed_ns"]
    need(_window_matches(report, t0), "Measured finite window or EOF labels differ")
    _check_eof(report, t0)
    _check_departure(report)
    return report
