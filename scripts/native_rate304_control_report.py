"""Check a finished 304 report offline, against its plan and its own events.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. The checks run
in a fixed order, so a fault is reported by the first check that finds it.
"""

import json
import typing as typ

import native_rate304_cases as cases
from native_rate304_control_classify import classify
from native_rate304_control_frames import (
    BURST_BARRIERS,
    BURST_REQUESTS,
    ICON_FIRST,
    ICON_TERMINAL,
    MAX_UID,
    PACED_BARRIERS,
    PACED_REQUESTS,
    QUIET_SECONDS,
    ROSTER_ID,
    TRIAL_SECONDS,
    UID_BYTES,
    UPDATES,
    Report,
    digest,
    exact_fields,
    need,
    one,
)
from native_wire_names import (
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import ORACLE_SHA256, decode_frame
from verify_native_auth import roster

if typ.TYPE_CHECKING:
    import collections.abc as cabc

NS_PER_SECOND = 1e9
IDLE_MIN = 13
IDLE_MAX = 15
OBSERVER_IDLE_BASE = 5000
OBSERVER_CONTROL_TYPE = 303
TERMINAL_EVENTS = frozenset({"eof", "rst"})


def expected_actions(
    plan: Report, idle_count: int, observer_uid: int
) -> list[tuple[str, str, str]]:
    """List the requests the runner must have made, in order.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    idle_count : int
        How many idle barriers the observer sent during the quiet interval.
    observer_uid : int
        The observer's user id, used by its 303 control.

    Returns
    -------
    list[tuple[str, str, str]]
        The label, the flow and the hex of each request.
    """
    need(IDLE_MIN <= idle_count <= IDLE_MAX, "Observer idle cadence differs")
    need(1 <= observer_uid <= MAX_UID, "Observer UID invalid for expected actions")
    roster_request = cases.observer_control(300, ROSTER_ID)
    actions = [
        ("observer-login", "observer", plan["logins"]["observer"]),
        ("observer-roster-initial", "observer", roster_request),
        ("paced-login", "paced", plan["logins"]["paced"]),
        ("paced-roster", "paced", roster_request),
    ]
    for index in range(UPDATES):
        actions.extend([
            (
                f"paced-304-{index:02d}",
                "paced",
                cases.update(PACED_REQUESTS + index, index + ICON_FIRST),
            ),
            (
                f"paced-500-{index:02d}",
                "paced",
                cases.barrier(PACED_BARRIERS + index),
            ),
        ])
    actions.extend(
        (
            f"observer-idle500-{index:02d}",
            "observer",
            cases.barrier(OBSERVER_IDLE_BASE + index),
        )
        for index in range(idle_count)
    )
    actions.extend([
        (
            "paced-304-after-quiet",
            "paced",
            cases.update(PACED_REQUESTS + UPDATES, ICON_TERMINAL),
        ),
        ("paced-500-after-quiet", "paced", cases.barrier(PACED_BARRIERS + UPDATES)),
        ("burst-login", "burst", plan["logins"]["burst"]),
        ("burst-roster", "burst", roster_request),
    ])
    for index in range(UPDATES):
        actions.extend([
            (
                f"burst-304-{index:02d}",
                "burst",
                cases.update(BURST_REQUESTS + index, index + ICON_FIRST),
            ),
            (
                f"burst-500-{index:02d}",
                "burst",
                cases.barrier(BURST_BARRIERS + index),
            ),
        ])
    actions.extend([
        (
            "burst-304-terminal",
            "burst",
            cases.update(BURST_REQUESTS + UPDATES, ICON_TERMINAL),
        ),
        ("probe-login", "probe", plan["logins"]["probe"]),
    ])
    for kind, identifier in plan["request_ids"]["observer_controls"].items():
        actions.append((
            f"observer-{kind}",
            "observer",
            cases.observer_control(
                int(kind),
                identifier,
                observer_uid if int(kind) == OBSERVER_CONTROL_TYPE else None,
            ),
        ))
    return actions


def _stream_events(report: Report) -> dict[str, dict[str, str]]:
    """Require monotonic event times and rebuild each flow's streams.

    Returns
    -------
    dict[str, dict[str, str]]
        ``sent_hex`` and ``received_hex`` by flow name.
    """
    rebuilt: dict[str, dict[str, str]] = {}
    last_ns = -1
    for event in report["events"]:
        need(event["elapsed_ns"] >= last_ns, "Nonmonotonic event timestamp")
        last_ns = event["elapsed_ns"]
        stream = rebuilt.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        match event["event"]:
            case "send":
                stream["sent_hex"] += event["hex"]
            case "receive":
                stream["received_hex"] += event["hex"]
    return rebuilt


def _action_schedule(plan: Report, report: Report) -> dict[str, str]:
    """Require the as-run actions to be the expected ones and tie them to events.

    Returns
    -------
    dict[str, str]
        The bytes each flow was injected with, by flow name.
    """
    expected = dict.fromkeys(plan["schedule"]["flows"], cases.HELLO)
    actions = report["actions"]
    idle_count = sum(a["label"].startswith("observer-idle500-") for a in actions)
    need(
        [(a["label"], a["connection"], a["hex"]) for a in actions]
        == expected_actions(
            plan,
            idle_count,
            roster(one(report["frames"], "observer", 0, ROSTER_ID, 1))[0]["uid"],
        ),
        "As-run request action schedule differs",
    )
    prior_end = 0
    for action in actions:
        first, last = action["event_range"]
        need(
            prior_end <= first < last <= len(report["events"])
            and action["connection"] in expected
            and action["elapsed_ns"] >= report["events"][last - 1]["elapsed_ns"],
            "Action/event range differs",
        )
        sent = "".join(
            e["hex"] for e in report["events"][first:last] if e["event"] == "send"
        )
        need(sent == action["hex"], "Action sent bytes differ")
        expected[action["connection"]] += action["hex"]
        prior_end = last
    return expected


def _phase_update(frame: Report, receiver: str, uid: bytes) -> bool:
    """Say whether a frame is a 301 update of the subject within the phase's icons.

    Returns
    -------
    bool
        ``True`` for a 301 to ``receiver`` that names ``uid`` and one of the
        phase's icons.
    """
    if frame["connection"] != receiver or frame["type"] != TYPE_PRESENCE_UPDATE:
        return False
    content = exact_fields(frame)
    icon = int.from_bytes(content.get(FIELD_ICON, b"\0\0"), "big")
    return content.get(FIELD_USER_ID) == uid and ICON_FIRST <= icon <= ICON_TERMINAL - 1


def _phase_updates(
    report: Report, label: str, first_ns: int, completed_ns: int
) -> None:
    """Require the phase's updates and barrier ACKs to fall inside its receipt."""
    uid = report["identities"][f"{label}_uid"].to_bytes(UID_BYTES, "big")
    for receiver in ("observer", label):
        for frame in report["frames"]:
            if _phase_update(frame, receiver, uid):
                need(
                    first_ns <= frame["arrival_elapsed_ns"] <= completed_ns,
                    f"{label} update outside phase receipt",
                )
    barriers = PACED_BARRIERS if label == "paced" else BURST_BARRIERS
    for index in range(UPDATES):
        ack = one(report["frames"], label, 0, barriers + index, 1)
        need(
            first_ns <= ack["arrival_elapsed_ns"] <= completed_ns,
            f"{label} barrier outside phase receipt",
        )


def _phase_timing(
    plan: Report, report: Report, action_times: dict[str, int], label: str
) -> None:
    """Require one subject's request timing and phase receipt to agree."""
    first, last = f"{label}-304-00", f"{label}-500-25"
    elapsed = (action_times[last] - action_times[first]) / NS_PER_SECOND
    need(
        0 <= elapsed <= report["timing"][f"{label}_trial_seconds"] <= TRIAL_SECONDS,
        f"{label} request timing receipt differs",
    )
    phase = report["phase_receipts"][label]
    need(
        phase["mode"] == plan["schedule"]["phase_mode"]
        and phase["started_elapsed_ns"]
        <= action_times[first]
        <= action_times[last]
        <= phase["all_pairs_sent_elapsed_ns"]
        <= phase["completed_elapsed_ns"]
        and 0
        <= (phase["completed_elapsed_ns"] - phase["started_elapsed_ns"]) / NS_PER_SECOND
        <= report["timing"][f"{label}_trial_seconds"]
        <= TRIAL_SECONDS,
        f"{label} pipeline timing receipt differs",
    )
    _phase_updates(report, label, action_times[first], phase["completed_elapsed_ns"])


def _timing(plan: Report, report: Report) -> None:
    """Require the phase receipts and the quiet interval to agree with the actions."""
    action_times = {a["label"]: a["elapsed_ns"] for a in report["actions"]}
    for label in ("paced", "burst"):
        _phase_timing(plan, report, action_times, label)
    quiet_bound = (
        action_times["paced-304-after-quiet"] - action_times["paced-500-25"]
    ) / NS_PER_SECOND
    need(
        quiet_bound >= report["timing"]["subject_quiet_seconds"] >= QUIET_SECONDS,
        "Subject quiet timing receipt differs",
    )


def _streams(report: Report, expected: dict[str, str]) -> None:
    """Require the streams to be the injected bytes, the hello reply and the frames."""
    need(
        set(expected) == set(report["streams"])
        and all(
            report["streams"][name]["sent_hex"] == raw for name, raw in expected.items()
        ),
        "Injected request stream differs from declared actions",
    )
    for name, stream in report["streams"].items():
        need(stream["received_hex"].startswith(cases.HELLO_REPLY), "TRTP reply differs")
        parsed = "".join(
            f["raw_hex"] for f in report["frames"] if f["connection"] == name
        )
        need(
            stream["received_hex"]
            == cases.HELLO_REPLY + parsed + report["unparsed_hex"][name],
            "Received bytes omitted/reordered",
        )
    need(
        all(not raw for raw in report["unparsed_hex"].values()),
        "Completed case has truncated/unparsed tail",
    )


def _terminals(plan: Report, report: Report) -> None:
    """Require each flow's terminal label to follow from its events."""
    for name in plan["schedule"]["flows"]:
        terminals = [
            e["event"]
            for e in report["events"]
            if e["connection"] == name and e["event"] in TERMINAL_EVENTS
        ]
        need(len(terminals) <= 1, "Contradictory socket terminals")
        observed = terminals[0] if terminals else "bounded_no_eof"
        need(
            report["terminals"].get(name) == observed,
            "Terminal label differs from bytes/events",
        )


def _identified(
    plan: Report, report: Report, identified: cabc.Callable[[Report], bool]
) -> None:
    """Require the report to name this plan, these scripts and this oracle."""
    need(
        report["plan_sha256"] == digest((json.dumps(plan, indent=2) + "\n").encode())
        and identified(report)
        and report["oracle_sha256"] == ORACLE_SHA256,
        "As-run plan/source/oracle identity differs",
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
    need(report["status"] == "completed", "Rate304 run incomplete")
    need(report["native_clock_calibrated"] is False, "Native clock not calibrated")
    need(
        report["phase_progress"] == {"paced": UPDATES, "burst": UPDATES},
        "Incomplete phase progress",
    )
    need(
        report["phase_mode"] == plan["schedule"]["phase_mode"],
        "As-run pipeline mode differs",
    )
    _identified(plan, report, identified)
    need(_stream_events(report) == report["streams"], "Stream bytes differ from events")
    expected = _action_schedule(plan, report)
    _timing(plan, report)
    _streams(report, expected)
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(k) == v for k, v in decode_frame(raw).items()),
            "Decoded frame differs from raw",
        )
    _terminals(plan, report)
    need(
        len(report["frames"]) <= plan["schedule"]["max_frames"]
        and sum(len(bytes.fromhex(e["hex"])) for e in report["events"])
        <= plan["schedule"]["max_bytes"],
        "Frame/byte bound exceeded",
    )
    classify(plan, report)
