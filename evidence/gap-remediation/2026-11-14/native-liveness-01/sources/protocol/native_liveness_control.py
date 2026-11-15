#!/usr/bin/env python3
"""Run the bounded B74 liveness schedule inside its owned network namespace."""

import argparse
import hashlib
import json
import os
import select
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import native_liveness_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from protocol_capture import ORACLE_SHA256, Recorder, decode_frame
from verify_native_auth import roster
from verify_native_shx import fields

MAX_WINDOW_SECONDS = 720
AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
SCHEDULE_LATE_NS = 5_000_000_000
SCHEDULE_EARLY_NS = 5_000_000  # Float seconds to monotonic-ns conversion allowance.


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def prepared(directory: Path) -> dict:
    raw = (directory / "plan.json").read_bytes()
    hashes = json.loads((directory / "source-hashes.json").read_text())
    need(hashes == {"plan.json": digest(raw)}, "Prepared plan hash differs")
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared schedule differs from frozen producer",
    )
    return plan


class Timeline:
    """Retain complete receive chunks, parsed frames and all socket terminals."""

    def __init__(self, plan: dict, deadline: float) -> None:
        self.plan = plan
        self.deadline = deadline
        self.recorder = Recorder({"endpoints": {"control": plan["endpoint"]}})
        self.buffers: dict[str, bytearray] = {}
        self.terminals: dict[str, str] = {}
        self.window_status: dict[str, str] = {}
        self.window_frame_count: int | None = None
        self.frames: list[dict] = []
        self.operations: list[dict] = []
        self.next_action = 0
        self.max_bytes = plan["schedule"]["max_bytes"]
        self.tail_mode = False
        self.tail_bytes: dict[str, int] = {}

    def action(self) -> int:
        result = self.next_action
        self.next_action += 1
        return result

    def execute(self, step: dict) -> None:
        need(time.monotonic() < self.deadline, "Global liveness deadline reached")
        self.recorder.execute(
            self.action(),
            {
                **step,
                "timeout": min(
                    step.get("timeout", 2), self.deadline - time.monotonic()
                ),
            },
        )
        need(self.recorder.byte_count <= self.max_bytes, "128KiB capture cap reached")

    def connect(self, name: str) -> None:
        need(name not in self.recorder.sockets, "Duplicate flow")
        need(
            len(self.recorder.sockets) < self.plan["schedule"]["max_simultaneous"],
            "Simultaneous flow bound reached",
        )
        self.execute({"op": "connect", "connection": name, "endpoint": "control"})
        self.execute({"op": "send", "connection": name, "hex": cases.HELLO})
        self.execute(
            {
                "op": "read",
                "connection": name,
                "size": 8,
                "expect_hex": cases.HELLO_REPLY,
            }
        )
        self.buffers[name] = bytearray()

    def send(self, name: str, raw_hex: str) -> None:
        need(name in self.recorder.sockets, f"Unknown flow {name}")
        need(name not in self.terminals, f"Flow {name} already ended")
        self.execute({"op": "send", "connection": name, "hex": raw_hex})

    def poll(self, seconds: float) -> None:
        until = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < until and self.recorder.sockets:
            active = {
                sock: name
                for name, sock in self.recorder.sockets.items()
                if name not in self.terminals
            }
            if not active:
                time.sleep(min(0.02, max(0, until - time.monotonic())))
                continue
            ready, _, _ = select.select(
                list(active), [], [], min(0.05, max(0, until - time.monotonic()))
            )
            for sock in ready:
                name = active[sock]
                try:
                    allowance = min(65536, self.max_bytes - self.recorder.byte_count)
                    if self.tail_mode:
                        allowance = min(
                            allowance,
                            self.plan["schedule"]["max_tail_bytes_per_flow"]
                            - self.tail_bytes.get(name, 0),
                        )
                    need(allowance > 0, "Total or per-flow tail capture cap reached")
                    data = sock.recv(allowance)
                except ConnectionResetError:
                    self.recorder.event(-1, name, "rst")
                    self.terminals[name] = "rst"
                    continue
                if not data:
                    self.recorder.event(-1, name, "eof")
                    self.terminals[name] = "eof"
                    continue
                self.recorder.event(-1, name, "receive", data)
                if self.tail_mode:
                    self.tail_bytes[name] = self.tail_bytes.get(name, 0) + len(data)
                self.buffers[name].extend(data)
                self._parse(name)

    def _parse(self, name: str) -> None:
        buffer = self.buffers[name]
        while len(buffer) >= 20:
            size = 20 + int.from_bytes(buffer[16:20], "big")
            need(20 <= size <= self.max_bytes, "Unbounded or malformed frame size")
            if len(buffer) < size:
                break
            raw = bytes(buffer[:size])
            del buffer[:size]
            frame = {
                "connection": name,
                "raw_hex": raw.hex(),
                "arrival_elapsed_ns": time.monotonic_ns() - self.recorder.started,
                **decode_frame(raw),
            }
            self.frames.append(frame)
            need(len(self.frames) <= 128, "128-frame cap reached")

    def wait_for(self, predicate, seconds: float, label: str) -> None:
        end = min(time.monotonic() + seconds, self.deadline)
        while not predicate():
            need(time.monotonic() < end, f"Missing {label}")
            self.poll(min(0.05, end - time.monotonic()))

    def close(self, name: str) -> None:
        if name in self.recorder.sockets:
            self.recorder.sockets.pop(name).close()
            self.recorder.event(self.action(), name, "close")

    def final_drain(self) -> None:
        self.tail_mode = True
        for name, sock in list(self.recorder.sockets.items()):
            if name not in self.terminals:
                try:
                    sock.shutdown(socket.SHUT_WR)
                    self.recorder.event(self.action(), name, "shutdown_write")
                except OSError:
                    self.recorder.event(self.action(), name, "shutdown_write_failed")
        self.poll(min(3, max(0, self.deadline - time.monotonic())))
        for name in list(self.recorder.sockets):
            if name not in self.terminals:
                self.terminals[name] = "bounded_no_eof"
            self.close(name)


def matching(frames: list[dict], name: str, identifier: int) -> list[dict]:
    return [
        frame
        for frame in frames
        if frame["connection"] == name
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["id"] == identifier
    ]


def successful(frames: list[dict], name: str, identifier: int) -> bool:
    return (
        len(matching(frames, name, identifier)) == 1
        and matching(frames, name, identifier)[0]["error"] == 0
    )


def agreement_ok(frames: list[dict], name: str) -> bool:
    notices = [f for f in frames if f["connection"] == name and f["type"] == 109]
    return (
        len(notices) == 1
        and notices[0]["is_reply"] == 0
        and set(fields(notices[0])) == {101}
        and digest(fields(notices[0])[101]) == AGREEMENT_SHA256
    )


def check_observer(timeline: Timeline) -> None:
    need(successful(timeline.frames, "o", 1), "Observer107 failed")
    need(
        any(f["connection"] == "o" and f["type"] == 354 for f in timeline.frames),
        "Observer did not become online",
    )
    need(
        agreement_ok(timeline.frames, "o"),
        "Observer agreement differs from controlled 242 bytes",
    )


def check_b_preonline(timeline: Timeline) -> None:
    frames = timeline.frames
    need(successful(frames, "b", 1), "B valid107 did not succeed")
    need(
        agreement_ok(frames, "b"),
        "B controlled agreement differs",
    )
    need(
        not any(f["connection"] == "b" and f["type"] == 354 for f in frames),
        "B became online before complete121",
    )
    rosters = matching(frames, "o", 10)
    need(len(rosters) == 1 and rosters[0]["error"] == 0, "Observer300 missing")
    need(
        all(
            bytes.fromhex(row["name_hex"]) != cases.NAME_B for row in roster(rosters[0])
        ),
        "B appeared in preonline roster",
    )


def check_failure(timeline: Timeline) -> None:
    replies = matching(timeline.frames, "f", 1)
    need(len(replies) == 1 and replies[0]["error"] != 0, "F failure107 differs")


def check_complete(timeline: Timeline) -> None:
    view = Timeline(timeline.plan, time.monotonic() + 1)
    view.frames = timeline.frames[: timeline.window_frame_count]
    view.window_status = timeline.window_status
    check_observer(view)
    check_b_preonline(view)
    check_failure(view)
    for at in range(5, 135, 5):
        need(successful(view.frames, "o", 100 + at // 5), f"O500 {at} failed")
    need(
        not any(
            f["connection"] == "b" and f["is_reply"] and f["id"] == 2
            for f in view.frames
        ),
        "Incomplete B121 received a reply",
    )
    for name in ("a", "b", "f", "s35", "s75", "s120"):
        need(name in timeline.window_status, f"Missing window observation: {name}")


def perform_operation(timeline: Timeline, op: dict, end: float) -> None:
    """Execute one generated injection or bounded observation."""
    name = op["connection"]
    if op["op"] in {"admit", "stimulus"}:
        timeline.connect(name)
        if op["hex"]:
            timeline.send(name, op["hex"])
        if op["op"] == "stimulus":
            timeline.poll(0.25)
            timeline.close(name)
            timeline.terminals.setdefault(
                name, "client_closed_after_bounded_observation"
            )
    elif op["op"] == "send":
        if op["label"] == "b121-partial-body":
            timeline.wait_for(
                lambda: bool(matching(timeline.frames, "o", 10)),
                min(1, end - time.monotonic()),
                "observer300 at T46",
            )
            check_b_preonline(timeline)
        timeline.send(name, op["hex"])
    elif op["op"] == "checkpoint":
        timeline.poll(0)
    else:
        raise ValueError("Unrecognised schedule action")


def verify_report(plan: dict, report: dict) -> None:
    """Check a complete custom report; this is not generic verify_capture."""
    need(
        report["status"] == "completed" and report["window_completed"],
        "Case incomplete",
    )
    need(report["native_conformance"] is False, "Unexpected conformance claim")
    source = (json.dumps(plan, indent=2) + "\n").encode()
    need(
        report["plan_sha256"] == digest(source)
        and report["cases_sha256"] == digest(Path(cases.__file__).read_bytes())
        and report["source_sha256"] == digest(Path(__file__).read_bytes())
        and report["oracle_sha256"] == ORACLE_SHA256,
        "As-run source identity changed",
    )
    events = report["events"]
    rebuilt: dict[str, dict[str, str]] = {}
    for event in events:
        name = event["connection"]
        stream = rebuilt.setdefault(name, {"sent_hex": "", "received_hex": ""})
        if event["event"] == "send":
            stream["sent_hex"] += event["hex"]
        elif event["event"] == "receive":
            stream["received_hex"] += event["hex"]
    need(rebuilt == report["streams"], "Raw streams differ from events")
    expected = {
        name: cases.HELLO for name in ("o", "a", "b", "f", "s35", "s75", "s120")
    }
    expected["o"] += plan["observer_login_hex"]
    for op in plan["schedule"]["operations"]:
        if op["connection"]:
            expected[op["connection"]] += op["hex"]
    need(
        set(report["streams"]) == set(expected)
        and all(
            report["streams"][name]["sent_hex"] == raw for name, raw in expected.items()
        ),
        "Injected TCP bytes differ from generated schedule",
    )
    operation_log = report["operations"]
    schedule = plan["schedule"]["operations"]
    need(
        len(operation_log) == len(schedule) + 1
        and operation_log[0]["label"] == "t0"
        and [item["label"] for item in operation_log[1:]]
        == [op["label"] for op in schedule],
        "As-run schedule labels differ",
    )
    t0 = operation_log[0]["elapsed_ns"]
    window = report["window_elapsed_ns"]
    need(
        isinstance(t0, int)
        and isinstance(window, int)
        and 0 <= t0 < window
        and t0 + 135_000_000_000 - SCHEDULE_EARLY_NS
        <= window
        <= t0 + 135_000_000_000 + SCHEDULE_LATE_NS,
        "135-second window timing differs",
    )
    prior_event_ns = -1
    for event in events:
        elapsed = event["elapsed_ns"]
        need(
            isinstance(elapsed, int) and prior_event_ns <= elapsed,
            "Raw event times are not monotonic",
        )
        prior_event_ns = elapsed
    event_cursor = operation_log[1]["event_range"][0]
    frame_cursor = operation_log[1]["frame_range"][0]
    previous_operation_ns = t0
    for item, op in zip(operation_log[1:], schedule, strict=True):
        first, last = item["event_range"]
        front, back = item["frame_range"]
        need(
            first == event_cursor <= last <= len(events)
            and front == frame_cursor <= back <= len(report["frames"]),
            "As-run ranges are gapped or overlapping",
        )
        actual = item["actual_elapsed_ns"]
        target = t0 + op["at_seconds"] * 1_000_000_000
        need(
            isinstance(actual, int)
            and previous_operation_ns <= actual <= window
            and target - SCHEDULE_EARLY_NS <= actual <= target + SCHEDULE_LATE_NS
            and all(
                previous_operation_ns <= event["elapsed_ns"] <= actual
                for event in events[first:last]
            ),
            f"Scheduled time differs at {op['label']}",
        )
        injected = "".join(
            event["hex"] for event in events[first:last] if event["event"] == "send"
        )
        planned = (cases.HELLO if op["op"] in {"admit", "stimulus"} else "") + op["hex"]
        need(injected == planned, f"Injected bytes differ at {op['label']}")
        event_cursor, frame_cursor = last, back
        previous_operation_ns = actual
    need(
        all(event["elapsed_ns"] >= window for event in events[event_cursor:]),
        "Teardown event predates window boundary",
    )
    need(
        all(item["arrival_elapsed_ns"] >= 0 for item in report["frames"]),
        "Missing frame arrival timing",
    )
    by_name: dict[str, list[dict]] = {name: [] for name in expected}
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(key) == value for key, value in decode_frame(raw).items()),
            "Decoded frame differs from raw",
        )
        by_name[frame["connection"]].append(frame)
    for name, stream in report["streams"].items():
        raw = stream["received_hex"]
        need(raw.startswith(cases.HELLO_REPLY), "TRTP reply missing")
        parsed = "".join(frame["raw_hex"] for frame in by_name[name])
        need(
            raw[len(cases.HELLO_REPLY) :] == parsed + report["unparsed_hex"][name],
            "Received bytes omitted or reordered",
        )
    need(
        all(name in report["window_status"] for name in expected),
        "Missing finite socket status",
    )
    need(set(report["window_status"]) == set(expected), "Extra window socket status")
    for name in expected:
        terminal = [
            event["event"]
            for event in events
            if event["connection"] == name
            and event["elapsed_ns"] <= window
            and event["event"] in {"eof", "rst"}
        ]
        need(len(terminal) <= 1, f"Conflicting terminal events: {name}")
        closed = any(
            event["connection"] == name
            and event["elapsed_ns"] <= window
            and event["event"] == "close"
            for event in events
        )
        observed = (
            terminal[0]
            if terminal
            else "client_closed_after_bounded_observation"
            if closed
            else "bounded_no_eof_through_window"
        )
        need(
            report["window_status"][name] == observed,
            f"Window socket outcome differs from events: {name}",
        )
        full_terminal = [
            event["event"]
            for event in events
            if event["connection"] == name and event["event"] in {"eof", "rst"}
        ]
        need(len(full_terminal) <= 1, f"Conflicting full terminal events: {name}")
        final_observed = (
            full_terminal[0]
            if full_terminal
            else "client_closed_after_bounded_observation"
            if closed
            else "bounded_no_eof"
        )
        need(
            report["terminals"].get(name) == final_observed,
            f"Final socket outcome differs from events: {name}",
        )
    need(
        isinstance(report["window_frame_count"], int)
        and 0 <= report["window_frame_count"] <= len(report["frames"]),
        "Window frame boundary missing",
    )
    view = Timeline(plan, time.monotonic() + 1)
    view.frames = report["frames"]
    view.window_status = report["window_status"]
    view.window_frame_count = report["window_frame_count"]
    check_complete(view)


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    plan = prepared(plan_dir)
    receipt = json.loads(receipt_path.read_text())
    deadline_utc = utc(receipt["deadline_utc"])
    need(
        0
        < (deadline_utc - datetime.now(timezone.utc)).total_seconds()
        <= MAX_WINDOW_SECONDS,
        "Epoch must fit12min",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat("/proc/self/ns/net").st_ino
        == plan["environment"]["emulator_netns_inode"],
        "Caller is outside the owned emulator namespace",
    )
    need(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    output.mkdir(parents=True, exist_ok=False)
    end = min(
        time.monotonic() + plan["schedule"]["hard_deadline_seconds"],
        time.monotonic() + (deadline_utc - datetime.now(timezone.utc)).total_seconds(),
    )
    timeline = Timeline(plan, end)
    started = time.monotonic()
    status, error = "completed", ""
    window_completed = False
    try:
        timeline.connect("o")
        timeline.send("o", plan["observer_login_hex"])
        timeline.wait_for(
            lambda: all(
                [
                    successful(timeline.frames, "o", 1),
                    any(
                        f["connection"] == "o" and f["type"] == 354
                        for f in timeline.frames
                    ),
                    any(
                        f["connection"] == "o" and f["type"] == 109
                        for f in timeline.frames
                    ),
                ]
            ),
            8,
            "observer online107/354/109",
        )
        check_observer(timeline)
        runtime_gate(receipt, plan["environment"], deadline_utc)
        t0 = time.monotonic()
        timeline.operations.append(
            {
                "label": "t0",
                "elapsed_ns": time.monotonic_ns() - timeline.recorder.started,
            }
        )
        for op in plan["schedule"]["operations"]:
            event_start, frame_start = (
                len(timeline.recorder.events),
                len(timeline.frames),
            )
            target = t0 + op["at_seconds"]
            need(target < end, "Scheduled action past global deadline")
            while time.monotonic() < target:
                timeline.poll(min(0.05, target - time.monotonic()))
            perform_operation(timeline, op, end)
            timeline.operations.append(
                {
                    "label": op["label"],
                    "at_seconds": op["at_seconds"],
                    "actual_elapsed_ns": time.monotonic_ns()
                    - timeline.recorder.started,
                    "event_range": [event_start, len(timeline.recorder.events)],
                    "frame_range": [frame_start, len(timeline.frames)],
                    "terminals": dict(timeline.terminals),
                }
            )
        while time.monotonic() < t0 + 135:
            timeline.poll(min(0.05, t0 + 135 - time.monotonic()))
        window_completed = True
        window_elapsed_ns = time.monotonic_ns() - timeline.recorder.started
        timeline.window_frame_count = len(timeline.frames)
        timeline.window_status = {
            name: timeline.terminals.get(name, "bounded_no_eof_through_window")
            for name in timeline.buffers
        }
        check_complete(timeline)
    except (
        OSError,
        ValueError,
        TimeoutError,
        EOFError,
        KeyError,
        IndexError,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        try:
            timeline.final_drain()
        except (OSError, ValueError, TimeoutError) as failure:
            status = "failed"
            error += f"; teardown {type(failure).__name__}: {failure}"
        for name in list(timeline.recorder.sockets):
            timeline.close(name)
    report = {
        "schema_version": 1,
        "status": status,
        "error": error,
        "window_completed": window_completed,
        "window_elapsed_ns": window_elapsed_ns if window_completed else None,
        "window_frame_count": timeline.window_frame_count,
        "native_conformance": False,
        "preflight": "operator-provided separate18 control report, not runner-executed",
        "postflight": "operator-provided separate18 control report, not runner-executed",
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": digest(receipt_path.read_bytes()),
        "cases_sha256": digest(Path(cases.__file__).read_bytes()),
        "source_sha256": digest(Path(__file__).read_bytes()),
        "started_at_utc": timeline.recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - started,
        "operations": timeline.operations,
        "events": timeline.recorder.events,
        "frames": timeline.frames,
        "unparsed_hex": {name: data.hex() for name, data in timeline.buffers.items()},
        "terminals": timeline.terminals,
        "window_status": timeline.window_status,
        "streams": timeline.recorder.streams(),
    }
    if report["status"] == "completed":
        try:
            verify_report(plan, report)
        except (ValueError, KeyError, IndexError) as failure:
            report["status"] = "failed"
            report["error"] = f"Offline report check: {failure}"
    (output / "plan.json").write_bytes((plan_dir / "plan.json").read_bytes())
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.plan_dir, args.capture_receipt, args.binary, args.output)
    print(json.dumps({"status": result["status"], "error": result["error"]}))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
