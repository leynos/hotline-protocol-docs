#!/usr/bin/env python3
"""Run and verify one bounded native 304 reset/limit experiment."""

import argparse
import hashlib
import json
import os
import select
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import native_rate304_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_control_readiness import BASELINE_FIELDS, field_digest
from protocol_capture import ORACLE_SHA256, Recorder, decode_frame
from verify_native_auth import ADMIN, roster
from verify_native_shx import fields

MAX_WINDOW_SECONDS = 720
MAX_FRAME_BYTES = 65536
MAX_TAIL_SECONDS = 2


def need(ok: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(raw).hexdigest()


def prepared(directory: Path) -> dict:
    """Check the prepared plan against its hash and the frozen producer and return it."""
    raw = (directory / "plan.json").read_bytes()
    need(
        json.loads((directory / "source-hashes.json").read_text())
        == {"plan.json": digest(raw)},
        "Prepared plan hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from frozen producer",
    )
    return plan


def one(
    frames: list[dict], connection: str, kind: int, identifier: int, reply: int
) -> dict:
    """Return the single frame that matches a connection, type, identifier and reply marker."""
    matches = [
        frame
        for frame in frames
        if (frame["connection"], frame["type"], frame["id"], frame["is_reply"])
        == (connection, kind, identifier, reply)
    ]
    need(len(matches) == 1, f"Missing/duplicate {connection}/{kind}/{identifier}")
    return matches[0]


def exact_fields(frame: dict) -> dict[int, bytes]:
    """Return a frame's fields, refusing malformed, fragmented or repeated ones."""
    result = fields(frame)
    need(
        frame["total_size"] == frame["data_size"]
        and len(result) == len(frame["fields"])
        and frame.get("declared_field_count") == len(result)
        and frame.get("unconsumed_hex") == "",
        "Frame fields malformed/fragmented/duplicated",
    )
    return result


def successful(frame: dict) -> None:
    """Require a direct successful reply."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Reply is not direct success",
    )


def agreement(frames: list[dict], connection: str) -> None:
    """Require the one agreement notice of a connection to have the controlled bytes."""
    notices = [
        frame
        for frame in frames
        if frame["connection"] == connection and frame["type"] == 109
    ]
    need(len(notices) == 1 and notices[0]["is_reply"] == 0, "Agreement differs")
    content = exact_fields(notices[0])
    need(
        set(content) == {101} and digest(content[101]) == cases.AGREEMENT_SHA256,
        "Controlled agreement bytes differ",
    )


def login_identity(frames: list[dict], connection: str, access: bytes) -> None:
    """Require a connection's login reply and effective access to be as expected."""
    ack = one(frames, connection, 0, 1, 1)
    successful(ack)
    need(
        exact_fields(ack) == {160: b"\0\xbe", 161: b"\0\0"},
        "Login107 extras differ",
    )
    grants = [
        frame
        for frame in frames
        if frame["connection"] == connection and frame["type"] == 354
    ]
    need(
        len(grants) == 1 and exact_fields(grants[0]) == {110: access},
        "Login access/354 differs",
    )
    agreement(frames, connection)


def subject_identity(frames: list[dict], connection: str) -> int:
    """Check the subject's login and roster identity and return its user identifier."""
    login_identity(frames, connection, bytes.fromhex(cases.ZERO_ACCESS))
    reply = one(frames, connection, 0, 10, 1)
    successful(reply)
    rows = roster(reply)
    own = [r for r in rows if bytes.fromhex(r["name_hex"]) == cases.SUBJECT_NAME]
    need(len(own) == 1 and own[0]["icon"] == 1, "Subject roster identity differs")
    need(len(rows) == 2, "Subject roster lacks observer or has third party")
    need(
        any(bytes.fromhex(r["name_hex"]) == cases.OBS_NAME for r in rows),
        "Observer missing from subject roster",
    )
    return own[0]["uid"]


def update_frame(frame: dict, uid: int, icon: int) -> None:
    """Require a user update notice to carry the expected identifier, name and icon."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 0
        and frame["type"] == 301
        and frame["error"] == 0,
        "Expected update301 differs",
    )
    data = exact_fields(frame)
    need(
        set(data) == {102, 103, 104, 112}
        and data[103] == uid.to_bytes(2, "big")
        and data[102] == cases.SUBJECT_NAME
        and data[104] == icon.to_bytes(2, "big"),
        "Update301 UID/name/icon differs",
    )


def classify(plan: dict, report: dict) -> None:
    """Check measured semantic chain; never invent native clock or EOF proof."""
    frames = report["frames"]
    login_identity(frames, "observer", ADMIN)
    initial_rows = roster(one(frames, "observer", 0, 10, 1))
    need(
        len(initial_rows) == 1
        and bytes.fromhex(initial_rows[0]["name_hex"]) == cases.OBS_NAME,
        "Initial observer roster differs",
    )
    paced_uid = subject_identity(frames, "paced")
    burst_uid = subject_identity(frames, "burst")
    burst_start = next(
        action["elapsed_ns"]
        for action in report["actions"]
        if action["label"] == "burst-login"
    )
    need(
        report["identities"] == {"paced_uid": paced_uid, "burst_uid": burst_uid},
        "Reported dynamic UIDs differ",
    )
    for name, uid, prefix, bars in (
        ("paced", paced_uid, 1000, 2000),
        ("burst", burst_uid, 3000, 4000),
    ):
        expected_subject = list(range(2, 29)) if name == "paced" else list(range(2, 28))
        for receiver, expected_icons in (
            ("observer", [1, *expected_subject]),
            (name, expected_subject),
        ):
            updates = [
                f
                for f in frames
                if f["connection"] == receiver
                and f["type"] == 301
                and not f["is_reply"]
                and exact_fields(f).get(103) == uid.to_bytes(2, "big")
                and (
                    receiver != "observer"
                    or (f["arrival_elapsed_ns"] < burst_start) == (name == "paced")
                )
            ]
            need(
                len(updates) == len(expected_icons),
                f"{name}/{receiver} 301 cardinality differs",
            )
            for frame, icon in zip(updates, expected_icons, strict=True):
                update_frame(frame, uid, icon)
        for offset in range(26 + (name == "paced")):
            successful(one(frames, name, 0, bars + offset, 1))
        need(
            not any(
                f["connection"] == name
                and f["is_reply"]
                and f["id"] in range(prefix, prefix + 27)
                for f in frames
            ),
            "304 unexpectedly has a direct ACK",
        )
    need(
        not any(
            f["connection"] in {"observer", "burst"}
            and f["type"] == 301
            and f["arrival_elapsed_ns"] >= burst_start
            and exact_fields(f).get(103) == burst_uid.to_bytes(2, "big")
            and exact_fields(f).get(104) == (28).to_bytes(2, "big")
            for f in frames
        ),
        "Terminal 27th 304 unexpectedly broadcast 301",
    )
    notifications = [f for f in frames if f["type"] in {301, 302, 104}]
    expected_301 = {"observer": 55, "paced": 27, "burst": 26}
    for receiver, count in expected_301.items():
        need(
            sum(f["type"] == 301 and f["connection"] == receiver for f in notifications)
            == count,
            f"Unexpected/foreign {receiver} 301",
        )
    need(
        not any(
            f["type"] == 301 and f["connection"] not in expected_301
            for f in notifications
        ),
        "Foreign 301 recipient",
    )
    probe_start = next(
        a["elapsed_ns"] for a in report["actions"] if a["label"] == "probe-login"
    )
    terminal_start = next(
        a["elapsed_ns"] for a in report["actions"] if a["label"] == "burst-304-terminal"
    )
    departures = [f for f in notifications if f["type"] == 302]
    need(
        all(
            f["connection"] == "observer"
            and f["flags"] == 0
            and f["is_reply"] == 0
            and f["error"] == 0
            and set(exact_fields(f)) == {103}
            and len(exact_fields(f)[103]) == 2
            for f in departures
        ),
        "Unexpected departure302 grammar/recipient",
    )
    paced_leave = [f for f in departures if f["arrival_elapsed_ns"] < burst_start]
    burst_leave = [
        f for f in departures if burst_start <= f["arrival_elapsed_ns"] < probe_start
    ]
    probe_leave = [f for f in departures if f["arrival_elapsed_ns"] >= probe_start]
    need(
        len(paced_leave) == len(burst_leave) == 1
        and exact_fields(paced_leave[0])[103] == paced_uid.to_bytes(2, "big")
        and exact_fields(burst_leave[0])[103] == burst_uid.to_bytes(2, "big")
        and len(probe_leave) <= 1
        and all(
            exact_fields(f)[103]
            not in {
                initial_rows[0]["uid"].to_bytes(2, "big"),
                paced_uid.to_bytes(2, "big"),
                burst_uid.to_bytes(2, "big"),
            }
            for f in probe_leave
        ),
        "Known departure or optional unassigned probe302 differs",
    )
    notices = [f for f in notifications if f["type"] == 104]
    need(
        len(notices) <= 1
        and all(
            f["connection"] == "burst"
            and f["flags"] == 0
            and f["is_reply"] == 0
            and f["error"] == 0
            and f["arrival_elapsed_ns"] >= terminal_start
            and bool(exact_fields(f))
            for f in notices
        ),
        "Unexpected 104 outside bounded terminal-burst phase",
    )
    probe = one(frames, "probe", 0, 1, 1)
    need(
        probe["flags"] == 0
        and probe["error"] == 1
        and exact_fields(probe) == {100: cases.TEMPORARY_BAN},
        "Fresh Login107 does not match published temporary-ban error",
    )
    need(
        not any(f["connection"] == "probe" and f["type"] == 354 for f in frames),
        "Ban probe unexpectedly gained access",
    )
    controls = plan["request_ids"]["observer_controls"]
    for kind_text, identifier in controls.items():
        kind = int(kind_text)
        reply = one(frames, "observer", 0, identifier, 1)
        successful(reply)
        if kind in BASELINE_FIELDS:
            need(
                field_digest(reply) == BASELINE_FIELDS[kind],
                "Observer baseline hash differs",
            )
        if kind == 300:
            rows = roster(reply)
            need(
                len(rows) == 1 and bytes.fromhex(rows[0]["name_hex"]) == cases.OBS_NAME,
                "Observer post-ban roster differs",
            )
    need(
        report["timing"]["paced_trial_seconds"] <= 20
        and report["timing"]["burst_trial_seconds"] <= 20
        and report["timing"]["subject_quiet_seconds"] >= 70,
        "Trial/reset host timing differs",
    )
    need(
        report["timing"]["native_60_seconds_proven"] is False,
        "Native clock cannot be inferred from host timing",
    )
    need(
        report["terminals"].get("burst") in {"eof", "rst"},
        "Burst limiter close not observed",
    )
    need(
        all(name in report["terminals"] for name in plan["schedule"]["flows"]),
        "Missing finite terminal classification",
    )


def expected_actions(plan: dict, idle_count: int) -> list[tuple[str, str, str]]:
    """Return the actions that the plan should have run, as label, connection and bytes."""
    need(13 <= idle_count <= 15, "Observer idle cadence differs")
    actions = [
        ("observer-login", "observer", plan["logins"]["observer"]),
        ("observer-roster-initial", "observer", cases.observer_control(300, 10)),
        ("paced-login", "paced", plan["logins"]["paced"]),
        ("paced-roster", "paced", cases.observer_control(300, 10)),
    ]
    for index in range(26):
        actions.extend(
            [
                (
                    f"paced-304-{index:02d}",
                    "paced",
                    cases.update(1000 + index, index + 2),
                ),
                (f"paced-500-{index:02d}", "paced", cases.barrier(2000 + index)),
            ]
        )
    for index in range(idle_count):
        actions.append(
            (f"observer-idle500-{index:02d}", "observer", cases.barrier(5000 + index))
        )
    actions.extend(
        [
            ("paced-304-after-quiet", "paced", cases.update(1026, 28)),
            ("paced-500-after-quiet", "paced", cases.barrier(2026)),
            ("burst-login", "burst", plan["logins"]["burst"]),
            ("burst-roster", "burst", cases.observer_control(300, 10)),
        ]
    )
    for index in range(26):
        actions.extend(
            [
                (
                    f"burst-304-{index:02d}",
                    "burst",
                    cases.update(3000 + index, index + 2),
                ),
                (f"burst-500-{index:02d}", "burst", cases.barrier(4000 + index)),
            ]
        )
    actions.extend(
        [
            ("burst-304-terminal", "burst", cases.update(3026, 28)),
            ("probe-login", "probe", plan["logins"]["probe"]),
        ]
    )
    for kind, identifier in plan["request_ids"]["observer_controls"].items():
        actions.append(
            (
                f"observer-{kind}",
                "observer",
                cases.observer_control(int(kind), identifier),
            )
        )
    return actions


class Wire:
    """One bounded multi-socket collector retaining every observed byte."""

    def __init__(self, plan: dict, deadline: float, guard=None) -> None:
        """Start the wire with its plan, deadline and optional guard."""
        self.plan, self.deadline = plan, deadline
        self.guard = guard
        self.recorder = Recorder({"endpoints": {"control": plan["endpoint"]}})
        self.buffers: dict[str, bytearray] = {}
        self.frames: list[dict] = []
        self.terminals: dict[str, str] = {}
        self.actions: list[dict] = []
        self.next_action = 0
        self.tail_bytes: dict[str, int] = {}
        self.tail_mode = False

    def execute(self, step: dict) -> None:
        """Run one plan step within the case deadline and byte cap."""
        remaining = self.deadline - time.monotonic()
        need(remaining > 0, "Case deadline reached")
        self.recorder.execute(
            self.next_action,
            {**step, "timeout": min(step.get("timeout", 3), remaining)},
        )
        self.next_action += 1
        need(
            self.recorder.byte_count <= self.plan["schedule"]["max_bytes"],
            "Case byte cap reached",
        )

    def connect_login(self, name: str) -> None:
        """Connect a named connection, handshake and send its login."""
        if self.guard is not None:
            self.guard()
        need(
            len(self.recorder.sockets) < self.plan["schedule"]["max_simultaneous"],
            "Simultaneous socket cap reached",
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
        self.send(name, self.plan["logins"][name], f"{name}-login")
        self.wait_for(
            lambda: all(
                [
                    bool(self.match(name, 0, 1, 1)),
                    bool(self.match(name, 354, None, 0)),
                    bool(self.match(name, 109, None, 0)),
                ]
            ),
            5,
            f"{name} early107/354/109",
        )
        login_identity(self.frames, name, ADMIN if name == "observer" else bytes(8))

    def connect_login_probe(self, name: str) -> None:
        """Connect a named connection and handshake, then send its login without waiting for the reply."""
        if self.guard is not None:
            self.guard()
        need(
            len(self.recorder.sockets) < self.plan["schedule"]["max_simultaneous"],
            "Simultaneous socket cap reached",
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
        self.send(name, self.plan["logins"][name], f"{name}-login")

    def send(self, name: str, raw: str, label: str) -> None:
        """Send bytes on an open connection and record the labelled action."""
        need(name in self.recorder.sockets, "Send on closed socket")
        start = len(self.recorder.events)
        self.execute({"op": "send", "connection": name, "hex": raw})
        self.actions.append(
            {
                "label": label,
                "connection": name,
                "hex": raw,
                "elapsed_ns": time.monotonic_ns() - self.recorder.started,
                "event_range": [start, len(self.recorder.events)],
            }
        )

    def match(
        self, name: str, kind: int, identifier: int | None, reply: int
    ) -> list[dict]:
        """Return the frames that match a connection, type, identifier and reply marker."""
        return [
            f
            for f in self.frames
            if f["connection"] == name
            and f["type"] == kind
            and f["is_reply"] == reply
            and (identifier is None or f["id"] == identifier)
        ]

    def poll(self, seconds: float) -> None:
        """Read from the open connections for a while and parse what arrives."""
        until = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < until:
            active = {
                sock: name
                for name, sock in self.recorder.sockets.items()
                if name not in self.terminals
            }
            if not active:
                return
            ready, _, _ = select.select(
                list(active), [], [], min(0.05, max(0, until - time.monotonic()))
            )
            if not ready:
                continue
            for sock in ready:
                name = active[sock]
                allowance = (
                    self.plan["schedule"]["max_bytes"] - self.recorder.byte_count
                )
                if self.tail_mode:
                    allowance = min(
                        allowance,
                        self.plan["schedule"]["max_tail_bytes_per_flow"]
                        - self.tail_bytes.get(name, 0),
                    )
                need(allowance > 0, "Case/tail byte cap reached")
                try:
                    raw = sock.recv(min(65536, allowance))
                except ConnectionResetError:
                    self.recorder.event(-1, name, "rst")
                    self.terminals[name] = "rst"
                    continue
                if not raw:
                    self.recorder.event(-1, name, "eof")
                    self.terminals[name] = "eof"
                    continue
                self.recorder.event(-1, name, "receive", raw)
                if self.tail_mode:
                    self.tail_bytes[name] = self.tail_bytes.get(name, 0) + len(raw)
                self.buffers[name].extend(raw)
                self.parse(name)

    def parse(self, name: str) -> None:
        """Parse the complete frames in a connection's buffer."""
        buffer = self.buffers[name]
        while len(buffer) >= 20:
            size = 20 + int.from_bytes(buffer[16:20], "big")
            need(20 <= size <= MAX_FRAME_BYTES, "Frame exceeds hard bound")
            if len(buffer) < size:
                return
            raw = bytes(buffer[:size])
            del buffer[:size]
            value = decode_frame(raw)
            need(value["total_size"] == value["data_size"], "Fragmented logical frame")
            self.frames.append(
                {
                    "connection": name,
                    "raw_hex": raw.hex(),
                    "arrival_elapsed_ns": time.monotonic_ns() - self.recorder.started,
                    **value,
                }
            )
            need(
                len(self.frames) <= self.plan["schedule"]["max_frames"],
                "Case frame cap reached",
            )

    def wait_for(self, predicate, seconds: float, label: str) -> None:
        """Poll until the predicate holds, failing at the deadline."""
        until = min(time.monotonic() + seconds, self.deadline)
        while not predicate():
            need(time.monotonic() < until, f"Missing {label}")
            self.poll(min(0.05, until - time.monotonic()))

    def shutdown_and_close(self, name: str) -> None:
        """Shut down a connection's socket and close it."""
        sock = self.recorder.sockets.get(name)
        if sock is None:
            return
        if name not in self.terminals:
            try:
                sock.shutdown(socket.SHUT_WR)
                self.recorder.event(self.next_action, name, "shutdown_write")
            except OSError:
                self.recorder.event(self.next_action, name, "shutdown_write_failed")
        self.tail_mode = True
        self.poll(min(MAX_TAIL_SECONDS, max(0, self.deadline - time.monotonic())))
        self.recorder.sockets.pop(name).close()
        self.recorder.event(self.next_action, name, "close")
        self.next_action += 1
        self.terminals.setdefault(name, "bounded_no_eof")

    def close_all(self) -> None:
        """Close each open connection in turn; when a close fails, close that socket anyway and re-raise, leaving the later ones to the caller."""
        self.tail_mode = True
        for name in list(self.recorder.sockets):
            try:
                self.shutdown_and_close(name)
            except (OSError, ValueError, TimeoutError):
                # Caller records failure; preserve and release every owned descriptor.
                sock = self.recorder.sockets.pop(name, None)
                if sock is not None:
                    sock.close()
                    self.recorder.event(self.next_action, name, "close_after_failure")
                raise


def update_and_barrier(wire: Wire, name: str, index: int, uid: int) -> None:
    """Send a settings update and a barrier request and wait for every receiver to see the update."""
    paced = name == "paced"
    request_id = (1000 if paced else 3000) + index
    barrier_id = (2000 if paced else 4000) + index
    icon = index + 2
    wire.send(name, cases.update(request_id, icon), f"{name}-304-{index:02d}")
    wire.send(name, cases.barrier(barrier_id), f"{name}-500-{index:02d}")
    wire.wait_for(
        lambda: (
            all(
                any(
                    f["connection"] == receiver
                    and f["type"] == 301
                    and f["is_reply"] == 0
                    and exact_fields(f).get(103) == uid.to_bytes(2, "big")
                    and exact_fields(f).get(104) == icon.to_bytes(2, "big")
                    for f in wire.frames
                )
                for receiver in ("observer", name)
            )
            and bool(wire.match(name, 0, barrier_id, 1))
        ),
        0.55,
        f"{name} subject/observer301 and500 ACK icon{icon}",
    )
    for receiver in ("observer", name):
        matches = [
            f
            for f in wire.frames
            if f["connection"] == receiver
            and f["type"] == 301
            and exact_fields(f).get(103) == uid.to_bytes(2, "big")
            and exact_fields(f).get(104) == icon.to_bytes(2, "big")
        ]
        need(len(matches) == 1, f"{receiver} duplicate 301 icon{icon}")
        update_frame(matches[0], uid, icon)
    successful(one(wire.frames, name, 0, barrier_id, 1))


def roster_uid(wire: Wire, name: str) -> int:
    """Fetch the roster on a connection and return the subject's user identifier."""
    wire.send(name, cases.observer_control(300, 10), f"{name}-roster")
    wire.wait_for(lambda: bool(wire.match(name, 0, 10, 1)), 2, f"{name} roster")
    return subject_identity(wire.frames, name)


def observer_baseline(wire: Wire, plan: dict) -> None:
    """Send the observer's control requests and wait for each reply."""
    for kind_text, identifier in plan["request_ids"]["observer_controls"].items():
        kind = int(kind_text)
        wire.send(
            "observer", cases.observer_control(kind, identifier), f"observer-{kind}"
        )
        wire.wait_for(
            lambda identifier=identifier: bool(
                wire.match("observer", 0, identifier, 1)
            ),
            3,
            f"observer control {kind}",
        )
        successful(one(wire.frames, "observer", 0, identifier, 1))


def perform(wire: Wire, plan: dict) -> dict:
    """Run the first rate-limit pair: the observer and the paced connection, with their updates and timing."""
    wire.connect_login("observer")
    wire.send("observer", cases.observer_control(300, 10), "observer-roster-initial")
    wire.wait_for(
        lambda: bool(wire.match("observer", 0, 10, 1)), 2, "initial observer roster"
    )
    need(
        len(roster(one(wire.frames, "observer", 0, 10, 1))) == 1,
        "Observer roster not solo",
    )
    wire.connect_login("paced")
    paced_uid = roster_uid(wire, "paced")
    first_paced = time.monotonic()
    for index in range(26):
        update_and_barrier(wire, "paced", index, paced_uid)
    paced_trial = time.monotonic() - first_paced
    need(paced_trial <= 20, "Paced26 exceeded host20s bracket")
    last_subject_request = time.monotonic()
    next_observer = last_subject_request + 5
    while time.monotonic() - last_subject_request < 70:
        need(time.monotonic() < wire.deadline - 30, "Quiet interval cannot finish")
        wire.poll(min(0.05, max(0, next_observer - time.monotonic())))
        if time.monotonic() >= next_observer:
            number = sum(
                action["label"].startswith("observer-idle500-")
                for action in wire.actions
            )
            identifier = plan["request_ids"]["observer_500_start"] + number
            wire.send(
                "observer", cases.barrier(identifier), f"observer-idle500-{number:02d}"
            )
            wire.wait_for(
                lambda identifier=identifier: bool(
                    wire.match("observer", 0, identifier, 1)
                ),
                2,
                "observer idle500 ACK",
            )
            successful(one(wire.frames, "observer", 0, identifier, 1))
            next_observer += 5
    quiet = time.monotonic() - last_subject_request
    wire.send("paced", cases.update(1026, 28), "paced-304-after-quiet")
    wire.send("paced", cases.barrier(2026), "paced-500-after-quiet")
    wire.wait_for(
        lambda: (
            all(
                any(
                    f["connection"] == receiver
                    and f["type"] == 301
                    and exact_fields(f).get(103) == paced_uid.to_bytes(2, "big")
                    and exact_fields(f).get(104) == b"\0\x1c"
                    for f in wire.frames
                )
                for receiver in ("observer", "paced")
            )
            and bool(wire.match("paced", 0, 2026, 1))
        ),
        2,
        "paced 27th subject/observer301 and500 ACK",
    )
    for receiver in ("observer", "paced"):
        updates = [
            f
            for f in wire.frames
            if f["connection"] == receiver
            and f["type"] == 301
            and exact_fields(f).get(103) == paced_uid.to_bytes(2, "big")
            and exact_fields(f).get(104) == b"\0\x1c"
        ]
        need(len(updates) == 1, f"{receiver} duplicate post-quiet301")
        update_frame(updates[0], paced_uid, 28)
    successful(one(wire.frames, "paced", 0, 2026, 1))
    wire.shutdown_and_close("paced")
    wire.wait_for(
        lambda: any(
            f["connection"] == "observer"
            and f["type"] == 302
            and exact_fields(f).get(103) == paced_uid.to_bytes(2, "big")
            for f in wire.frames
        ),
        2,
        "paced departure302",
    )
    wire.connect_login("burst")
    burst_uid = roster_uid(wire, "burst")
    first_burst = time.monotonic()
    for index in range(26):
        update_and_barrier(wire, "burst", index, burst_uid)
    burst_trial = time.monotonic() - first_burst
    need(burst_trial <= 20, "Burst26 exceeded host20s bracket")
    wire.send("burst", cases.update(3026, 28), "burst-304-terminal")
    wire.wait_for(
        lambda: wire.terminals.get("burst") in {"eof", "rst"},
        3,
        "terminal limiter close",
    )
    wire.shutdown_and_close("burst")
    wire.wait_for(
        lambda: any(
            f["connection"] == "observer"
            and f["type"] == 302
            and exact_fields(f).get(103) == burst_uid.to_bytes(2, "big")
            for f in wire.frames
        ),
        3,
        "burst departure302",
    )
    wire.connect_login_probe("probe")
    wire.wait_for(
        lambda: bool(wire.match("probe", 0, 1, 1)),
        3,
        "single ban login reply",
    )
    probe = one(wire.frames, "probe", 0, 1, 1)
    need(
        probe["error"] == 1 and exact_fields(probe) == {100: cases.TEMPORARY_BAN},
        "Fresh Login107 not refused by known temporary-ban path",
    )
    observer_baseline(wire, plan)
    return {
        "paced_uid": paced_uid,
        "burst_uid": burst_uid,
        "timing": {
            "paced_trial_seconds": paced_trial,
            "burst_trial_seconds": burst_trial,
            "subject_quiet_seconds": quiet,
            "native_60_seconds_proven": False,
        },
    }


def verify_report(plan: dict, report: dict) -> None:
    """Check the finished report's status, hashes and event order against the plan."""
    need(report["status"] == "completed", "Rate304 run incomplete")
    need(report["native_clock_calibrated"] is False, "Native clock not calibrated")
    need(
        report["plan_sha256"] == digest((json.dumps(plan, indent=2) + "\n").encode())
        and report["cases_sha256"] == digest(Path(cases.__file__).read_bytes())
        and report["source_sha256"] == digest(Path(__file__).read_bytes())
        and report["oracle_sha256"] == ORACLE_SHA256,
        "As-run plan/source/oracle identity differs",
    )
    rebuilt: dict[str, dict[str, str]] = {}
    last_ns = -1
    for event in report["events"]:
        need(event["elapsed_ns"] >= last_ns, "Nonmonotonic event timestamp")
        last_ns = event["elapsed_ns"]
        stream = rebuilt.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        if event["event"] == "send":
            stream["sent_hex"] += event["hex"]
        elif event["event"] == "receive":
            stream["received_hex"] += event["hex"]
    need(rebuilt == report["streams"], "Stream bytes differ from events")
    expected = {name: cases.HELLO for name in plan["schedule"]["flows"]}
    actions = report["actions"]
    idle_count = sum(a["label"].startswith("observer-idle500-") for a in actions)
    need(
        [(a["label"], a["connection"], a["hex"]) for a in actions]
        == expected_actions(plan, idle_count),
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
    action_times = {action["label"]: action["elapsed_ns"] for action in actions}
    for label, first, last in (
        ("paced", "paced-304-00", "paced-500-25"),
        ("burst", "burst-304-00", "burst-500-25"),
    ):
        elapsed = (action_times[last] - action_times[first]) / 1e9
        need(
            0 <= elapsed <= report["timing"][f"{label}_trial_seconds"] <= 20,
            f"{label} request timing receipt differs",
        )
    quiet_bound = (
        action_times["paced-304-after-quiet"] - action_times["paced-500-25"]
    ) / 1e9
    need(
        quiet_bound >= report["timing"]["subject_quiet_seconds"] >= 70,
        "Subject quiet timing receipt differs",
    )
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
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(k) == v for k, v in decode_frame(raw).items()),
            "Decoded frame differs from raw",
        )
    for name in plan["schedule"]["flows"]:
        terminals = [
            e["event"]
            for e in report["events"]
            if e["connection"] == name and e["event"] in {"eof", "rst"}
        ]
        need(len(terminals) <= 1, "Contradictory socket terminals")
        observed = terminals[0] if terminals else "bounded_no_eof"
        need(
            report["terminals"].get(name) == observed,
            "Terminal label differs from bytes/events",
        )
    need(
        len(report["frames"]) <= plan["schedule"]["max_frames"]
        and sum(len(bytes.fromhex(e["hex"])) for e in report["events"])
        <= plan["schedule"]["max_bytes"],
        "Frame/byte bound exceeded",
    )
    classify(plan, report)


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    """Check the plan, receipt and window, run the first pair and write the report."""
    plan = prepared(plan_dir)
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    deadline_utc = utc(receipt["deadline_utc"])
    remaining = (deadline_utc - datetime.now(timezone.utc)).total_seconds()
    need(
        390 <= remaining <= MAX_WINDOW_SECONDS
        and (deadline_utc - utc(receipt["epoch_started_utc"])).total_seconds()
        <= MAX_WINDOW_SECONDS,
        "Capture epoch lacks390s or exceeds12min",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat("/proc/self/ns/net").st_ino
        == plan["environment"]["emulator_netns_inode"],
        "Runner outside owned lab namespace",
    )
    need(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    output.mkdir(parents=True, exist_ok=False)
    wire = Wire(
        plan,
        min(time.monotonic() + 210, time.monotonic() + remaining),
        lambda: runtime_gate(receipt, plan["environment"], deadline_utc),
    )
    started = time.monotonic()
    status, error, result = "completed", "", {}
    try:
        result = perform(wire, plan)
        runtime_gate(receipt, plan["environment"], deadline_utc)
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
            wire.close_all()
        except (OSError, ValueError, TimeoutError) as failure:
            status = "failed"
            error += f"; teardown {type(failure).__name__}: {failure}"
        for name, sock in list(wire.recorder.sockets.items()):
            sock.close()
            wire.recorder.sockets.pop(name)
            wire.recorder.event(-1, name, "close_after_failure")
    report = {
        "schema_version": 1,
        "status": status,
        "error": error,
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "cases_sha256": digest(Path(cases.__file__).read_bytes()),
        "source_sha256": digest(Path(__file__).read_bytes()),
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": digest(receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - started,
        "native_clock_calibrated": False,
        "identities": {k: result.get(k) for k in ("paced_uid", "burst_uid")},
        "timing": result.get("timing", {}),
        "actions": wire.actions,
        "events": wire.recorder.events,
        "frames": wire.frames,
        "streams": wire.recorder.streams(),
        "unparsed_hex": {name: raw.hex() for name, raw in wire.buffers.items()},
        "terminals": wire.terminals,
        "preflight": "operator-provided separate18 report, not runner-executed",
        "postflight": "retained observer controls only; no fresh login/full A7",
    }
    if status == "completed":
        try:
            verify_report(plan, report)
        except (ValueError, KeyError, IndexError) as failure:
            report["status"] = "failed"
            report["error"] = f"Offline report check: {failure}"
    (output / "plan.json").write_bytes((plan_dir / "plan.json").read_bytes())
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    """Parse the command line, run the capture and exit non-zero unless it completed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.plan_dir, args.capture_receipt, args.binary, args.output)
    print(json.dumps({"status": report["status"], "error": report["error"]}))
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
