#!/usr/bin/env python3
"""Run and verify one finite, isolated native legacy-board exchange."""

import argparse
import hashlib
import json
import os
import select
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import native_board_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_plan import packet
from protocol_capture import ORACLE_SHA256, Recorder, decode_frame
from verify_native_auth import ADMIN
from verify_native_shx import fields

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"


def need(ok: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(raw).hexdigest()


def strict(raw: bytes) -> dict:
    """Decode one physical frame, refusing short, fragmented or malformed ones."""
    need(len(raw) >= 22, "Short physical frame")
    size = int.from_bytes(raw[16:20], "big")
    need(len(raw) == 20 + size and size <= 65541, "Frame size/fragment differs")
    value = decode_frame(raw)
    need(
        value["flags"] == 0
        and value["total_size"] == size
        and value.get("declared_field_count") == len(value.get("fields", []))
        and not value.get("unconsumed_hex"),
        "Malformed or fragmented board frame",
    )
    fields(value)
    return value


def frame_fields(frame: dict) -> dict[int, bytes]:
    """Return a frame's fields by identifier, refusing duplicates."""
    result = fields(frame)
    need(len(result) == len(frame["fields"]), "Duplicate board TLV")
    return result


def one(frames: list[dict], name: str, kind: int, identifier: int, reply: int) -> dict:
    """Return the single frame that matches a connection, type, identifier and reply marker."""
    matches = [
        frame
        for frame in frames
        if frame["connection"] == name
        and frame["type"] == kind
        and frame["id"] == identifier
        and frame["is_reply"] == reply
    ]
    need(len(matches) == 1, f"Missing/duplicate {name}/{kind}/{identifier}")
    return matches[0]


class Wire:
    """Collect all bytes from four sockets; never assume a cross-socket order."""

    def __init__(self, recorder: Recorder, deadline: float) -> None:
        """Start the wire with its recorder and deadline."""
        self.recorder = recorder
        self.deadline = deadline
        self.buffers: dict[str, bytearray] = {}
        self.eof: set[str] = set()
        self.bytes_seen = 0
        self.frames_seen = 0
        self.action = 0

    def connect(self, name: str, endpoint: tuple[str, int]) -> None:
        """Connect a named non-blocking connection, record it and send the handshake."""
        need(len(self.recorder.sockets) < 4, "Too many board sockets")
        sock = socket.create_connection(
            endpoint, min(5, self.deadline - time.monotonic())
        )
        sock.setblocking(False)
        self.recorder.sockets[name] = sock
        self.buffers[name] = bytearray()
        self.recorder.event(self.action, name, "connect")
        self.recorder.events[-1].update(
            local_address=list(sock.getsockname()),
            peer_address=list(sock.getpeername()),
        )
        self.action += 1
        self.send(name, bytes.fromhex(cases.HELLO))
        hello = bytearray()
        while len(hello) < 8:
            self.poll(min(self.deadline, time.monotonic() + 5), handshake=(name, hello))
        need(hello.hex() == cases.HELLO_REPLY, "Board TRTP handshake differs")

    def send(self, name: str, data: bytes) -> None:
        """Send all the bytes on a connection within the deadline, recording each send."""
        sock = self.recorder.sockets[name]
        offset = 0
        while offset < len(data):
            remaining = self.deadline - time.monotonic()
            need(remaining > 0, "Board send deadline")
            _, ready, _ = select.select([], [sock], [], min(remaining, 3))
            need(bool(ready), "Board send stalled")
            count = sock.send(data[offset:])
            need(count > 0, "Board send EOF")
            self.recorder.event(
                self.action, name, "send", data[offset : offset + count]
            )
            offset += count
        self.action += 1

    def mark(self, name: str, label: str) -> None:
        """Record a labelled operation event for a connection."""
        self.recorder.event(-1, name, "operation")
        self.recorder.events[-1]["label"] = label

    def poll(
        self, until: float, handshake: tuple[str, bytearray] | None = None
    ) -> None:
        """Read what the open connections have ready until the time limit, parsing complete frames."""
        active = {
            name: sock
            for name, sock in self.recorder.sockets.items()
            if name not in self.eof
        }
        remaining = min(until, self.deadline) - time.monotonic()
        need(remaining > 0, "Board observation deadline")
        ready, _, _ = select.select(list(active.values()), [], [], remaining)
        if not ready:
            return
        for name, sock in active.items():
            if sock not in ready:
                continue
            need(self.bytes_seen < cases.MAX_CAPTURE_BYTES, "Board capture byte bound")
            raw = sock.recv(min(65536, cases.MAX_CAPTURE_BYTES - self.bytes_seen))
            if not raw:
                self.recorder.event(-1, name, "eof")
                self.eof.add(name)
                continue
            self.bytes_seen += len(raw)
            need(self.bytes_seen <= cases.MAX_CAPTURE_BYTES, "Board capture byte bound")
            self.recorder.event(-1, name, "receive", raw)
            if handshake and handshake[0] == name:
                missing = 8 - len(handshake[1])
                handshake[1].extend(raw[:missing])
                raw = raw[missing:]
                if not raw:
                    continue
            self.buffers[name].extend(raw)
            while len(self.buffers[name]) >= 20:
                size = int.from_bytes(self.buffers[name][16:20], "big")
                need(size <= 65541, "Board frame size bound")
                if len(self.buffers[name]) < 20 + size:
                    break
                frame_raw = bytes(self.buffers[name][: 20 + size])
                del self.buffers[name][: 20 + size]
                decoded = strict(frame_raw)
                self.frames_seen += 1
                need(self.frames_seen <= cases.MAX_FRAMES, "Board frame-count bound")
                self.recorder.frames.append(
                    {
                        "action": -1,
                        "connection": name,
                        "arrival_ns": time.monotonic_ns() - self.recorder.started,
                        "raw_hex": frame_raw.hex(),
                        **decoded,
                    }
                )

    def until(self, predicate, seconds: float = 5) -> None:
        """Poll until the predicate holds, failing when the time limit passes."""
        stop = min(self.deadline, time.monotonic() + seconds)
        while not predicate():
            need(time.monotonic() < stop, "Required board frame missing")
            self.poll(stop)

    def observe(self, seconds: float) -> None:
        """Poll for a fixed time, collecting whatever arrives."""
        stop = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < stop:
            self.poll(stop)

    def close(self, name: str) -> None:
        """Shut down a connection's writing side and wait briefly for the peer's EOF."""
        sock = self.recorder.sockets.get(name)
        if sock is None:
            return
        try:
            try:
                sock.shutdown(socket.SHUT_WR)
                self.recorder.event(-1, name, "shutdown_write")
            except OSError as exc:
                self.recorder.event(-1, name, "shutdown_error")
                self.recorder.events[-1]["error"] = str(exc)
            stop = min(self.deadline, time.monotonic() + 2)
            while name not in self.eof and time.monotonic() < stop:
                self.poll(stop)
            if name not in self.eof:
                self.recorder.event(-1, name, "no_eof_within_2s")
            need(not self.buffers[name], "Truncated board frame in tail")
        finally:
            try:
                sock.close()
            except OSError as exc:
                self.recorder.event(-1, name, "close_error")
                self.recorder.events[-1]["error"] = str(exc)
            else:
                self.recorder.event(-1, name, "close")
            del self.recorder.sockets[name]


def success(frame: dict, identifier: int) -> dict[int, bytes]:
    """Require a direct successful reply with the given identifier and return its fields."""
    need(
        frame["id"] == identifier
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Direct board success ACK differs",
    )
    return frame_fields(frame)


def login(wire: Wire, name: str, raw: bytes, access: bytes | None) -> None:
    """Connect, send a login and check the acknowledgement and the effective access."""
    wire.connect(name, ("127.0.0.1", cases.PORT))
    wire.send(name, raw)
    wire.until(
        lambda: any(
            f["connection"] == name and f["is_reply"] == 1 and f["id"] == 1
            for f in wire.recorder.frames
        )
    )
    reply = one(wire.recorder.frames, name, 0, 1, 1)
    need(
        frame_fields(reply) == {160: b"\0\xbe", 161: b"\0\0"} and reply["error"] == 0,
        "Login ACK differs",
    )
    wire.until(
        lambda: any(
            f["connection"] == name and f["type"] == 109 for f in wire.recorder.frames
        )
    )
    notices = [
        f for f in wire.recorder.frames if f["connection"] == name and f["type"] == 109
    ]
    need(
        len(notices) == 1
        and sha(frame_fields(notices[0]).get(101, b"")) == AGREEMENT_SHA,
        "Board actor agreement differs",
    )
    if access is not None:
        wire.until(
            lambda: any(
                f["connection"] == name and f["type"] == 354
                for f in wire.recorder.frames
            )
        )
        acl = one(
            wire.recorder.frames,
            name,
            354,
            next(
                f["id"]
                for f in wire.recorder.frames
                if f["connection"] == name and f["type"] == 354
            ),
            0,
        )
        need(frame_fields(acl) == {110: access}, "Board actor ACL differs")
    else:
        need(
            not any(
                f["connection"] == name and f["type"] == 354
                for f in wire.recorder.frames
            ),
            "Waiting actor became online",
        )


def read_board(
    wire: Wire,
    name: str,
    identifier: int,
    expected: bytes | None,
    *,
    denied: bool = False,
) -> bytes:
    """Request the board text and check the reply against the expected text, or a denial."""
    before = len(wire.recorder.frames)
    wire.send(name, bytes.fromhex(packet(101, identifier)))
    wire.until(
        lambda: any(
            f["connection"] == name and f["is_reply"] == 1 and f["id"] == identifier
            for f in wire.recorder.frames[before:]
        )
    )
    frame = one(wire.recorder.frames[before:], name, 0, identifier, 1)
    result = frame_fields(frame)
    if denied:
        need(frame["error"] == 1 and set(result) == {100}, "Denied board read differs")
        return b""
    need(
        frame["error"] == 0 and set(result) <= {101}, "Board read status/fields differ"
    )
    actual = result.get(101, b"")
    need((101 in result) == bool(actual), "Empty board field presence differs")
    if expected is not None:
        need(actual == expected[:65535], "Board aggregate prefix differs")
    return actual


def check_segment(
    frame: dict, data: bytes, expected_overhead: int | None
) -> tuple[bytes, int]:
    """Check one board update segment against the posted data and its expected overhead."""
    need(
        frame["type"] == 102 and frame["is_reply"] == 0 and frame["error"] == 0,
        "Board update header differs",
    )
    value = frame_fields(frame)
    need(set(value) == {101}, "Board update fields differ")
    segment = value[101]
    need(
        segment.startswith(b"From ") and segment.endswith(data + cases.SEPARATOR),
        "Board segment header/data/separator differs",
    )
    overhead = len(segment) - len(data)
    if expected_overhead is not None:
        need(overhead == expected_overhead, "Rendered header overhead changed")
    return segment, overhead


def post(
    wire: Wire, index: int, data: bytes, overhead: int | None
) -> tuple[bytes, int | None]:
    """Post a body from the sender connection and check the update that the readers receive."""
    before = len(wire.recorder.frames)
    wire.send("sender", bytes.fromhex(cases.post_packet(index, data)))
    identifier = 1000 + index
    if index == 12:
        wire.until(
            lambda: any(
                f["connection"] == "sender"
                and f["is_reply"] == 1
                and f["id"] == identifier
                for f in wire.recorder.frames[before:]
            )
        )
        reply = one(wire.recorder.frames[before:], "sender", 0, identifier, 1)
        need(
            reply["error"] == 1 and set(frame_fields(reply)) == {100},
            "Oversize post status differs",
        )
        wire.observe(0.4)
        need(
            not any(f["type"] == 102 for f in wire.recorder.frames[before:]),
            "Oversize post emitted update",
        )
        return b"", overhead
    wire.until(
        lambda: all(
            any(
                f["connection"] == name
                and f["type"] == kind
                and (kind != 0 or f["id"] == identifier)
                for f in wire.recorder.frames[before:]
            )
            for name, kind in (("sender", 0), ("sender", 102), ("eligible", 102))
        ),
        5,
    )
    reply = one(wire.recorder.frames[before:], "sender", 0, identifier, 1)
    need(success(reply, identifier) == {}, "Post ACK carries unexpected data")
    sender = [
        f
        for f in wire.recorder.frames[before:]
        if f["connection"] == "sender" and f["type"] == 102
    ]
    eligible = [
        f
        for f in wire.recorder.frames[before:]
        if f["connection"] == "eligible" and f["type"] == 102
    ]
    need(len(sender) == len(eligible) == 1, "Update recipient count differs")
    segment, overhead = check_segment(sender[0], data, overhead)
    need(frame_fields(eligible[0]) == {101: segment}, "Eligible update bytes differ")
    wire.observe(0.2)
    need(
        not any(
            f["connection"] == "denied" and f["type"] == 102
            for f in wire.recorder.frames[before:]
        ),
        "Denied observer received update",
    )
    return segment, overhead


def verify_report(plan: dict, report: dict) -> None:
    """Check the finished board report: plan hash, status, bounds, storage claim and recorded frames."""
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
    need(len(report["segments_hex"]) == 12, "Board segment count differs")
    data = [bytes.fromhex(x) for x in report["post_data_hex"]]
    need(
        len(data) == 13
        and all(len(x) <= 8192 for x in data[:12])
        and len(data[12]) == 8193,
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
        report["whole_board_sha256"] == sha(whole) and len(whole) > 65535,
        "Whole board reconstruction differs",
    )
    need(
        report["reads"]
        == {
            str(k): (b"".join(reversed(segments[: k + 1]))[:65535]).hex()
            for k in (0, 1, 2, 9, 10, 11, 12)
        }
        | {"initial": ""},
        "Board read/prefix mismatch",
    )
    need(len(whole) - len(segments[11]) == 65535, "Inclusive board boundary differs")
    expected_sends = {
        name: cases.HELLO + plan["login_hex"][name]
        for name in ("sender", "eligible", "denied", "waiting")
    }
    expected_sends["sender"] += packet(101, 100)
    expected_sends["denied"] += packet(101, 101)
    for index, value in enumerate(data):
        expected_sends["sender"] += cases.post_packet(index, value)
        if index < 3:
            expected_sends["eligible"] += packet(500, 200 + 2 * index)
            expected_sends["denied"] += packet(500, 201 + 2 * index)
        if index in {0, 1, 2, 9, 10, 11, 12}:
            expected_sends["sender"] += packet(101, 110 + index)
    actual_sends = {name: "" for name in expected_sends}
    for event in report["events"]:
        if event["event"] == "send":
            need(event["connection"] in expected_sends, "Unexpected board socket")
            actual_sends[event["connection"]] += event["hex"]
        need(
            0
            <= event["elapsed_ns"]
            <= int(report["elapsed_seconds"] * 1e9) + 1_000_000,
            "Event timing outside window",
        )
    need(actual_sends == expected_sends, "Board request bytes/order differ")
    expected_labels = [f"login-{name}" for name in expected_sends]
    expected_labels += ["initial101", "denied101"]
    for index in range(13):
        expected_labels.append(f"p{index:02d}")
        if index < 3:
            expected_labels += [
                f"p{index:02d}-barrier-{name}" for name in ("eligible", "denied")
            ]
        if index == 2:
            expected_labels.append("waiting-close")
        if index in {0, 1, 2, 9, 10, 11, 12}:
            expected_labels.append(f"p{index:02d}-read")
    need(
        [event["label"] for event in report["events"] if event["event"] == "operation"]
        == expected_labels,
        "Board operation labels/order differ",
    )
    for frame in report["frames"]:
        need(
            all(
                frame[key] == value
                for key, value in strict(bytes.fromhex(frame["raw_hex"])).items()
            ),
            "Captured frame raw mismatch",
        )
    need(report["streams"] == _streams(report["events"]), "Raw stream/event mismatch")
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
    for name, acl in (("sender", ADMIN), ("eligible", ADMIN), ("denied", bytes(8))):
        need(
            success(one(report["frames"], name, 0, 1, 1), 1)
            == {160: b"\0\xbe", 161: b"\0\0"},
            "Login ACK fields differ",
        )
        access_frames = [
            f for f in report["frames"] if f["connection"] == name and f["type"] == 354
        ]
        need(
            len(access_frames) == 1 and frame_fields(access_frames[0]) == {110: acl},
            "Actor access proof differs",
        )
    for name in expected_sends:
        notices = [
            f for f in report["frames"] if f["connection"] == name and f["type"] == 109
        ]
        need(
            len(notices) == 1
            and sha(frame_fields(notices[0]).get(101, b"")) == AGREEMENT_SHA,
            "Actor agreement proof differs",
        )
    need(
        success(one(report["frames"], "waiting", 0, 1, 1), 1)
        == {160: b"\0\xbe", 161: b"\0\0"},
        "Waiting login differs",
    )
    need(
        not any(
            f["connection"] == "waiting" and f["type"] == 354 for f in report["frames"]
        ),
        "Waiting actor online",
    )
    need(
        frame_fields(one(report["frames"], "denied", 0, 101, 1)).keys() == {100},
        "Denied read error absent",
    )
    need(
        one(report["frames"], "denied", 0, 101, 1)["error"] == 1,
        "Denied read status differs",
    )
    need(
        success(one(report["frames"], "sender", 0, 100, 1), 100) == {},
        "Initial board was not empty",
    )
    for index in range(3):
        for name, ident in (("eligible", 200 + 2 * index), ("denied", 201 + 2 * index)):
            need(
                success(one(report["frames"], name, 0, ident, 1), ident) == {},
                "Board barrier ACK differs",
            )
    sender_updates = [
        f for f in report["frames"] if f["connection"] == "sender" and f["type"] == 102
    ]
    eligible_updates = [
        f
        for f in report["frames"]
        if f["connection"] == "eligible" and f["type"] == 102
    ]
    need(
        len(sender_updates) == len(eligible_updates) == 12,
        "Board update cardinality differs",
    )
    waiting_updates = [
        f for f in report["frames"] if f["connection"] == "waiting" and f["type"] == 102
    ]
    waiting_indexes = [
        next(
            (
                i
                for i, segment in enumerate(segments[:3])
                if frame_fields(f) == {101: segment}
            ),
            -1,
        )
        for f in waiting_updates
    ]
    need(
        waiting_indexes == sorted(set(waiting_indexes))
        and all(i >= 0 for i in waiting_indexes),
        "Waiting update outside first three posts",
    )
    for index, segment in enumerate(segments):
        ident = 1000 + index
        need(
            success(one(report["frames"], "sender", 0, ident, 1), ident) == {},
            "Post ACK differs",
        )
        sender = sender_updates[index]
        eligible = eligible_updates[index]
        need(
            sender["is_reply"] == eligible["is_reply"] == 0
            and sender["error"] == eligible["error"] == 0,
            "Update header differs",
        )
        need(
            frame_fields(sender) == frame_fields(eligible) == {101: segment},
            "Update recipient segment differs",
        )
        need(
            not any(
                f["connection"] == "denied" and f["type"] == 102
                for f in report["frames"]
            ),
            "Denied update present",
        )
    rejected = one(report["frames"], "sender", 0, 1012, 1)
    need(
        rejected["error"] == 1 and set(frame_fields(rejected)) == {100},
        "Oversize post rejection differs",
    )
    for index in (0, 1, 2, 9, 10, 11, 12):
        reply = one(report["frames"], "sender", 0, 110 + index, 1)
        need(
            success(reply, 110 + index).get(101, b"").hex()
            == report["reads"][str(index)],
            "Read reply bytes differ",
        )


def _streams(events: list[dict]) -> dict:
    """Return the sent and received bytes of each connection as hexadecimal text."""
    result: dict[str, dict[str, str]] = {}
    for event in events:
        name = event["connection"]
        if name:
            entry = result.setdefault(name, {"sent_hex": "", "received_hex": ""})
            if event["event"] == "send":
                entry["sent_hex"] += event["hex"]
            elif event["event"] == "receive":
                entry["received_hex"] += event["hex"]
    return result


def prepared(directory: Path) -> dict:
    """Check the prepared plan against its source hashes and the frozen producer and return it."""
    raw = (directory / "plan.json").read_bytes()
    plan = json.loads(raw)
    need(
        json.loads((directory / "source-hashes.json").read_text())
        == {
            "plan.json": sha(raw),
            "native_board_cases.py": sha(Path(cases.__file__).read_bytes()),
            "native_board_control.py": sha(Path(__file__).read_bytes()),
        },
        "Prepared board source hash differs",
    )
    need(
        plan == cases.source_plan(plan["environment"], cases.PORT),
        "Prepared board plan differs",
    )
    return plan


def execute_case(
    wire: Wire,
    plan: dict,
    recorder: Recorder,
    segments: list[bytes],
    payloads: list[bytes],
    reads: dict[str, str],
    pace_seconds: float = 1.0,
) -> None:
    """Run the board operations in order: reads, posts and their checks, recording segments and payloads."""
    overhead: int | None = None
    operations = {item["label"]: item for item in plan["operations"]}
    need(
        operations["initial101"]["hex"] == packet(101, 100)
        and operations["denied101"]["hex"] == packet(101, 101),
        "Initial board request source differs",
    )
    for name, access in (
        ("sender", ADMIN),
        ("eligible", ADMIN),
        ("denied", bytes(8)),
        ("waiting", None),
    ):
        wire.mark(name, f"login-{name}")
        login(wire, name, bytes.fromhex(plan["login_hex"][name]), access)
    wire.mark("sender", "initial101")
    read_board(wire, "sender", 100, b"")
    reads["initial"] = ""
    wire.mark("denied", "denied101")
    read_board(wire, "denied", 101, None, denied=True)
    last_post = time.monotonic() - 1
    for index in range(13):
        source = operations[f"p{index:02d}"]
        need(
            time.monotonic() - recorder.started / 1e9 < cases.WINDOW_SECONDS,
            "Board case window expired",
        )
        while time.monotonic() - last_post < pace_seconds:
            time.sleep(min(0.1, pace_seconds - (time.monotonic() - last_post)))
        if index == 10:
            aggregate = b"".join(reversed(segments))
            if overhead is None:
                raise ValueError("Missing measured segment overhead")
            tuned = 65535 - len(aggregate) - overhead
            need(0 <= tuned <= 8192, "Dynamic P10 filler outside post bounds")
            prefix = b"P10:"
            data = prefix + b"K" * (tuned - len(prefix))
            need(len(data) == tuned, "Dynamic filler too short")
        else:
            data = cases.post_data(index)
        need(
            source["data_hex"] == (None if index == 10 else data.hex())
            and source["hex"]
            == (None if index == 10 else cases.post_packet(index, data))
            and source["request_id"] == 1000 + index,
            "Prepared board post bytes differ",
        )
        payloads.append(data)
        wire.mark("sender", f"p{index:02d}")
        segment, overhead = post(wire, index, data, overhead)
        last_post = time.monotonic()
        if index != 12:
            segments.append(segment)
        if index < 3:
            for barrier, (name, ident) in zip(
                source["barriers"],
                (
                    ("eligible", 200 + 2 * index),
                    ("denied", 201 + 2 * index),
                ),
                strict=True,
            ):
                need(
                    barrier == {"connection": name, "hex": packet(500, ident)},
                    "Barrier source differs",
                )
                wire.mark(name, f"p{index:02d}-barrier-{name}")
                before = len(recorder.frames)
                wire.send(name, bytes.fromhex(barrier["hex"]))
                wire.until(
                    lambda name=name, ident=ident, before=before: any(
                        f["connection"] == name
                        and f["is_reply"] == 1
                        and f["id"] == ident
                        for f in recorder.frames[before:]
                    )
                )
                success(one(recorder.frames[before:], name, 0, ident, 1), ident)
        if index == 2:
            wire.mark("waiting", "waiting-close")
            need(
                operations["waiting-close"]["op"] == "close_waiting",
                "Waiting close source differs",
            )
            wire.close("waiting")
        if index in {0, 1, 2, 9, 10, 11, 12}:
            need(
                source["read_after_hex"] == packet(101, 110 + index),
                "Board read source differs",
            )
            wire.mark("sender", f"p{index:02d}-read")
            board = b"".join(reversed(segments))
            actual = read_board(wire, "sender", 110 + index, board)
            reads[str(index)] = actual.hex()
    need(len(segments) == 12, "Board successful-post count differs")


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    """Check the plan, receipt, namespace and oracle, run the board case and write the report."""
    plan = prepared(plan_dir)
    receipt = json.loads(receipt_path.read_text())
    deadline_utc = utc(receipt["deadline_utc"])
    need(
        0 < (deadline_utc - datetime.now(timezone.utc)).total_seconds() <= 720,
        "Board epoch deadline differs",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat("/proc/self/ns/net").st_ino == receipt["emulator_netns_inode"],
        "Runner not in isolated guest namespace",
    )
    need(sha(binary.read_bytes()) == ORACLE_SHA256, "Native source fork differs")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    wire = Wire(
        recorder,
        min(
            time.monotonic() + cases.HARD_SECONDS,
            time.monotonic()
            + (deadline_utc - datetime.now(timezone.utc)).total_seconds(),
        ),
    )
    status = "failed"
    error = ""
    segments: list[bytes] = []
    payloads: list[bytes] = []
    reads: dict[str, str] = {}
    try:
        execute_case(wire, plan, recorder, segments, payloads, reads)
        runtime_gate(receipt, plan["environment"], deadline_utc)
        status = "completed"
    except (OSError, ValueError, TimeoutError, EOFError, KeyError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        for name in list(recorder.sockets):
            try:
                wire.close(name)
            except (OSError, ValueError, TimeoutError, EOFError) as exc:
                error += f"; {name} tail: {type(exc).__name__}: {exc}"
                status = "failed"
        report = {
            "status": status,
            "error": error,
            "plan_sha256": sha((plan_dir / "plan.json").read_bytes()),
            "started_utc": recorder.started_at_utc,
            "ended_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": (time.monotonic_ns() - recorder.started) / 1e9,
            "byte_count": recorder.byte_count,
            "frames": recorder.frames,
            "events": recorder.events,
            "streams": recorder.streams(),
            "post_data_hex": [x.hex() for x in payloads],
            "segments_hex": [x.hex() for x in segments],
            "reads": reads,
            "whole_board_sha256": sha(b"".join(reversed(segments))),
            "storage": "requires_stopped_guest_fork",
            "full_a7": "not_exercised",
            "capture_receipt_sha256": sha(receipt_path.read_bytes()),
            "native_source_sha256": ORACLE_SHA256,
            "runner_sha256": sha(Path(__file__).read_bytes()),
            "producer_sha256": sha(Path(cases.__file__).read_bytes()),
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if status == "completed":
        try:
            verify_report(plan, report)
        except ValueError as exc:
            report["status"] = "failed"
            report["error"] = f"Report verification: {exc}"
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    """Parse the command line, run the case and exit non-zero unless it completed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = run(args.plan, args.receipt, args.binary, args.output)
    print(json.dumps({"status": report["status"], "error": report["error"]}))
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
