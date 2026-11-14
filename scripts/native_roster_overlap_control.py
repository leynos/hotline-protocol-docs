#!/usr/bin/env python3
"""Run one bounded control-only 300/304 overlap; preserve both socket orders."""

import argparse
import hashlib
import json
import select
import time
from datetime import datetime, timezone
from pathlib import Path

import native_roster_overlap_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from protocol_capture import ORACLE_SHA256, Recorder, decode_frame, validate_plan
from verify_native_auth import ADMIN, roster
from verify_native_shx import fields

MAX_SECONDS = 600
MAX_FRAMES = 32
MAX_BYTES = 65536


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def frame_key(frame: dict) -> tuple[str, int, int, int]:
    identifier = (
        0 if frame["type"] in (301, 302) and not frame["is_reply"] else frame["id"]
    )
    return frame["connection"], frame["is_reply"], frame["type"], identifier


def expected_frame(
    frame: dict, connection: str, kind: int, identifier: int, is_reply: int
) -> bool:
    return frame_key(frame) == (connection, is_reply, kind, identifier)


def one(
    frames: list[dict], connection: str, kind: int, identifier: int, is_reply: int
) -> dict:
    matches = [
        f for f in frames if expected_frame(f, connection, kind, identifier, is_reply)
    ]
    need(len(matches) == 1, f"Missing or duplicate {connection}/{kind}/{identifier}")
    return matches[0]


def exact_rows(
    frame: dict,
    a_uid: int | None = None,
    b_uid: int | None = None,
    *,
    b_new: bool = False,
) -> tuple[int, int]:
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Roster reply header differs",
    )
    rows = roster(frame)
    need(len(rows) == 2, "Roster has missing or unexplained third member")
    names = {bytes.fromhex(row["name_hex"]): row for row in rows}
    need(
        set(names) == {cases.OLD_A, cases.NEW_B if b_new else cases.OLD_B},
        "Roster identity is mixed or unexpected",
    )
    a, b = names[cases.OLD_A], names[cases.NEW_B if b_new else cases.OLD_B]
    need(
        a["icon"] == 1
        and b["icon"] == (3 if b_new else 2)
        and a["uid"] != b["uid"]
        and a["uid"] > 0
        and b["uid"] > 0,
        "Roster icon/UID pair is torn",
    )
    need(
        (a_uid is None or a["uid"] == a_uid) and (b_uid is None or b["uid"] == b_uid),
        "Roster UID changed",
    )
    return a["uid"], b["uid"]


def check_setup(recorder: Recorder) -> tuple[int, int]:
    a = [f for f in recorder.frames if f["connection"] == "a"]
    b = [f for f in recorder.frames if f["connection"] == "b"]
    need(len(a) == 5 and len(b) == 4, "Initial frame count differs")
    need(
        [(f["type"], f["is_reply"], f["id"]) for f in a]
        == [
            (0, 1, 1),
            (354, 0, a[1]["id"]),
            (109, 0, a[2]["id"]),
            (301, 0, a[3]["id"]),
            (0, 1, 10),
        ],
        "A initial frame order differs",
    )
    need(
        [(f["type"], f["is_reply"], f["id"]) for f in b]
        == [(0, 1, 1), (354, 0, b[1]["id"]), (109, 0, b[2]["id"]), (0, 1, 10)],
        "B initial frame order differs",
    )
    for label, frames in (("a", a), ("b", b)):
        need(
            frames[0]["error"] == 0
            and len(frames[1]["fields"]) == 1
            and fields(frames[1]) == {110: ADMIN},
            f"{label} login/access differs",
        )
    a_uid, b_uid = exact_rows(a[4])
    exact_rows(b[3], a_uid, b_uid)
    need(
        recorder.variables.get("b_uid") == b_uid.to_bytes(2, "big"),
        "B dynamic 301 UID differs from roster",
    )
    update = fields(a[3])
    need(
        len(a[3]["fields"]) == 4
        and set(update) == {102, 103, 104, 112}
        and update.get(103) == b_uid.to_bytes(2, "big")
        and update.get(102) == cases.OLD_B
        and update.get(104) == cases.ICON_B,
        "B initial 301 identity/icon differs",
    )
    return a_uid, b_uid


class DualDrain:
    """Bounded two-socket byte collector; no expected arrival order."""

    def __init__(self, recorder: Recorder, epoch_deadline: float) -> None:
        self.recorder = recorder
        self.deadline = epoch_deadline
        self.buffers = {"a": bytearray(), "b": bytearray()}
        self.eof: set[str] = set()
        self.bytes_read = 0
        self.frames_seen = 0

    def pump(self, until: float) -> None:
        active = {
            label: sock
            for label, sock in self.recorder.sockets.items()
            if label not in self.eof
        }
        remaining = min(until, self.deadline) - time.monotonic()
        if remaining <= 0 or not active:
            raise TimeoutError("Dual-socket drain expired or both sockets closed")
        ready, _, _ = select.select(list(active.values()), [], [], remaining)
        if not ready:
            raise TimeoutError("Dual-socket drain timed out")
        for label, sock in active.items():
            if sock not in ready:
                continue
            need(self.bytes_read < MAX_BYTES, "Dual-socket byte limit")
            raw = sock.recv(min(4096, MAX_BYTES - self.bytes_read))
            if not raw:
                self.recorder.event(-1, label, "eof")
                self.eof.add(label)
                need(not self.buffers[label], "Truncated frame at socket EOF")
                continue
            self.recorder.event(-1, label, "receive", raw)
            self.bytes_read += len(raw)
            need(self.bytes_read <= MAX_BYTES, "Dual-socket byte limit")
            self.buffers[label].extend(raw)
            while len(self.buffers[label]) >= 20:
                size = int.from_bytes(self.buffers[label][16:20], "big")
                need(size <= 65516, "Oversize frame in dual drain")
                if len(self.buffers[label]) < 20 + size:
                    break
                frame_raw = bytes(self.buffers[label][: 20 + size])
                del self.buffers[label][: 20 + size]
                decoded = decode_frame(frame_raw)
                need(
                    decoded["total_size"] == decoded["data_size"]
                    and decoded.get("declared_field_count")
                    == len(decoded.get("fields", []))
                    and not decoded.get("unconsumed_hex"),
                    "Malformed or fragmented dual-drain frame",
                )
                self.frames_seen += 1
                need(self.frames_seen <= MAX_FRAMES, "Dual-socket frame limit")
                self.recorder.frames.append(
                    {
                        "action": -1,
                        "connection": label,
                        "arrival_ns": time.monotonic_ns() - self.recorder.started,
                        "raw_hex": frame_raw.hex(),
                        **decoded,
                    }
                )

    def until(
        self, required: set[tuple[str, int, int, int]], seconds: float
    ) -> list[dict]:
        start = len(self.recorder.frames)
        stop = min(time.monotonic() + seconds, self.deadline)
        while not required.issubset(
            {frame_key(f) for f in self.recorder.frames[start:]}
        ) or any(self.buffers.values()):
            self.pump(stop)
        return self.recorder.frames[start:]


def check_overlap(frames: list[dict], a_uid: int, b_uid: int) -> str:
    expected = {
        ("a", 1, 0, 11),
        ("a", 1, 0, 12),
        ("b", 1, 0, 12),
        ("a", 0, 301, 0),
        ("b", 0, 301, 0),
    }
    need(
        len(frames) == 5 and {frame_key(f) for f in frames} == expected,
        "Overlap reply/update set differs",
    )
    for label in ("a", "b"):
        ack = one(frames, label, 0, 12, 1)
        need(ack["error"] == 0 and ack["fields"] == [], "500 barrier ACK differs")
        update = one(frames, label, 301, 0, 0)
        value = fields(update)
        need(
            update["error"] == 0
            and len(update["fields"]) == 4
            and set(value) == {102, 103, 104, 112}
            and value.get(103) == b_uid.to_bytes(2, "big")
            and value.get(102) == cases.NEW_B
            and value.get(104) == cases.ICON_NEW,
            "Rename 301 identity/icon differs",
        )
    snapshot = one(frames, "a", 0, 11, 1)
    try:
        exact_rows(snapshot, a_uid, b_uid)
        return "old"
    except ValueError:
        exact_rows(snapshot, a_uid, b_uid, b_new=True)
        return "new"


def prepared(path: Path) -> dict:
    raw = (path / "plan.json").read_bytes()
    plan = json.loads(raw)
    validate_plan(plan)
    need(
        json.loads((path / "source-hashes.json").read_text())
        == {"plan.json": sha(raw)},
        "Prepared plan hash differs",
    )
    need(
        plan == cases.source_plan(plan["environment"], cases.MAX_PORT),
        "Prepared overlap plan differs",
    )
    kinds = {
        int.from_bytes(bytes.fromhex(s["hex"])[2:4], "big")
        for s in plan["steps"]
        if s["op"] == "send" and not s["hex"].startswith("54525450")
    }
    need(
        kinds <= {107, 300} and len(plan["endpoints"]) == 1,
        "Unexpected setup request or endpoint",
    )
    return plan


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    plan = prepared(plan_dir)
    receipt = json.loads(receipt_path.read_text())
    deadline = utc(receipt["deadline_utc"])
    need(
        0 < (deadline - datetime.now(timezone.utc)).total_seconds() <= MAX_SECONDS,
        "Overlap epoch must fit10min",
    )
    runtime_gate(receipt, plan["environment"], deadline)
    need(sha(binary.read_bytes()) == ORACLE_SHA256, "Oracle data fork differs")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    end = time.monotonic() + min(
        MAX_SECONDS, (deadline - datetime.now(timezone.utc)).total_seconds()
    )
    status, error, old_or_new = "completed", "", None
    drain = None
    actions = 0
    try:
        steps = plan["steps"]
        teardown = next(i for i, s in enumerate(steps) if s["op"] == "shutdown_write")
        for action, step in enumerate(steps[:teardown]):
            remaining = end - time.monotonic()
            need(remaining > 0, "Setup deadline reached")
            recorder.execute(
                action, {**step, "timeout": min(step.get("timeout", 2), remaining)}
            )
            actions += 1
        a_uid, b_uid = check_setup(recorder)
        runtime_gate(receipt, plan["environment"], deadline)
        overlap = plan["overlap"]
        drain = DualDrain(recorder, end)
        for label, key in (
            ("a", "a_300"),
            ("b", "b_304"),
            ("a", "a_500"),
            ("b", "b_500"),
        ):
            recorder.execute(
                actions,
                {
                    "op": "send",
                    "connection": label,
                    "hex": overlap[key],
                    "timeout": min(2, end - time.monotonic()),
                },
            )
            actions += 1
        first = drain.until(
            {
                ("a", 1, 0, 11),
                ("a", 1, 0, 12),
                ("b", 1, 0, 12),
                ("a", 0, 301, 0),
                ("b", 0, 301, 0),
            },
            overlap["drain_seconds"],
        )
        old_or_new = check_overlap(first, a_uid, b_uid)
        recorder.execute(
            actions,
            {
                "op": "send",
                "connection": "a",
                "hex": overlap["a_final_300"],
                "timeout": min(2, end - time.monotonic()),
            },
        )
        actions += 1
        final = drain.until({("a", 1, 0, 13)}, overlap["drain_seconds"])
        need(len(final) == 1, "Unexpected frame before stable snapshot")
        exact_rows(one(final, "a", 0, 13, 1), a_uid, b_uid, b_new=True)
        for label in ("a", "b"):
            recorder.execute(
                actions,
                {
                    "op": "expect_quiet",
                    "connection": label,
                    "timeout": min(overlap["quiet_seconds"], end - time.monotonic()),
                },
            )
            actions += 1
        before_teardown = len(recorder.frames)
        for step in steps[teardown:]:
            remaining = end - time.monotonic()
            need(remaining > 0, "Teardown deadline reached")
            recorder.execute(
                actions, {**step, "timeout": min(step.get("timeout", 2), remaining)}
            )
            actions += 1
        leave = one(recorder.frames, "a", 302, 0, 0)
        need(
            len(recorder.frames[before_teardown:]) == 1
            and fields(leave).get(103) == b_uid.to_bytes(2, "big"),
            "Departure UID differs",
        )
    except (
        OSError,
        EOFError,
        ValueError,
        TimeoutError,
        KeyError,
        IndexError,
        StopIteration,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for label, sock in list(recorder.sockets.items()):
            sock.close()
            recorder.event(actions, label, "close")
    result = {
        "status": status,
        "error": error,
        "completed_actions": actions,
        "old_or_new_snapshot": old_or_new,
        "scope": "one outstanding 300 and session-only 304; no cross-socket total order",
        "oracle_sha256": ORACLE_SHA256,
        "plan_sha256": sha((plan_dir / "plan.json").read_bytes()),
        "receipt_sha256": sha(receipt_path.read_bytes()),
        "started_at_utc": recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "events": recorder.events,
        "frames": recorder.frames,
        "unparsed_hex": {}
        if drain is None
        else {name: data.hex() for name, data in drain.buffers.items()},
        "streams": recorder.streams(),
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.plan_dir, args.capture_receipt, args.binary, args.output)
    print(json.dumps(result, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
