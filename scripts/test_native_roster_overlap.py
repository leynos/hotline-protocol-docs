"""Offline socket and frame faults for the generated roster-overlap plan."""

import json
import socket
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

import native_roster_overlap_cases as cases
import native_roster_overlap_control as control
from native_plan import packet, payload
from protocol_capture import Recorder, decode_frame
from verify_native_auth import ADMIN


def environment() -> dict:
    return {
        "fixture_profile": "control-only",
        "emulator_pid": 9,
        "emulator_starttime": 10,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 11,
        "owned_working_image": "/ignored/working.dsk",
        "owned_working_image_inode": 12,
    }


def record(uid: int, icon: int, name: bytes) -> bytes:
    return (
        uid.to_bytes(2, "big")
        + icon.to_bytes(2, "big")
        + b"\0\x20"
        + len(name).to_bytes(2, "big")
        + name
    )


def reply(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> bytes:
    return bytes.fromhex(packet(kind, identifier, payload(values), reply=1))


def notice(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> bytes:
    return bytes.fromhex(packet(kind, identifier, payload(values)))


def roster_reply(identifier: int, *, name: bytes = cases.OLD_B, icon: int = 2) -> bytes:
    return reply(
        0, identifier, [(300, record(1, 1, cases.OLD_A)), (300, record(2, icon, name))]
    )


def decoded(raw: bytes, connection: str) -> dict:
    return {"connection": connection, **decode_frame(raw)}


def overlap_messages(order: str) -> tuple[bytes, bytes]:
    snapshot = roster_reply(11)
    update = notice(
        301,
        77,
        [(103, b"\0\x02"), (104, cases.ICON_NEW), (112, b"\0\x20"), (102, cases.NEW_B)],
    )
    barrier = reply(0, 12, [])
    if order == "ack-first":
        return snapshot + update + barrier, update + barrier
    return update + snapshot + barrier, barrier + update


class RosterOverlapTests(unittest.TestCase):
    def fixture(self) -> tuple[dict, Recorder, socket.socket, socket.socket]:
        plan = cases.source_plan(environment())
        recorder = Recorder(plan)
        client_a, server_a = socket.socketpair()
        client_b, server_b = socket.socketpair()
        recorder.sockets = {"a": client_a, "b": client_b}
        for sock in (client_a, server_a, client_b, server_b):
            self.addCleanup(sock.close)
        return plan, recorder, server_a, server_b

    def test_generated_plan_limits_requests_and_prepared_hash(self) -> None:
        plan = cases.source_plan(environment())
        self.assertEqual(plan["endpoints"]["control"]["port"], 15820)
        self.assertEqual(sum(s["op"] == "connect" for s in plan["steps"]), 2)
        sends = [
            bytes.fromhex(s["hex"])[2:4]
            for s in plan["steps"]
            if s["op"] == "send" and not s["hex"].startswith("54525450")
        ]
        self.assertEqual(set(sends), {b"\0k", b"\x01,"})
        self.assertEqual(
            [s["op"] for s in plan["steps"][-7:]],
            [
                "shutdown_write",
                "read_eof",
                "close",
                "read_frame",
                "shutdown_write",
                "read_eof",
                "close",
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "plans"
            cases.write_plan(directory, environment())
            self.assertEqual(control.prepared(directory), plan)
            altered = json.loads((directory / "plan.json").read_text())
            altered["overlap"]["b_304"] = cases.source_plan(environment())["overlap"][
                "a_300"
            ]
            (directory / "plan.json").write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, "hash differs"):
                control.prepared(directory)

    def test_both_arrival_orders_from_generated_plan(self) -> None:
        required = {
            ("a", 1, 0, 11),
            ("a", 1, 0, 12),
            ("b", 1, 0, 12),
            ("a", 0, 301, 0),
            ("b", 0, 301, 0),
        }
        for order in ("ack-first", "update-first"):
            with self.subTest(order=order):
                _plan, recorder, server_a, server_b = self.fixture()
                a, b = overlap_messages(order)
                server_a.sendall(a)
                server_b.sendall(b)
                drained = control.DualDrain(recorder, time.monotonic() + 1)
                frames = drained.until(required, 1)
                self.assertEqual(control.check_overlap(frames, 1, 2), "old")
                self.assertEqual(len(frames), 5)
                self.assertTrue(
                    all(f["raw_hex"] and f["arrival_ns"] >= 0 for f in frames)
                )
                self.assertEqual(recorder.streams()["a"]["received_hex"], a.hex())
                self.assertEqual(recorder.streams()["b"]["received_hex"], b.hex())

    def test_truncated_malformed_and_wrong_correlation(self) -> None:
        required = {("a", 1, 0, 11)}
        _plan, recorder, server_a, _server_b = self.fixture()
        server_a.sendall(roster_reply(11)[:10])
        server_a.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(ValueError, "Truncated frame"):
            control.DualDrain(recorder, time.monotonic() + 1).until(required, 1)
        self.assertEqual(
            recorder.streams()["a"]["received_hex"], roster_reply(11)[:10].hex()
        )
        _plan, recorder, server_a, _server_b = self.fixture()
        server_a.sendall(bytes.fromhex(packet(0, 11, b"\0\1", reply=1)))
        with self.assertRaisesRegex(ValueError, "Malformed"):
            control.DualDrain(recorder, time.monotonic() + 1).until(required, 1)
        _plan, recorder, server_a, _server_b = self.fixture()
        server_a.sendall(roster_reply(99))
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            control.DualDrain(recorder, time.monotonic() + 0.02).until(required, 0.02)

    def test_torn_identity_and_extra_update_fail(self) -> None:
        _plan, recorder, server_a, server_b = self.fixture()
        a, b = overlap_messages("ack-first")
        torn = roster_reply(11, name=cases.NEW_B, icon=2)
        server_a.sendall(torn + a[len(roster_reply(11)) :])
        server_b.sendall(b)
        required = {
            ("a", 1, 0, 11),
            ("a", 1, 0, 12),
            ("b", 1, 0, 12),
            ("a", 0, 301, 0),
            ("b", 0, 301, 0),
        }
        frames = control.DualDrain(recorder, time.monotonic() + 1).until(required, 1)
        with self.assertRaisesRegex(ValueError, "torn"):
            control.check_overlap(frames, 1, 2)
        with self.assertRaisesRegex(ValueError, "set differs"):
            control.check_overlap(frames + [frames[1]], 1, 2)
        duplicate = [dict(frame) for frame in frames]
        update = control.one(duplicate, "a", 301, 0, 0)
        update["fields"] = [*update["fields"], update["fields"][-1]]
        with self.assertRaisesRegex(ValueError, "repeated scalar"):
            control.check_overlap(duplicate, 1, 2)

    def test_actual_setup_consumer_rejects_third_user(self) -> None:
        _plan, recorder, _server_a, _server_b = self.fixture()
        a = [
            reply(0, 1, []),
            notice(354, 2, [(110, ADMIN)]),
            notice(109, 3, []),
            notice(
                301,
                4,
                [
                    (103, b"\0\x02"),
                    (102, cases.OLD_B),
                    (104, cases.ICON_B),
                    (112, b"\0\x20"),
                ],
            ),
            roster_reply(10),
        ]
        b = [
            reply(0, 1, []),
            notice(354, 2, [(110, ADMIN)]),
            notice(109, 3, []),
            roster_reply(10),
        ]
        recorder.frames = [decoded(raw, "a") for raw in a] + [
            decoded(raw, "b") for raw in b
        ]
        recorder.variables["b_uid"] = b"\0\x02"
        self.assertEqual(control.check_setup(recorder), (1, 2))
        third = reply(
            0,
            10,
            [
                (300, record(1, 1, cases.OLD_A)),
                (300, record(2, 2, cases.OLD_B)),
                (300, record(3, 4, b"unexpected")),
            ],
        )
        recorder.frames[4] = decoded(third, "a")
        with self.assertRaisesRegex(ValueError, "third member"):
            control.check_setup(recorder)


class FakeNativeRecorder(Recorder):
    """Actual Recorder over socketpairs; responses follow generated requests."""

    order = "ack-first"
    late_tail = False
    latest = None

    def __init__(self, plan: dict) -> None:
        super().__init__(plan)
        self.peers: dict[str, socket.socket] = {}
        FakeNativeRecorder.latest = self

    def execute(self, action: int, step: dict) -> None:
        name, op = step["connection"], step["op"]
        if op == "connect":
            client, peer = socket.socketpair()
            self.sockets[name], self.peers[name] = client, peer
            self.event(action, name, "connect")
            return
        super().execute(action, step)
        if op == "close":
            self.peers[name].close()
        elif op == "shutdown_write":
            if name == "b":
                self.peers["a"].sendall(notice(302, 88, [(103, b"\0\x02")]))
                if self.late_tail:
                    self.peers["b"].sendall(b"late-tail")
            self.peers[name].shutdown(socket.SHUT_WR)
        elif op == "send":
            raw = bytes.fromhex(step["hex"])
            self.peers[name].recv(len(raw))
            if raw == b"TRTPHOTL\0\1\0\2":
                self.peers[name].sendall(b"TRTP\0\0\0\0")
                return
            request = decode_frame(raw)
            kind, identifier = request["type"], request["id"]
            if kind == 107:
                self.peers[name].sendall(
                    reply(0, 1, [])
                    + notice(354, 2, [(110, ADMIN)])
                    + notice(109, 3, [])
                )
                if name == "b":
                    self.peers["a"].sendall(
                        notice(
                            301,
                            4,
                            [
                                (103, b"\0\x02"),
                                (102, cases.OLD_B),
                                (104, cases.ICON_B),
                                (112, b"\0\x20"),
                            ],
                        )
                    )
            elif kind == 300 and identifier == 10:
                self.peers[name].sendall(roster_reply(10))
            elif kind == 300 and identifier == 11 and self.order == "ack-first":
                self.peers["a"].sendall(roster_reply(11))
            elif kind == 304:
                update = notice(
                    301,
                    77,
                    [
                        (103, b"\0\x02"),
                        (104, cases.ICON_NEW),
                        (112, b"\0\x20"),
                        (102, cases.NEW_B),
                    ],
                )
                self.peers["a"].sendall(update)
                self.peers["b"].sendall(update)
                if self.order == "update-first":
                    self.peers["a"].sendall(roster_reply(11, name=cases.NEW_B, icon=3))
            elif kind == 500:
                self.peers[name].sendall(reply(0, identifier, []))
            elif kind == 300 and identifier == 13:
                self.peers["a"].sendall(roster_reply(13, name=cases.NEW_B, icon=3))


class WholeRunTests(unittest.TestCase):
    def test_generated_plan_through_actual_coordinator_both_orders_and_tail(
        self,
    ) -> None:
        for order, late in (("ack-first", False), ("update-first", True)):
            with self.subTest(order=order), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cases.write_plan(root / "plans", environment())
                binary = root / "oracle"
                binary.write_bytes(b"oracle")
                (root / "receipt.json").write_text(
                    json.dumps(
                        {
                            "deadline_utc": (
                                datetime.now(timezone.utc) + timedelta(minutes=2)
                            ).isoformat()
                        }
                    )
                )
                FakeNativeRecorder.order, FakeNativeRecorder.late_tail = order, late
                with (
                    patch.object(control, "runtime_gate"),
                    patch.object(
                        control, "ORACLE_SHA256", sha256(b"oracle").hexdigest()
                    ),
                    patch.object(control, "Recorder", FakeNativeRecorder),
                ):
                    report = control.run(
                        root / "plans", root / "receipt.json", binary, root / "out"
                    )
                self.assertEqual(report["status"], "completed", report["error"])
                self.assertEqual(report["overlap_status"], "completed")
                self.assertEqual(
                    report["old_or_new_snapshot"],
                    "old" if order == "ack-first" else "new",
                )
                self.assertEqual(
                    report["teardown_status"],
                    "completed_with_late_bytes" if late else "completed",
                )
                control.verify_operation_map(cases.source_plan(environment()), report)
                changed = json.loads(json.dumps(report))
                injected = next(
                    e for e in changed["operation_map"] if e["label"] == "b304-rename"
                )
                changed["events"][injected["event_range"][0]]["hex"] = "00"
                with self.assertRaisesRegex(ValueError, "Injected request bytes"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )
                changed = json.loads(json.dumps(report))
                drain = next(
                    e for e in changed["operation_map"] if e["label"] == "overlap-drain"
                )
                changed["events"][drain["event_range"][0]]["action"] = 1
                with self.assertRaisesRegex(ValueError, "Custom drain"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )
                changed = json.loads(json.dumps(report))
                changed["operation_map"][2]["event_range"][0] += 1
                with self.assertRaisesRegex(ValueError, "Operation map bounds"):
                    control.verify_operation_map(
                        cases.source_plan(environment()), changed
                    )


if __name__ == "__main__":
    unittest.main()
