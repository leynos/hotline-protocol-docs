"""Offline generated-wire and fault controls for the isolated board fixture."""

import copy
import json
import socket
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import native_board_cases as cases
from native_board_control import (
    Wire,
    execute_case,
    prepared,
    sha,
    strict,
    verify_report,
)
from native_plan import packet, payload
from protocol_capture import Recorder
from verify_mac_peer_first_session import AGREEMENT
from verify_native_auth import ADMIN
from verify_native_shx import fields


class FakeWire(Wire):
    """Consume actual generated requests and emit deterministic native-shaped bytes."""

    def __init__(self, recorder, fault=None):
        self.recorder = recorder
        self.board = b""
        self.fault = fault
        self.overhead = None
        self.closed = set()
        self.deadline = time.monotonic() + 30
        self.action = 0

    def emit(self, name, kind, identifier, values=(), *, reply=0, error=0):
        raw = bytes.fromhex(
            packet(kind, identifier, payload(list(values)), reply=reply, error=error)
        )
        decoded = strict(raw)
        frame = {
            "action": -1,
            "connection": name,
            "arrival_ns": time.monotonic_ns() - self.recorder.started,
            "raw_hex": raw.hex(),
            **decoded,
        }
        self.recorder.frames.append(frame)
        self.recorder.event(-1, name, "receive", raw)
        return frame

    def connect(self, name, endpoint):
        assert endpoint == ("127.0.0.1", cases.PORT)
        self.recorder.sockets[name] = socket.socket()
        self.recorder.event(self.action, name, "connect")
        self.recorder.event(-1, name, "send", bytes.fromhex(cases.HELLO))
        self.recorder.event(-1, name, "receive", bytes.fromhex(cases.HELLO_REPLY))
        self.action += 1

    def send(self, name, data):
        self.recorder.event(self.action, name, "send", data)
        self.action += 1
        frame = strict(data)
        values = fields(frame)
        kind, ident = frame["type"], frame["id"]
        if kind == 107:
            self.emit(name, 0, ident, ((160, b"\0\xbe"), (161, b"\0\0")), reply=1)
            if name != "waiting":
                self.emit(
                    name, 354, 0, ((110, bytes(8) if name == "denied" else ADMIN),)
                )
            elif self.fault == "waiting_online":
                self.emit(name, 354, 0, ((110, ADMIN),))
            self.emit(name, 109, 0, ((101, AGREEMENT),))
        elif kind == 101:
            if name == "denied":
                if self.fault == "permission":
                    self.emit(name, 0, ident, reply=1)
                else:
                    self.emit(
                        name, 0, ident, ((100, b"Permission denied"),), reply=1, error=1
                    )
            else:
                board = self.board[:65535]
                if self.fault == "filler" and ident == 120:
                    board = board[:-1] + b"!"
                self.emit(
                    name,
                    0,
                    ident,
                    ((101, board),) if board else (),
                    reply=1,
                )
        elif kind == 500:
            self.emit(name, 0, ident, reply=1)
        elif kind == 103:
            data = values[101]
            if len(data) > 8192:
                self.emit(
                    name,
                    0,
                    ident,
                    ((100, b"Invalid size"),),
                    reply=1,
                    error=0 if self.fault == "error_status" else 1,
                )
                return
            self.emit(name, 0, ident, reply=1)
            segment = b"From BoardSender (Nov 14 08:20):\r\r" + data + cases.SEPARATOR
            if self.fault == "corrupt_segment" and ident == 1002:
                segment = segment[:-1] + b"!"
            self.board = segment + self.board
            for recipient in ("sender", "eligible", "waiting"):
                if recipient not in self.closed:
                    if (
                        self.fault == "missing_eligible"
                        and recipient == "eligible"
                        and ident == 1001
                    ):
                        continue
                    observed = segment
                    if (
                        self.fault == "wrong_waiting"
                        and recipient == "waiting"
                        and ident == 1001
                    ):
                        observed = segment + b"!"
                    self.emit(recipient, 102, ident, ((101, observed),))
            if self.fault == "denied_update" and ident == 1001:
                self.emit("denied", 102, ident, ((101, segment),))
        else:
            raise AssertionError(f"Unexpected fake request {kind}")

    def until(self, predicate, seconds=5):
        assert predicate(), "Fake response did not satisfy requested barrier"

    def observe(self, seconds):
        pass

    def close(self, name):
        self.closed.add(name)
        self.recorder.sockets.pop(name).close()
        self.recorder.event(-1, name, "shutdown_write")
        self.recorder.event(-1, name, "eof")
        self.recorder.event(-1, name, "close")


def environment():
    return {
        "fixture_profile": "control-only",
        "emulator_pid": 42,
        "emulator_starttime": 123,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 555,
        "owned_working_image": "/ignored/fresh.dsk",
        "owned_working_image_inode": 100,
        "stopped_board_baseline": {
            "path": cases.PATH,
            "catalog_id": 11191,
            "data_size": 0,
            "resource_size": 0,
            "finder_type": "TEXT",
            "finder_creator": "ttxt",
        },
    }


def fake_report(fault=None):
    plan = cases.source_plan(environment())
    recorder = Recorder(plan)
    wire = FakeWire(recorder, fault)
    segments, payloads, reads = [], [], {}
    try:
        execute_case(wire, plan, recorder, segments, payloads, reads, pace_seconds=0)
    finally:
        for name in list(recorder.sockets):
            wire.close(name)
    whole = b"".join(reversed(segments))
    report = {
        "status": "completed",
        "plan_sha256": sha((json.dumps(plan, indent=2) + "\n").encode()),
        "elapsed_seconds": (time.monotonic_ns() - recorder.started) / 1e9,
        "byte_count": recorder.byte_count,
        "frames": recorder.frames,
        "events": recorder.events,
        "streams": recorder.streams(),
        "post_data_hex": [x.hex() for x in payloads],
        "segments_hex": [x.hex() for x in segments],
        "reads": reads,
        "whole_board_sha256": sha(whole),
        "storage": "requires_stopped_guest_fork",
        "full_a7": "not_exercised",
    }
    return plan, report


class BoardTests(unittest.TestCase):
    def test_generated_full_chain(self):
        plan, report = fake_report()
        verify_report(plan, report)
        self.assertEqual(len(report["post_data_hex"]), 13)
        self.assertEqual(len(bytes.fromhex(report["reads"]["10"])), 65535)
        self.assertEqual(
            bytes.fromhex(report["reads"]["11"]), bytes.fromhex(report["reads"]["12"])
        )
        self.assertGreater(
            sum(len(bytes.fromhex(x)) for x in report["segments_hex"]), 65535
        )
        self.assertEqual(
            len(
                [
                    f
                    for f in report["frames"]
                    if f["connection"] == "waiting" and f["type"] == 102
                ]
            ),
            3,
        )

    def test_generated_boundaries(self):
        self.assertEqual(
            [len(cases.post_data(i)) for i in (0, 1, 2, 3, 4, 9, 11, 12)],
            [0, 7, 7, 8191, 8192, 8192, 1, 8193],
        )
        with self.assertRaises(ValueError):
            cases.post_data(10)

    def test_static_and_runtime_identity_required(self):
        for key in (
            "emulator_pid",
            "emulator_netns_inode",
            "owned_working_image_inode",
        ):
            env = environment()
            env[key] = 0
            with self.subTest(key=key), self.assertRaises(ValueError):
                cases.source_plan(env)
        env = environment()
        env["stopped_board_baseline"]["data_size"] = 1
        with self.assertRaises(ValueError):
            cases.source_plan(env)

    def test_prepared_plan_hash_and_source(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "new"
            cases.write_plan(root, environment())
            prepared(root)
            hashes_path = root / "source-hashes.json"
            original_hashes = hashes_path.read_text()
            hashes = json.loads(original_hashes)
            hashes["native_board_control.py"] = "0" * 64
            hashes_path.write_text(json.dumps(hashes))
            with self.assertRaisesRegex(ValueError, "source hash"):
                prepared(root)
            hashes_path.write_text(original_hashes)
            plan = json.loads((root / "plan.json").read_text())
            plan["operations"][0]["label"] = "changed"
            (root / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
            with self.assertRaises(ValueError):
                prepared(root)

    def test_corrupt_segment_fails_before_false_success(self):
        with self.assertRaises(ValueError):
            fake_report("corrupt_segment")

    def test_actor_and_boundary_semantic_faults(self):
        for fault in (
            "permission",
            "waiting_online",
            "missing_eligible",
            "denied_update",
            "filler",
            "error_status",
        ):
            with (
                self.subTest(fault=fault),
                self.assertRaises((ValueError, AssertionError)),
            ):
                fake_report(fault)

    def test_source_operation_fault_rejected(self):
        plan = cases.source_plan(environment())
        plan["operations"][4]["hex"] = packet(103, 1001)
        recorder = Recorder(plan)
        wire = FakeWire(recorder)
        try:
            with self.assertRaises(ValueError):
                execute_case(wire, plan, recorder, [], [], {}, pace_seconds=0)
        finally:
            for name in list(recorder.sockets):
                wire.close(name)

    def test_optional_waiting_update_requires_actual_first_three_segment(self):
        plan, report = fake_report("wrong_waiting")
        with self.assertRaisesRegex(ValueError, "Waiting update"):
            verify_report(plan, report)

    def test_nonblocking_parser_preserves_fragmented_socketpair_bytes(self):
        plan = cases.source_plan(environment())
        recorder = Recorder(plan)
        wire = Wire(recorder, time.monotonic() + 2)
        client, server = socket.socketpair()
        try:
            client.setblocking(False)
            recorder.sockets["sender"] = client
            wire.buffers["sender"] = bytearray()
            raw = bytes.fromhex(packet(0, 77, payload([(101, b"x")]), reply=1))
            server.sendall(raw[:9])
            wire.poll(time.monotonic() + 0.1)
            self.assertEqual(recorder.frames, [])
            server.sendall(raw[9:])
            wire.poll(time.monotonic() + 0.1)
            self.assertEqual(recorder.frames[0]["raw_hex"], raw.hex())
            server.shutdown(socket.SHUT_WR)
            wire.poll(time.monotonic() + 0.1)
            self.assertIn("sender", wire.eof)
        finally:
            client.close()
            server.close()

    def test_faults_reject_report_claims(self):
        plan, report = fake_report()
        for alteration in (
            "prefix",
            "boundary",
            "read",
            "status",
            "timing",
            "missing_frame",
        ):
            bad = copy.deepcopy(report)
            if alteration == "prefix":
                bad["segments_hex"][0] = (
                    b"Broken" + bytes.fromhex(bad["segments_hex"][0])[6:]
                ).hex()
            elif alteration == "boundary":
                bad["post_data_hex"][12] = "00"
            elif alteration == "read":
                bad["reads"]["11"] = "00"
            elif alteration == "status":
                bad["status"] = "completed_storage_proven"
            elif alteration == "timing":
                bad["events"][0]["elapsed_ns"] = int((bad["elapsed_seconds"] + 2) * 1e9)
            else:
                bad["frames"].pop()
            with self.subTest(alteration=alteration), self.assertRaises(ValueError):
                verify_report(plan, bad)


if __name__ == "__main__":
    unittest.main()
