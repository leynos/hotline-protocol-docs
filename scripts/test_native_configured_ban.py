"""Offline controls for the configured-address ban fixture plan and capture."""

import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

import native_configured_ban_cases as cases
import native_configured_ban_control as control
import protocol_capture
from native_plan import packet, payload
from protocol_capture import (
    Recorder,
    decode_frame,
    digest,
    validate_plan,
    verify_capture,
)


class FakeRecorder(Recorder):
    def __init__(self, plan: dict) -> None:
        super().__init__(plan)
        self.started_at_utc = "2026-11-14T04:00:00+00:00"
        self.variables = {"target_uid": b"\0\5"}

    def execute(self, action: int, step: dict) -> None:
        name = step["connection"]
        op = step["op"]
        if op == "send":
            self.event(action, name, "send", bytes.fromhex(step["hex"]))
        elif op == "read":
            self.event(action, name, "receive", b"TRTP\0\0\0\0")
        elif op == "read_frame":
            kind, identifier, reply = {
                4: (0, 1, 1),
                5: (354, 0, 0),
                6: (109, 0, 0),
                11: (0, 1, 1),
                12: (354, 0, 0),
                13: (109, 0, 0),
                14: (301, 0, 0),
                16: (0, 32, 1),
                17: (104, 0, 0),
                18: (104, 0, 0),
            }[action]
            values = [(101, control.base.BAN_TEXT)] if kind == 104 else []
            if kind == 301:
                values = [(103, b"\0\5"), (102, cases.NAME)]
            raw = bytes.fromhex(packet(kind, identifier, payload(values), reply=reply))
            self.event(action, name, "receive", raw)
            self.frames.append(
                {"action": action, "connection": name, **decode_frame(raw)}
            )
        else:
            self.event(action, name, "eof" if op == "read_eof" else op)


class ConfiguredBanPreparationTest(unittest.TestCase):
    def test_identity_gate_requires_current_uid_name_and_distinct_roster(self) -> None:
        def frame(connection, kind, identifier=0, *, reply=0, error=0, values=()):
            return {
                "connection": connection,
                "type": kind,
                "id": identifier,
                "is_reply": reply,
                "error": error,
                "fields": [{"id": key, "hex": value.hex()} for key, value in values],
            }

        frames = [frame("main", 0), frame("main", 354), frame("main", 109)]
        frames += [
            frame("target", 0, 1, reply=1),
            frame("target", 354, values=[(110, cases.ZERO)]),
            frame("target", 109),
            frame("main", 301, values=[(103, b"\0\5"), (102, cases.NAME)]),
            frame("main", 0, 32, reply=1),
        ]
        rows = [
            {"uid": 5, "name_hex": cases.NAME.hex()},
            {"uid": 4, "name_hex": b"framing-fixture".hex()},
        ]
        with (
            patch.object(control.base, "login_gate"),
            patch.object(control, "roster", return_value=rows),
        ):
            self.assertEqual(control.identity_gate(frames), b"\0\5")
            wrong_name = copy.deepcopy(frames)
            wrong_name[6]["fields"][1]["hex"] = b"intruder".hex()
            with self.assertRaisesRegex(ValueError, "UID/name differs"):
                control.identity_gate(wrong_name)
            rows[1]["uid"] = 5
            with self.assertRaisesRegex(ValueError, "roster identities differ"):
                control.identity_gate(frames)

    def test_plan_has_complete_tail_and_no_110(self) -> None:
        steps = cases.plans()
        self.assertEqual(
            {name: len(value) for name, value in steps.items()},
            {"readiness": 18, "guard": 10, "seed": 12, "held-apply": 23},
        )
        self.assertEqual(
            [(step["op"], step.get("connection")) for step in steps["held-apply"][-6:]],
            [
                ("read_frame", "main"),
                ("read_frame", "target"),
                ("read_eof", "main"),
                ("read_eof", "target"),
                ("close", "main"),
                ("close", "target"),
            ],
        )
        self.assertTrue(
            all("expect_hex" not in step for step in steps["held-apply"][-4:-2])
        )
        for phase in steps.values():
            for step in phase:
                if step["op"] == "send" and "{" not in step["hex"]:
                    self.assertNotEqual(bytes.fromhex(step["hex"])[2:4], b"\0\x6e")

    def test_plans_validate_and_reject_primary_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "owned lab port"):
                cases.write_plans(
                    Path(directory) / "bad", {"source_a7_sha256": cases.A7_SHA}, 15500
                )
            path = Path(directory) / "good"
            hashes = cases.write_plans(
                path, {"source_a7_sha256": cases.A7_SHA, "emulator_pid": 123}, 15770
            )
            self.assertEqual(set(hashes), control.EXPECTED_PLANS)
            for name, source_hash in hashes.items():
                source = (path / f"{name}.json").read_bytes()
                self.assertEqual(digest(source), source_hash)
                validate_plan(json.loads(source))

    def test_pre_save_activity_fails_closed(self) -> None:
        sender, receiver = socket.socketpair()
        try:
            fake = FakeRecorder({})
            fake.sockets = {"main": receiver}
            sender.sendall(b"unexpected notice")
            with (
                tempfile.TemporaryDirectory() as directory,
                self.assertRaisesRegex(ValueError, "before reviewed Save"),
            ):
                control.wait_for_reviewed_save(
                    cast(Recorder, fake), Path(directory) / "trigger", 10**20
                )
        finally:
            sender.close()
            receiver.close()

    def test_report_producer_and_consumer_include_eof_tail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = {
                "schema_version": 1,
                "profile": "native-mac-oracle",
                "operator": "offline fake",
                "oracle_sha256": digest(b"binary"),
                "gap_ids": ["GAP-044"],
                "endpoints": {"control": {"host": "127.0.0.1", "port": 15770}},
                "steps": cases.plans()["held-apply"],
            }
            source = (json.dumps(plan) + "\n").encode()
            (root / "source.json").write_bytes(source)
            (root / "binary").write_bytes(b"binary")
            (root / "capture.json").write_text("{}")
            with (
                patch.object(control, "ORACLE_SHA256", digest(b"binary")),
                patch.object(protocol_capture, "ORACLE_SHA256", digest(b"binary")),
                patch.object(control, "Recorder", FakeRecorder),
                patch.object(control, "identity_gate", return_value=b"\0\5"),
                patch.object(control.base, "capture_gate"),
                patch.object(control, "wait_for_reviewed_save"),
            ):
                report = control.run_held(
                    root / "source.json",
                    root / "binary",
                    root / "out",
                    root / "trigger",
                    root / "capture.json",
                )
                restored = json.loads((root / "out/report.json").read_text())
                self.assertEqual(restored, report)
                self.assertEqual(verify_capture(root / "out"), restored)
                self.assertEqual(report["completed_actions"], 23)
                control.outcome(restored, plan)
                shortened = copy.deepcopy(restored)
                shortened["completed_actions"] = 21
                with self.assertRaisesRegex(ValueError, "tail incomplete"):
                    control.outcome(shortened, plan)
                no_eof = copy.deepcopy(restored)
                no_eof["events"] = [
                    e for e in no_eof["events"] if e["connection"] != "target"
                ]
                with self.assertRaisesRegex(ValueError, "target close missing"):
                    control.outcome(no_eof, plan)
                for header in ("flags", "is_reply", "error"):
                    with self.subTest(header=header):
                        wrong_header = copy.deepcopy(restored)
                        next(f for f in wrong_header["frames"] if f["type"] == 104)[
                            header
                        ] = 1
                        with self.assertRaisesRegex(
                            ValueError, "main configured-ban notice differs"
                        ):
                            control.outcome(wrong_header, plan)


if __name__ == "__main__":
    unittest.main()
