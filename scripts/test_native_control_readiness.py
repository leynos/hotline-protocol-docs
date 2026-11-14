"""Offline controls for the isolated ban request gate."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import native_ban_control_cases as cases
from native_control_readiness import execute_ban_step, main, plan_gate, target_gate
from native_plan import packet, payload
from protocol_capture import Recorder


def frame(kind: int, connection: str, values: list[tuple[int, bytes]], **extra) -> dict:
    return {
        "type": kind,
        "connection": connection,
        "is_reply": 0,
        "id": 0,
        "error": 0,
        "fields": [{"id": field, "hex": value.hex()} for field, value in values],
        **extra,
    }


def row(uid: int, name: bytes) -> bytes:
    return uid.to_bytes(2, "big") + b"\0\1\0\0" + len(name).to_bytes(2, "big") + name


def witnesses(
    uid: int = 2, access: bytes = bytes(8), name: bytes = cases.NAME
) -> list[dict]:
    main = [frame(0, "main", []), frame(354, "main", []), frame(109, "main", [])]
    target = [
        frame(0, "target", [], is_reply=1),
        frame(354, "target", [(110, access)]),
        frame(109, "target", []),
    ]
    join = frame(301, "main", [(103, uid.to_bytes(2, "big")), (102, name)])
    roster = frame(
        0,
        "main",
        [(300, row(1, b"framing-fixture")), (300, row(2, cases.NAME))],
        is_reply=1,
        id=32,
    )
    return main + target + [join, roster]


class FakeRecorder(Recorder):
    def __init__(self, frames: list[dict], uid: bytes = b"\0\2") -> None:
        self.frames = frames
        self.variables = {"target_uid": uid}
        self.sent: list[dict] = []

    def execute(self, action: int, step: dict) -> None:
        del action
        self.sent.append(step)


class NativeControlReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ban_step = {
            "op": "send",
            "hex": packet(110, 33, payload([(103, b"\0\2"), (113, b"\0\2")])),
        }

    def test_exact_short_plan_has_no_transfer_or_reason(self) -> None:
        plans = cases.plans()
        self.assertEqual(len(plans["readiness"]), 18)
        sent = [
            s["hex"] for steps in plans.values() for s in steps if s["op"] == "send"
        ]
        self.assertFalse(any(s.startswith(("000000ca", "48545846")) for s in sent))
        bans = [s for s in sent if s.startswith("0000006e")]
        self.assertEqual(len(bans), 1)
        ban = bans[0]
        self.assertIn("007100020002", ban)
        self.assertNotIn("006500", ban)

    def test_valid_current_uid_and_zero_access_allow_one_110(self) -> None:
        recorder = FakeRecorder(witnesses())
        with patch("native_control_readiness.login_gate"):
            self.assertEqual(target_gate(recorder.frames), b"\0\2")
            execute_ban_step(recorder, 17, self.ban_step)
        self.assertEqual(recorder.sent, [self.ban_step])

    def test_wrong_current_uid_sends_no_110(self) -> None:
        recorder = FakeRecorder(witnesses(uid=3), b"\0\3")
        with (
            patch("native_control_readiness.login_gate"),
            self.assertRaisesRegex(ValueError, "roster target"),
        ):
            execute_ban_step(recorder, 17, self.ban_step)
        self.assertEqual(recorder.sent, [])

    def test_nonzero_access_sends_no_110(self) -> None:
        recorder = FakeRecorder(witnesses(access=b"\x80" + bytes(7)))
        with (
            patch("native_control_readiness.login_gate"),
            self.assertRaisesRegex(ValueError, "access"),
        ):
            execute_ban_step(recorder, 17, self.ban_step)
        self.assertEqual(recorder.sent, [])

    def test_mismatched_saved_uid_sends_no_110(self) -> None:
        recorder = FakeRecorder(witnesses(), b"\0\3")
        with (
            patch("native_control_readiness.login_gate"),
            self.assertRaisesRegex(ValueError, "Saved target UID"),
        ):
            execute_ban_step(recorder, 17, self.ban_step)
        self.assertEqual(recorder.sent, [])

    def test_rehashed_plan_source_is_required_before_contact(self) -> None:
        with TemporaryDirectory() as temporary:
            directory = Path(temporary) / "plans"
            hashes = cases.write_plans(
                directory,
                {"source_a7_sha256": cases.A7_SHA, "emulator_pid": 42},
                15750,
            )
            (directory / "source-hashes.json").write_text(json.dumps(hashes))
            plan_gate(directory, 42)
            path = directory / "ban.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "source plan changed"):
                plan_gate(directory, 42)

    def test_live_cli_rejects_unprivileged_controller_before_receipt_read(self) -> None:
        argv = [
            "program",
            "run",
            "--plans",
            "/missing-plans",
            "--binary",
            "/missing-binary",
            "--capture-ready",
            "/missing-receipt",
            "--output",
            "/missing-output",
        ]
        with (
            patch("sys.argv", argv),
            patch("native_control_readiness.os.geteuid", return_value=1000),
            self.assertRaisesRegex(PermissionError, "requires root"),
        ):
            main()


if __name__ == "__main__":
    unittest.main()
