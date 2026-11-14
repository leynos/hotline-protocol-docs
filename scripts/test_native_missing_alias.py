"""Offline controls for the one-alias positive rehearsal."""

import io
import json
import os
import socket
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from unittest.mock import patch

import native_missing_alias_cases as cases
import native_missing_alias_control as control
from native_plan import packet, payload
from protocol_capture import decode_frame

ENV = {
    "fixture_profile": "control-only",
    "emulator_pid": 123,
    "emulator_starttime": 456,
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 789,
    "owned_working_image": "/owned/native-alias-live-04/working.dsk",
    "owned_working_image_inode": 321,
    "owned_runtime": "/owned/native-alias-live-04",
    "initial_finf_sha256": cases.digest(b"U54TM54X" + bytes(24)),
}


class AliasPlanTests(unittest.TestCase):
    def test_one_owned_path_and_exact_budget(self):
        plan = cases.source_plan(ENV)
        self.assertEqual([r["kind"] for r in plan["requests"]], [205, 200, 200, 206])
        self.assertEqual([r["id"] for r in plan["requests"]], [10, 11, 12, 13])
        self.assertEqual(plan["case_numbered_with_login"], 5)
        self.assertEqual(plan["total_numbered_including_readiness"], 11)
        self.assertEqual(plan["handshakes"], 2)
        self.assertEqual(plan["barrier500_requests"], 0)
        self.assertEqual(plan["mutations"], 1)
        self.assertNotIn("unlink", repr(plan).lower())

    def test_named_alias_window_keeps_request_budget(self):
        env = {
            **ENV,
            "capture_window_profile": "native-missing-alias-ui-30m-v1",
            "capture_window_purpose": "native-missing-alias-positive",
        }
        plan = cases.source_plan(env)
        self.assertEqual(plan["limits"]["epoch_seconds"], 1800)
        self.assertEqual(plan["requests"], cases.source_plan(ENV)["requests"])
        for change in (
            {"capture_window_purpose": "other"},
            {"capture_window_profile": "unknown"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                cases.source_plan({**env, **change})

    def test_source_pin_and_dynamic_206(self):
        for pin in ("", "Z" * 64, "a" * 63):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                cases.source_plan({**ENV, "initial_finf_sha256": pin})
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "plan"
            cases.write_plan(folder, ENV)
            plan = control.prepared(folder)
            self.assertEqual(plan["total_numbered_including_readiness"], 11)
            alias = b"copied alias"
            raw = cases.request_hex(plan["requests"][3], alias)
            decoded = decode_frame(bytes.fromhex(raw))
            self.assertEqual(decoded["type"], 206)
            self.assertEqual(
                decoded["fields"],
                [
                    {"id": 201, "hex": alias.hex()},
                    {"id": 202, "hex": cases.ROOT_PATH.hex()},
                ],
            )
            (folder / "source-hashes.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "source hash"):
                control.prepared(folder)

    def test_tagged_alias_206_and_semantic_faults(self):
        alias = b"copied alias"
        values = [
            (201, alias),
            (205, control.ALIAS_205),
            (206, control.ALIAS_206),
            (213, control.ALIAS_213),
            (207, b"\x01\x4d"),
        ]

        def frame(items):
            raw = packet(0, 13, payload(items), reply=1)
            return {
                "connection": "main",
                "raw_hex": raw,
                **decode_frame(bytes.fromhex(raw)),
            }

        self.assertEqual(
            control.positive_alias(frame(values), alias)["field207_hex"], "014d"
        )
        for changed in (
            [(201, alias), (205, b"U54T"), *values[2:]],
            [(201, alias), (205, b"Unattached Alias"), *values[2:]],
            [*values, (205, control.ALIAS_205)],
            [(201, b"other"), *values[1:]],
            [*values[:2], (206, b"BAD!"), *values[3:]],
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                control.positive_alias(frame(changed), alias)
        error = frame(values)
        error["error"] = 1
        with self.assertRaisesRegex(ValueError, "status/error"):
            control.direct([error], 13)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            control.direct([frame(values), frame(values)], 13)

    def test_owned_target_and_finder_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "native-alias-live-04"
            shared = runtime / "shared"
            (shared / ".finf").mkdir(parents=True)
            target = shared / cases.TARGET.decode()
            finder = shared / ".finf" / cases.TARGET.decode()
            target.write_bytes(cases.TARGET_DATA)
            finder.write_bytes(b"U54TM54X" + bytes(24))
            os.chmod(target, 0o600)
            os.chmod(finder, 0o600)
            seconds = target.stat().st_mtime_ns // 1_000_000_000
            os.utime(
                target,
                ns=(seconds * 1_000_000_000, seconds * 1_000_000_000 + 88_000_000),
            )
            plan = cases.source_plan(
                {
                    **ENV,
                    "owned_runtime": str(runtime),
                    "owned_working_image": str(runtime / "working.dsk"),
                }
            )
            before = control.host_state(plan)
            os.utime(target, ns=(seconds * 1_000_000_000, seconds * 1_000_000_000))
            changed = bytearray(finder.read_bytes())
            changed[10] = 1
            finder.write_bytes(changed)
            after = control.host_state(plan)
            self.assertNotEqual(
                before["target"]["mtime_ns"], after["target"]["mtime_ns"]
            )
            control.same_target(before, after)
            self.assertNotEqual(before["finder"]["sha256"], after["finder"]["sha256"])
            changed[0] = ord("X")
            finder.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "type/creator"):
                control.host_state(plan)
            finder.write_bytes(b"U54TM54X" + bytes(24))
            target.write_bytes(b"X" + cases.TARGET_DATA[1:])
            with self.assertRaisesRegex(ValueError, "DATA differs"):
                control.host_state(plan)
            target.write_bytes(cases.TARGET_DATA)
            target.unlink()
            with self.assertRaises(FileNotFoundError):
                control.host_state(plan)

    def test_duplicate_200_rows_stop_before_206(self):
        def reply(identifier, values, kind=0, answer=1):
            raw = packet(kind, identifier, payload(values), reply=answer)
            return {
                "connection": "main",
                "raw_hex": raw,
                **decode_frame(bytes.fromhex(raw)),
            }

        def row(name):
            return bytes(16) + len(name).to_bytes(4, "big") + name

        class FakeWire:
            def __init__(self):
                self.frames = [
                    reply(1, [(160, b"\0\xbe"), (161, b"\0\0")]),
                    reply(2, [(110, control.ADMIN)], 354, 0),
                    reply(3, [(101, b"x")], 109, 0),
                ]
                self.buffers = {}
                self.partial = {}
                self.request_count = 0
                self.deadline = time.monotonic() + 2

            def execute(self, step):
                pass

            def send(self, name, raw, label):
                pass

            def wait_for(self, predicate, seconds, label):
                pass

            def match(self, name, kind, identifier, answer):
                return [f for f in self.frames if f["type"] == kind]

            def poll(self, seconds):
                pass

        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "receipt.json"
            receipt.write_text(json.dumps(cases.example_operator_receipt()))
            plan = cases.source_plan(ENV)
            host = {
                "parents": {},
                "target": {},
                "finder": {"sha256": control.digest(b"U54TM54X" + bytes(24))},
            }
            original_digest = control.digest
            roots = [(200, row(f"prior-{i}".encode())) for i in range(41)]
            responses = [
                reply(10, []),
                reply(11, [*roots, (200, row(cases.ROOT))]),
                reply(12, [(200, row(b"copied alias"))] * 2),
            ]
            remaining = iter(responses)

            def fake_exchange(wire, spec, alias=None):
                wire.request_count += 1
                return next(remaining)

            output = io.StringIO()
            with (
                patch.object(control, "host_state", return_value=host),
                patch.object(control, "check_screens"),
                patch.object(control, "same_target"),
                patch.object(
                    control,
                    "digest",
                    side_effect=lambda raw: (
                        control.AGREEMENT_SHA if raw == b"x" else original_digest(raw)
                    ),
                ),
                patch.object(control, "exchange", side_effect=fake_exchange) as calls,
                redirect_stdout(output),
                self.assertRaisesRegex(ValueError, "Repeated file-list name"),
            ):
                control.perform(
                    cast(control.Wire, FakeWire()), plan, receipt, lambda: None
                )
            self.assertEqual(calls.call_count, 3, "206 was sent after ambiguity")
            ready = json.loads(output.getvalue())
            self.assertEqual(ready["event"], "READY")
            self.assertEqual(ready["stage"], "awaiting-reviewed-Finder-receipt")
            self.assertEqual(ready["numbered_requests"], 3)
            self.assertEqual(
                ready["plan_sha256"],
                control.digest((json.dumps(plan, indent=2) + "\n").encode()),
            )
            self.assertEqual(ready["emulator_pid"], ENV["emulator_pid"])
            self.assertEqual(ready["emulator_netns_inode"], ENV["emulator_netns_inode"])
            early = io.StringIO()
            with (
                patch.object(control, "host_state", return_value=host),
                patch.object(
                    control,
                    "digest",
                    side_effect=lambda raw: (
                        control.AGREEMENT_SHA if raw == b"x" else original_digest(raw)
                    ),
                ),
                patch.object(
                    control, "exchange", side_effect=[reply(10, []), reply(11, [])]
                ) as calls,
                redirect_stdout(early),
                self.assertRaisesRegex(ValueError, "Owned Files folder/root count"),
            ):
                control.perform(
                    cast(control.Wire, FakeWire()), plan, receipt, lambda: None
                )
            self.assertEqual(early.getvalue(), "")
            self.assertEqual(calls.call_count, 2)

    def test_failed_run_writes_partial_report_and_closes_real_fd(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "native-alias-live-04"
            shared = runtime / "shared"
            (shared / ".finf").mkdir(parents=True)
            prestaged_finfo = b"U54TM54X" + b"\x01" + bytes(23)
            for path, data in (
                (shared / cases.TARGET.decode(), cases.TARGET_DATA),
                (shared / ".finf" / cases.TARGET.decode(), prestaged_finfo),
            ):
                path.write_bytes(data)
                os.chmod(path, 0o600)
            env = {
                **ENV,
                "owned_runtime": str(runtime),
                "owned_working_image": str(runtime / "working.dsk"),
                "emulator_netns_inode": os.stat("/proc/self/ns/net").st_ino,
                "initial_finf_sha256": cases.digest(prestaged_finfo),
            }
            folder = root / "plan"
            cases.write_plan(folder, env)
            receipt = root / "capture-ready.json"
            receipt.write_text(
                json.dumps(
                    {
                        "deadline_utc": (
                            datetime.now(timezone.utc) + timedelta(seconds=600)
                        ).isoformat(),
                        "emulator_pid": env["emulator_pid"],
                    }
                )
            )
            binary = root / "pef"
            binary.write_bytes(b"offline test oracle")
            owned_fd = []

            def fail_with_partial(wire, plan, operator, guard):
                left, right = socket.socketpair()
                owned_fd.append(left)
                wire.recorder.sockets["main"] = left
                wire.buffers["main"] = bytearray()
                wire.partial = {
                    "stage": "partial-reply",
                    "request_count": 2,
                    "host_before": control.host_state(plan),
                }
                right.sendall(b"\x00\x01\x02")
                right.shutdown(socket.SHUT_WR)
                right.close()
                raise ValueError("controlled partial failure")

            with (
                patch.object(control, "runtime_gate"),
                patch.object(
                    control, "ORACLE_SHA256", control.digest(binary.read_bytes())
                ),
                patch.object(control, "perform", fail_with_partial),
            ):
                report = control.run(
                    folder, receipt, root / "operator.json", binary, root / "out"
                )
            self.assertEqual(report["status"], "failed")
            self.assertIn("controlled partial failure", report["error"])
            self.assertEqual(report["stage"], "partial-reply")
            self.assertEqual(report["unparsed_hex"]["main"], "000102")
            self.assertEqual(report["terminals"]["main"], "eof")
            self.assertEqual(owned_fd[0].fileno(), -1)
            self.assertEqual(json.loads((root / "out/report.json").read_text()), report)
            wrong = root / "wrong-plan"
            cases.write_plan(
                wrong, {**env, "initial_finf_sha256": ENV["initial_finf_sha256"]}
            )
            with (
                patch.object(control, "runtime_gate"),
                patch.object(
                    control, "ORACLE_SHA256", control.digest(binary.read_bytes())
                ),
                self.assertRaisesRegex(ValueError, "Pre-socket Finder sidecar"),
            ):
                control.run(
                    wrong, receipt, root / "operator.json", binary, root / "wrong-out"
                )
            self.assertFalse((root / "wrong-out").exists())

    def test_operator_gate_rejects_ambiguity(self):
        receipt = cases.example_operator_receipt()
        control.operator_gate(receipt, cases.source_plan(ENV))
        for key, value in (
            ("make_alias_enabled", False),
            ("copy_enabled", False),
            ("paste_enabled", False),
            ("separate_alias", False),
            ("unexpected_prompt", True),
            ("overwrite_prompt", True),
            ("action_count", 2),
            ("target_name_hex", "00"),
        ):
            changed = {**receipt, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                control.operator_gate(changed, cases.source_plan(ENV))

    def test_operator_screenshots_must_match_bytes(self):
        receipt = cases.example_operator_receipt()
        with tempfile.TemporaryDirectory() as temp:
            screens = Path(temp) / "screens"
            screens.mkdir()
            for key in control.SCREEN_KEYS:
                (screens / f"{key}.png").write_bytes(b"not the claimed PNG")
            with self.assertRaisesRegex(ValueError, "screenshot differs"):
                control.check_screens(receipt, Path(temp))


if __name__ == "__main__":
    unittest.main()
