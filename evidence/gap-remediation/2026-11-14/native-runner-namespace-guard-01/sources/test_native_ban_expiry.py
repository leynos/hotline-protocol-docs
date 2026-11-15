"""Offline controls for the finite temporary-ban fixture and its runner."""

import hashlib
import json
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import patch

import native_ban_expiry_cases as cases
import native_ban_expiry_control as control
from native_plan import packet, payload
from protocol_capture import decode_frame, validate_plan
from verify_native_auth import ADMIN


def environment() -> dict:
    return {
        "source_a7_sha256": cases.A7_SHA,
        "fixture_profile": "control-only",
        "full_file_baseline": "not_exercised",
        "emulator_pid": 9001,
        "emulator_starttime": 111,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 456,
        "owned_working_image": "/repo/state/mac-runtime/native-ban-expiry-01/working.dsk",
        "owned_working_image_inode": 222,
    }


def frame(
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]],
    connection: str,
    *,
    is_reply: int = 0,
    error: int = 0,
) -> dict:
    result = decode_frame(
        bytes.fromhex(
            packet(kind, identifier, payload(values), reply=is_reply, error=error)
        )
    )
    result["connection"] = connection
    result["action"] = 0
    return result


def roster_record(uid: int, name: bytes) -> bytes:
    return uid.to_bytes(2, "big") + b"\0\0\0\0" + len(name).to_bytes(2, "big") + name


def identity_frames(protected: bool = False) -> list[dict]:
    access = cases.PROTECTED_ACCESS if protected else cases.ZERO_ACCESS
    name = cases.PROTECTED_NAME if protected else cases.ZERO_NAME
    return [
        frame(0, 1, [], "main", is_reply=1),
        frame(354, 2, [(110, ADMIN)], "main"),
        frame(109, 3, [], "main"),
        frame(0, 1, [], "target", is_reply=1),
        frame(354, 2, [(110, access)], "target"),
        frame(109, 3, [], "target"),
        frame(301, 4, [(103, b"\0\x32"), (102, name)], "main"),
        frame(
            0,
            32,
            [
                (300, roster_record(1, b"framing-fixture")),
                (300, roster_record(50, name)),
            ],
            "main",
            is_reply=1,
        ),
    ]


def probe_frames(success: bool) -> list[dict]:
    if not success:
        return [
            frame(0, 1, [(100, cases.TEMPORARY_NOTICE)], "main", is_reply=1, error=1)
        ]
    return [
        frame(0, 1, [], "main", is_reply=1),
        frame(354, 2, [(110, cases.ZERO_ACCESS)], "main"),
        frame(109, 3, [], "main"),
        frame(0, 40, [(300, roster_record(50, cases.ZERO_NAME))], "main", is_reply=1),
    ]


class FakeRecorder:
    """Only consume the real generated post-probe actions; never open sockets."""

    selected_frames: ClassVar[list[dict]] = []

    def __init__(self, plan: dict) -> None:
        self.plan = plan
        self.started = time.monotonic_ns()
        self.started_at_utc = datetime.now(timezone.utc).isoformat()
        self.sockets = {}
        self.variables = {}
        self.events: list[dict] = []
        self.frames: list[dict] = []
        self.remaining = iter(self.selected_frames)

    def execute(self, index: int, step: dict) -> None:
        event = "send" if step["op"] == "send" else step["op"]
        self.events.append(
            {
                "action": index,
                "connection": step.get("connection", "main"),
                "event": event,
                "elapsed_ns": 0,
                "hex": step.get("hex", ""),
            }
        )
        if step["op"] == "read_frame":
            self.frames.append(next(self.remaining))

    def event(self, index: int, label: str, kind: str) -> None:
        self.events.append(
            {
                "action": index,
                "connection": label,
                "event": kind,
                "elapsed_ns": 0,
                "hex": "",
            }
        )

    def streams(self) -> dict:
        return {}


class BanExpiryTests(unittest.TestCase):
    def test_production_plans_are_finite_and_byte_pinned(self) -> None:
        generated = cases.plans()
        self.assertEqual(
            set(generated),
            {"readiness", *control.EPOCH_CASES["first"], "pre-probe", "post-probe"},
        )
        self.assertEqual(len(generated["readiness"]), 18)
        self.assertEqual(len(generated["tempban"]), 24)
        self.assertEqual(generated["protected"][-3]["op"], "expect_quiet")
        for name, steps in generated.items():
            plan = cases.plan(name, steps, environment(), 15800)
            validate_plan(plan)
            self.assertEqual(plan["environment"]["full_file_baseline"], "not_exercised")
            sends = [s["hex"] for s in steps if s["op"] == "send"]
            self.assertFalse(
                any(x.startswith("000000ca") or "48545846" in x for x in sends)
            )
        for name, option in (("kick0", "007100020000"), ("tempban", "007100020001")):
            kick = [
                s
                for s in generated[name]
                if s["op"] == "send" and s["hex"].startswith("0000006e")
            ]
            self.assertEqual(len(kick), 1)
            self.assertIn("00670002{target_uid}", kick[0]["hex"])
            self.assertIn(option, kick[0]["hex"])
            self.assertNotIn("006500", kick[0]["hex"])
        self.assertEqual(generated["immediate-probe"], generated["pre-probe"])
        self.assertEqual(generated["kick0-probe"], generated["post-probe"])

    def test_plan_source_and_runtime_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plans"
            hashes = cases.write_plans(target, environment())
            self.assertEqual(set(hashes), set(cases.plans()))
            for name in hashes:
                plan, actual = control.plan_gate(target / f"{name}.json")
                self.assertEqual(actual, name)
                self.assertEqual(plan["endpoints"]["control"]["port"], 15800)
            changed = json.loads((target / "tempban.json").read_text())
            changed["steps"][0]["timeout"] = 11
            (target / "tempban.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(
                ValueError, "source plan hash changed|Prepared plan changed"
            ):
                control.plan_gate(target / "tempban.json")
        for mutation in (
            {"source_a7_sha256": "wrong"},
            {"fixture_profile": "full"},
            {"full_file_baseline": "exercised"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                cases.plan(
                    "tempban", cases.plans()["tempban"], environment() | mutation, 15800
                )
        with self.assertRaisesRegex(ValueError, "owned port"):
            cases.plan("tempban", cases.plans()["tempban"], environment(), 15500)

    def test_identity_and_notice_negative_controls(self) -> None:
        good = identity_frames()
        control.identity_before_110(good, b"\0\x32", protected=False)
        control.identity_before_110(identity_frames(True), b"\0\x32", protected=True)
        with self.assertRaisesRegex(ValueError, "UID/name"):
            control.identity_before_110(good, b"\0\x33", protected=False)
        extra = identity_frames()
        extra[-1] = frame(
            0,
            32,
            [
                (300, roster_record(1, b"framing-fixture")),
                (300, roster_record(50, cases.ZERO_NAME)),
                (300, roster_record(51, b"other")),
            ],
            "main",
            is_reply=1,
        )
        with self.assertRaisesRegex(ValueError, "roster target identity"):
            control.identity_before_110(extra, b"\0\x32", protected=False)
        with self.assertRaisesRegex(ValueError, "access"):
            control.identity_before_110(good, b"\0\x32", protected=True)
        with self.assertRaisesRegex(ValueError, "privilege22"):
            bad = identity_frames()
            bad[1] = frame(354, 2, [(110, cases.ZERO_ACCESS)], "main")
            control.identity_before_110(bad, b"\0\x32", protected=False)
        report = {
            "status": "completed",
            "completed_actions": len(cases.plans()["kick0"]),
            "frames": good
            + [
                frame(104, 4, [(101, cases.TEMPORARY_NOTICE)], "target"),
                frame(0, 33, [], "main", is_reply=1),
                frame(302, 5, [(103, b"\0\x32")], "main"),
            ],
            "variables": {"target_uid": "0032"},
            "events": [{"connection": "target", "event": "eof"}],
        }
        with self.assertRaisesRegex(ValueError, "notice cardinality"):
            control.outcome_gate(report, "kick0")

    def test_timing_bounds_and_runtime_identity(self) -> None:
        start = datetime(2026, 11, 14, tzinfo=timezone.utc)
        value = {
            "request_utc": start.isoformat(),
            "ack_utc": (start + timedelta(seconds=2)).isoformat(),
            "image_inode": 222,
            "emulator_pid": 9001,
            "emulator_start_ticks": 111,
            "emulator_sha256": "a" * 64,
            "namespace_inode": 456,
        }
        bound = control.TimingBounds.from_json(value)
        receipt = environment()
        self.assertEqual(
            bound.gate("pre", start + timedelta(seconds=1690), receipt)["host_window"],
            [1600, 1700],
        )
        self.assertEqual(
            bound.gate("post", start + timedelta(seconds=1903), receipt)["host_window"],
            [1900, 2400],
        )
        self.assertFalse(
            bound.gate("pre", start + timedelta(seconds=1690), receipt)[
                "native_getdatetime_seconds_proven"
            ]
        )
        with self.assertRaisesRegex(ValueError, "window"):
            bound.gate("pre", start + timedelta(seconds=1701), receipt)
        with self.assertRaisesRegex(ValueError, "window"):
            bound.gate("post", start + timedelta(seconds=1800), receipt)
        with self.assertRaisesRegex(ValueError, "identity changed"):
            bound.gate(
                "pre",
                start + timedelta(seconds=1690),
                receipt | {"owned_working_image_inode": 223},
            )
        with self.assertRaisesRegex(ValueError, "bracket"):
            control.TimingBounds.from_json(
                value | {"ack_utc": (start + timedelta(seconds=21)).isoformat()}
            )

    def test_fake_consumer_preserves_semantic_failure(self) -> None:
        post = cases.plan(
            "post-probe", cases.plans()["post-probe"], environment(), 15800
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(control, "Recorder", FakeRecorder),
        ):
            FakeRecorder.selected_frames = probe_frames(True)
            good = control.run_case(
                post,
                "post-probe",
                Path(tmp) / "good",
                datetime.now(timezone.utc) + timedelta(minutes=2),
            )
            self.assertEqual(good["status"], "completed")
            FakeRecorder.selected_frames = probe_frames(False) + probe_frames(True)[1:]
            bad = control.run_case(
                post,
                "post-probe",
                Path(tmp) / "bad",
                datetime.now(timezone.utc) + timedelta(minutes=2),
            )
            self.assertEqual(bad["status"], "failed")
            self.assertIn("did not succeed", bad["error"])
            self.assertEqual(
                json.loads((Path(tmp) / "bad/report.json").read_text())["status"],
                "failed",
            )
            self.assertEqual(len(bad["events"]), len(post["steps"]))

    def test_later_epochs_never_require_admin_login_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases.write_plans(root / "plans", environment())
            (root / "binary").write_bytes(b"oracle")
            now = datetime.now(timezone.utc)
            (root / "receipt.json").write_text(
                json.dumps({"deadline_utc": (now + timedelta(minutes=2)).isoformat()})
            )
            (root / "clock.json").write_text(
                json.dumps(
                    control.TimingBounds(
                        now, now, 222, 9001, 111, "a" * 64, 456
                    ).to_json()
                )
            )
            for phase, marker in (
                ("pre", "not_exercised_ban_active"),
                ("post", "not_exercised_preserve_first_lookup"),
            ):
                with (
                    self.subTest(phase=phase),
                    patch.object(control, "runtime_gate"),
                    patch.object(control.TimingBounds, "gate", return_value={}),
                    patch.object(
                        control,
                        "verify_capture",
                        side_effect=AssertionError("prior107"),
                    ),
                    patch.object(
                        control,
                        "run_case",
                        return_value={"status": "completed", "error": ""},
                    ) as run,
                    patch.object(
                        control, "ORACLE_SHA256", hashlib.sha256(b"oracle").hexdigest()
                    ),
                ):
                    result = control.run_epoch(
                        phase,
                        root / "plans",
                        None,
                        root / "receipt.json",
                        root / "binary",
                        root / phase,
                        bounds_path=root / "clock.json",
                    )
                    self.assertEqual(result["preprobe_baseline"], marker)
                    self.assertIsNone(result["readiness_report_sha256"])
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(run.call_args.args[1], f"{phase}-probe")

    def test_wrong_runner_namespace_stops_before_capture_or_socket_work(self) -> None:
        original = environment()
        deadline = datetime.now(timezone.utc) + timedelta(minutes=2)
        with (
            patch.object(control.os, "geteuid", return_value=0),
            patch.object(control.os, "stat") as stat,
            patch.object(
                control, "capture_gate", side_effect=AssertionError("capture")
            ) as capture,
        ):
            stat.return_value = SimpleNamespace(
                st_ino=original["emulator_netns_inode"] + 1
            )
            with self.assertRaisesRegex(ValueError, "Runner.*namespace"):
                control.runtime_gate(original, original, deadline)
            capture.assert_not_called()
            stat.assert_called_with("/proc/self/ns/net")
            stat.return_value = SimpleNamespace(st_ino=original["emulator_netns_inode"])
            with self.assertRaisesRegex(AssertionError, "capture"):
                control.runtime_gate(original, original, deadline)
            capture.assert_called_once_with(original)

    def test_live_runtime_binding_and_namespace_routes(self) -> None:
        original = environment()
        with (
            patch.object(control.os, "geteuid", return_value=0),
            patch.object(control, "capture_gate", side_effect=AssertionError("live")),
        ):
            for key in (
                "emulator_starttime",
                "emulator_sha256",
                "emulator_netns_inode",
                "owned_working_image_inode",
            ):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "plan"):
                    control.runtime_gate(
                        original | {key: "changed"},
                        original,
                        datetime.now(timezone.utc) + timedelta(minutes=2),
                    )
        receipt = {
            "namespace_recorder_pid": 123,
            "emulator_pid": 456,
            "emulator_netns_inode": 789,
        }

        def inode(value: int) -> SimpleNamespace:
            return SimpleNamespace(st_ino=value)

        with (
            patch.object(control.os, "stat", side_effect=[inode(789), inode(789)]),
            patch.object(
                control.subprocess,
                "run",
                side_effect=[
                    SimpleNamespace(stdout="[]"),
                    SimpleNamespace(stdout="[]"),
                    SimpleNamespace(stdout='[{"ifname":"lo"}]'),
                ],
            ) as run,
        ):
            control.namespace_gate(receipt)
            self.assertEqual(run.call_count, 3)
        with (
            patch.object(control.os, "stat", side_effect=[inode(999), inode(789)]),
            self.assertRaisesRegex(ValueError, "not in the emulator namespace"),
        ):
            control.namespace_gate(receipt)
        with (
            patch.object(control.os, "stat", side_effect=[inode(789), inode(789)]),
            patch.object(
                control.subprocess,
                "run",
                side_effect=[SimpleNamespace(stdout='[{"dst":"default"}]')],
            ),
            self.assertRaisesRegex(ValueError, "routes changed"),
        ):
            control.namespace_gate(receipt)

    def test_first_epoch_settles_before_any_account_socket(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases.write_plans(root / "plans", environment())
            ready = root / "ready"
            ready.mkdir()
            (ready / "plan.json").write_bytes(
                (root / "plans/readiness.json").read_bytes()
            )
            (ready / "report.json").write_text("{}")
            (root / "binary").write_bytes(b"oracle")
            (root / "receipt.json").write_text(
                json.dumps(
                    {
                        "deadline_utc": (
                            datetime.now(timezone.utc) + timedelta(minutes=2)
                        ).isoformat()
                    }
                )
            )
            sequence = []
            clock = control.TimingBounds(
                datetime.now(timezone.utc),
                datetime.now(timezone.utc),
                222,
                9001,
                111,
                "a" * 64,
                456,
            )

            def fake_case(_plan: dict, name: str, *_args) -> dict:
                sequence.append(name)
                return {"status": "completed", "error": ""}

            with (
                patch.multiple(
                    control,
                    runtime_gate=lambda *_: None,
                    verify_capture=lambda *_: {
                        "oracle_sha256": hashlib.sha256(b"oracle").hexdigest()
                    },
                    readiness=lambda *_: None,
                    run_case=fake_case,
                    ban_timing=lambda *_: clock,
                    ORACLE_SHA256=hashlib.sha256(b"oracle").hexdigest(),
                ),
                patch.object(
                    control.time,
                    "sleep",
                    side_effect=lambda n: sequence.append(f"settle-{n}"),
                ),
                patch.object(
                    control.time, "monotonic_ns", side_effect=[0, 35_000_000_000]
                ),
            ):
                result = control.run_epoch(
                    "first",
                    root / "plans",
                    ready,
                    root / "receipt.json",
                    root / "binary",
                    root / "out",
                )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(sequence, ["settle-35", *control.EPOCH_CASES["first"]])
            self.assertEqual(result["post_readiness_settle"]["elapsed_seconds"], 35)


if __name__ == "__main__":
    unittest.main()
