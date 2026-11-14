"""Fault controls for the isolated settings persistence plan and gates."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import native_settings_persistence as runner
import native_settings_persistence_cases as cases
from protocol_capture import Recorder, digest, verify_capture


class PersistencePreparationTests(unittest.TestCase):
    def test_fixed_login_reused_and_three_bounded_transitions(self) -> None:
        plans = cases.plans(
            {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
        )
        before = plans["phase1"]["steps"]
        after = plans["phase2"]["steps"]
        self.assertEqual(
            [
                step
                for step in before
                if step["op"] == "send" and step["hex"].startswith("0000006b")
            ],
            [
                step
                for step in after
                if step["op"] == "send" and step["hex"].startswith("0000006b")
            ],
        )
        self.assertEqual(
            sum(
                step["hex"].startswith("00000130")
                for step in before
                if step["op"] == "send"
            ),
            3,
        )
        self.assertEqual(
            [stage["label"] for stage in plans["phase1"]["expectation"]["stages"]],
            ["enable", "disable", "reenable"],
        )
        self.assertTrue(plans["phase1"]["expectation"]["stages"][-1]["auto"])
        self.assertFalse(any(step["op"] == "close" for step in before))
        for plan, count in ((plans["phase1"], 64), (plans["phase2"], 26)):
            self.assertEqual(plan["expectation"]["observation_actions"], count)
            self.assertEqual(
                [(step["op"], step["connection"]) for step in plan["steps"][-2:]],
                [("read_eof", "subject"), ("read_eof", "main")],
            )
        self.assertEqual(
            plans["phase1"]["environment"]["full_file_baseline"], "not_exercised"
        )

    def test_bad_readiness_stops_before_recorder(self) -> None:
        with (
            patch.object(
                runner, "Recorder", side_effect=AssertionError("opened socket")
            ),
            self.assertRaisesRegex(ValueError, "readiness"),
        ):
            runner.gate_readiness({"status": "failed"}, {})

    def test_wrong_subject_identity_blocks_pm(self) -> None:
        plan = cases.plans(
            {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
        )["phase1"]
        action = plan["expectation"]["identity_action"]

        def frame(
            connection: str, kind: int, fields: dict[int, bytes], *, index: int = 0
        ) -> dict:
            return {
                "action": index,
                "connection": connection,
                "type": kind,
                "is_reply": int(kind == 0),
                "id": 1,
                "error": 0,
                "fields": [
                    {"id": key, "hex": value.hex()} for key, value in fields.items()
                ],
            }

        report = {
            "frames": [
                frame("main", 0, {}),
                frame("main", 354, {}),
                frame("main", 109, {}),
                frame("main", 0, {}, index=8),
                frame("subject", 0, {}),
                frame("subject", 354, {110: runner.ADMIN}),
                frame("subject", 109, {}),
                frame(
                    "main",
                    301,
                    {103: b"\0\2", 102: b"wrong", 104: b"\0\3"},
                    index=action,
                ),
            ]
        }
        report["frames"][3]["id"] = 10
        with (
            patch.object(runner, "login_gate"),
            patch.object(
                runner,
                "roster",
                return_value=[{"name_hex": b"framing-fixture".hex(), "uid": 1}],
            ),
            self.assertRaisesRegex(ValueError, "identity"),
        ):
            runner.gate_identity(report, plan)

    def test_wrong_automatic_text_is_not_an_enabled_witness(self) -> None:
        stage = cases.plans(
            {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
        )["phase1"]["expectation"]["stages"][0]
        start = stage["pm_action"]

        def frame(
            action: int,
            connection: str,
            kind: int,
            values: dict[int, bytes],
            *,
            reply: bool = False,
        ) -> dict:
            return {
                "action": action,
                "connection": connection,
                "type": kind,
                "is_reply": int(reply),
                "id": stage["pm_id"],
                "error": 0,
                "fields": [
                    {"id": key, "hex": value.hex()} for key, value in values.items()
                ],
            }

        report = {
            "completed_actions": start + 4,
            "frames": [
                frame(start + 1, "main", 0, {}, reply=True),
                frame(
                    start + 2,
                    "main",
                    104,
                    {103: b"\0\2", 102: cases.MARKER_NAME, 113: b"\0\4", 101: b"wrong"},
                ),
                frame(
                    start + 3,
                    "subject",
                    104,
                    {
                        103: b"\0\1",
                        102: b"framing-fixture",
                        113: b"\0\1",
                        101: bytes.fromhex(stage["pm_text_hex"]),
                    },
                ),
            ],
        }
        with self.assertRaisesRegex(ValueError, "Automatic PM feedback"):
            runner.gate_pm(report, start, b"\0\2", b"\0\1", phase=1, stage=stage)

    def test_changed_301_blocks_dependent_pm(self) -> None:
        plan = cases.plans(
            {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
        )["phase1"]
        report = {"frames": []}
        with self.assertRaisesRegex(ValueError, "301"):
            runner.gate_update(report, plan, b"\0\2")

    def test_runner_serialization_passes_generic_capture_gate(self) -> None:
        class OfflineRecorder(Recorder):
            def execute(self, action: int, step: dict) -> None:
                name = step["connection"]
                if step["op"] == "connect":
                    self.sockets[name] = Mock()
                    self.event(action, name, "connect")
                elif step["op"] == "read_eof":
                    self.event(action, name, "eof")
                else:
                    raise AssertionError("Unexpected offline action")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "oracle-fixture.bin"
            binary.write_bytes(b"offline oracle identity fixture")
            oracle = digest(binary.read_bytes())
            plan = cases.plans(
                {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
            )["phase1"]
            plan["profile"] = "synthetic-tool-test"
            plan["oracle_sha256"] = oracle
            plan["steps"] = [s for s in plan["steps"] if s["op"] == "connect"] + plan[
                "steps"
            ][-2:]
            plan["expectation"]["observation_actions"] = 2
            plans = root / "plans"
            plans.mkdir()
            raw = (json.dumps(plan) + "\n").encode()
            (plans / "phase1.json").write_bytes(raw)
            (plans / "source-hashes.json").write_text(
                json.dumps({"phase1": digest(raw)})
            )
            sources = {
                name: digest((Path(runner.__file__).parent / name).read_bytes())
                for name in (
                    "native_settings_persistence_cases.py",
                    "native_settings_persistence.py",
                )
            }
            (plans / "source-code-sha256.json").write_text(json.dumps(sources))
            ready = root / "readiness"
            ready.mkdir()
            (ready / "plan.json").write_text(json.dumps(plan))
            (ready / "report.json").write_text("{}")
            receipt = root / "capture-ready.json"
            receipt.write_text('{"emulator_pid": 123}')
            output = root / "phase"
            with (
                patch.object(runner.os, "geteuid", return_value=0),
                patch.object(runner, "ORACLE_SHA256", oracle),
                patch.object(runner, "verify_plan", return_value=1),
                patch.object(
                    runner, "verify_capture", return_value={"oracle_sha256": oracle}
                ),
                patch.object(runner, "gate_readiness"),
                patch.object(runner, "capture_gate"),
                patch.object(runner, "phase_gate", return_value=None),
                patch.object(runner, "Recorder", OfflineRecorder),
            ):
                result = runner.run_gated(
                    plans / "phase1.json", ready, receipt, binary, output
                )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["completed_actions"], 4)
            self.assertEqual(verify_capture(output)["completed_actions"], 4)
            with (
                patch.object(runner, "verify_plan", return_value=1),
                patch.object(runner, "phase_gate", return_value=None),
            ):
                self.assertEqual(
                    runner.semantic(result, plan)["status"], "verified_phase_only"
                )
                missing = {
                    **result,
                    "events": [
                        e
                        for e in result["events"]
                        if not (e["event"] == "eof" and e["connection"] == "main")
                    ],
                }
                with self.assertRaisesRegex(ValueError, "Owned socket EOFs"):
                    runner.semantic(missing, plan)
            report_path = output / "report.json"
            result["completed_actions"] = 3
            report_path.write_text(json.dumps(result) + "\n")
            (output / "checksums.sha256").write_text(
                f"{digest(raw)}  plan.json\n{digest(report_path.read_bytes())}  report.json\n"
            )
            with self.assertRaisesRegex(ValueError, "Incomplete plan"):
                verify_capture(output)


if __name__ == "__main__":
    unittest.main()
