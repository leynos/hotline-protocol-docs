"""Fault controls for the isolated settings persistence plan and gates."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_settings_persistence as runner
import native_settings_persistence_cases as cases
from protocol_capture import ORACLE_SHA256, Recorder, digest, verify_capture


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

    def test_serialized_completed_eofs_pass_generic_capture_gate(self) -> None:
        plan = cases.plans(
            {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}, 15760
        )["phase2"]
        plan["steps"] = [s for s in plan["steps"] if s["op"] == "connect"] + plan[
            "steps"
        ][-2:]
        recorder = Recorder(plan)
        recorder.event(2, "subject", "eof")
        recorder.event(3, "main", "eof")
        raw = (json.dumps(plan) + "\n").encode()
        report = {
            "profile": plan["profile"],
            "native_conformance": False,
            "plan_sha256": digest(raw),
            "oracle_sha256": ORACLE_SHA256,
            "status": "completed",
            "error": "",
            "completed_actions": 4,
            "events": recorder.events,
            "streams": recorder.streams(),
            "frames": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "plan.json").write_bytes(raw)

            def save() -> None:
                data = (json.dumps(report) + "\n").encode()
                (directory / "report.json").write_bytes(data)
                (directory / "checksums.sha256").write_text(
                    f"{digest(raw)}  plan.json\n{digest(data)}  report.json\n"
                )

            save()
            self.assertEqual(verify_capture(directory)["completed_actions"], 4)
            report["completed_actions"] = 3
            save()
            with self.assertRaisesRegex(ValueError, "Incomplete plan"):
                verify_capture(directory)


if __name__ == "__main__":
    unittest.main()
