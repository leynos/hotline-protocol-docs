"""Offline contract tests for the bounded same-session 304 fixture."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import native_settings_transition_cases as cases
import verify_native_settings_transition as verifier
from verify_native_settings_transition import check_stage

BASELINE = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json"
)


def frame(
    kind: int,
    action: int,
    connection: str,
    values: dict[int, bytes],
    *,
    reply: int = 0,
    identifier: int = 0,
) -> dict:
    return {
        "type": kind,
        "action": action,
        "connection": connection,
        "is_reply": reply,
        "id": identifier,
        "error": 0,
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
    }


def sample(stage: cases.Stage, window: dict, uid: bytes = b"\0\x21") -> dict:
    name, icon = stage.expected_name, stage.expected_icon
    frames = [
        frame(301, window["first"] + 1, "main", {103: uid, 102: name, 104: icon}),
        frame(301, window["first"] + 2, "subject", {103: uid, 102: name, 104: icon}),
        frame(
            108, window["first"] + 4, "main", {}, reply=1, identifier=window["pm_id"]
        ),
        frame(
            104,
            window["first"] + 5,
            "subject",
            {
                103: b"\0\x20",
                102: b"framing-fixture",
                113: b"\0\1",
                101: bytes.fromhex(window["pm_text_hex"]),
            },
        ),
    ]
    if stage.expected_auto is not None:
        frames.append(
            frame(
                104,
                window["first"] + 6,
                "main",
                {103: uid, 102: name, 113: b"\0\4", 101: stage.expected_auto},
            )
        )
    return {"frames": frames}


class SettingsTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_raw = BASELINE.read_bytes()
        cls.baseline = cases.load_baseline(cls.baseline_raw)
        cls.plan = cases.plans(cls.baseline["environment"], cls.baseline_raw)["observe"]

    def test_each_stage_accepts_exact_synthetic_witness(self) -> None:
        for stage, window in zip(
            cases.STAGES, self.plan["expectation"]["windows"], strict=True
        ):
            with self.subTest(stage=stage.label):
                result = check_stage(
                    sample(stage, window), self.plan, window, b"\0\x21"
                )
                self.assertEqual(result["uid_hex"], "0021")

    def test_rejects_wrong_default_missing_feedback_and_wrong_301(self) -> None:
        window = self.plan["expectation"]["windows"][1]
        report = sample(cases.STAGES[1], window)
        wrong = copy.deepcopy(report)
        wrong["frames"][-1]["fields"][-1]["hex"] = b"stale-explicit".hex()
        with self.assertRaisesRegex(ValueError, "automatic text"):
            check_stage(wrong, self.plan, window, b"\0\x21")
        with self.assertRaisesRegex(ValueError, "104 delivery"):
            check_stage({"frames": report["frames"][:-1]}, self.plan, window, b"\0\x21")
        wrong = copy.deepcopy(report)
        wrong["frames"][0]["fields"][2]["hex"] = b"\0\7".hex()
        with self.assertRaisesRegex(ValueError, "301 name/icon"):
            check_stage(wrong, self.plan, window, b"\0\x21")

    def test_rejects_extra_feedback_and_stale_uid(self) -> None:
        window = self.plan["expectation"]["windows"][3]
        report = sample(cases.STAGES[3], window)
        wrong = copy.deepcopy(report)
        wrong["frames"].append(
            frame(104, window["first"] + 6, "main", {101: b"unexpected"})
        )
        with self.assertRaisesRegex(ValueError, "104 delivery"):
            check_stage(wrong, self.plan, window, b"\0\x21")
        with self.assertRaisesRegex(ValueError, "301 name/icon/UID"):
            check_stage(report, self.plan, window, b"\0\x22")

    def test_runner_stops_before_304_or_pm_on_first_bad_gate(self) -> None:
        class FakeRecorder:
            executed: ClassVar[list[int]]

            def __init__(self, plan: dict) -> None:
                self.events, self.frames, self.sockets = [], [], {}
                self.started_at_utc = "offline"

            def execute(self, index: int, step: dict) -> None:
                self.executed.append(index)

            def streams(self) -> dict:
                return {}

        saved = next(
            i for i, s in enumerate(self.plan["steps"]) if s.get("save_fields")
        )
        first = self.plan["expectation"]["windows"][0]["first"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plan.json").write_text(json.dumps(self.plan))
            (root / "binary").write_bytes(b"offline")
            for gate, stop in (("current_uids", saved), ("check_update", first + 1)):
                FakeRecorder.executed = []
                with (
                    patch.object(verifier, "Recorder", FakeRecorder),
                    patch.object(verifier, "digest", return_value=cases.ORACLE_SHA256),
                    patch.object(
                        verifier, "current_uids", return_value=(b"\0\x21", b"\0\x20")
                    ),
                    patch.object(verifier, gate, side_effect=ValueError("bad gate")),
                ):
                    report = verifier.run_gated(
                        root / "plan.json", root / "binary", root / gate
                    )
                self.assertEqual(report["status"], "failed")
                self.assertEqual(FakeRecorder.executed[-1], stop)
                self.assertTrue((root / gate / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
