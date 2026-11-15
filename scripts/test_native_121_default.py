"""Offline fault controls for delayed-121 default-response gates."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import native_121_default_cases as cases
import verify_native_121_default as verifier

BASELINE = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json"
)


def frame(values: dict[int, bytes]) -> dict:
    return {
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()]
    }


class Delayed121Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = BASELINE.read_bytes()
        cls.baseline = cases.load_baseline(cls.raw)
        cls.plan = cases.plans(cls.baseline["environment"], cls.raw)["observe"]

    def test_exact_two_case_plan_and_full_baseline(self) -> None:
        plans = cases.plans(self.baseline["environment"], self.raw)
        self.assertEqual(plans["preflight"], self.baseline)
        self.assertEqual(plans["postflight"], self.baseline)
        self.assertEqual(len(self.baseline["steps"]), 29)
        self.assertEqual(
            [c["label"] for c in verifier.layout(self.plan)], ["absent", "empty"]
        )
        self.assertEqual(self.plan["expectation"]["pm_request_count"], 2)
        wrong = copy.deepcopy(self.plan)
        wrong["steps"][17]["hex"] = cases.packet(121, 20)
        with self.assertRaisesRegex(ValueError, "steps/cases"):
            verifier.layout(wrong)

    def test_wrong_default_text_and_subject_uid_rejected(self) -> None:
        uid, name = b"\0\x32", b"A35-absent-215"
        good = {103: uid, 102: name, 113: b"\0\4", 101: cases.DEFAULT}
        verifier.check_auto(frame(good), uid, name)
        wrong = dict(good)
        wrong[101] = b"stale"
        with self.assertRaisesRegex(ValueError, "default text"):
            verifier.check_auto(frame(wrong), uid, name)
        announcement = {
            "action": 19,
            "connection": "main",
            "type": 301,
            **frame({103: b"\0\x20", 102: name, 104: b"\0\7"}),
        }
        with self.assertRaisesRegex(ValueError, "301 identity"):
            verifier.subject_uid(
                {"frames": [announcement]},
                self.plan["expectation"]["cases"][0],
                b"\0\x20",
            )

    def test_first_bad_identity_and_case_stop_before_dependent_work(self) -> None:
        class FakeRecorder:
            executed: ClassVar[list[int]]

            def __init__(self, plan: dict) -> None:
                self.events, self.frames, self.sockets = [], [], {}
                self.started_at_utc = "offline"

            def execute(self, index: int, step: dict) -> None:
                self.executed.append(index)

            def streams(self) -> dict:
                return {}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "plan.json").write_text(json.dumps(self.plan))
            (root / "binary").write_bytes(b"offline")
            for stop in (8, 19, 38):
                FakeRecorder.executed = []

                def fail_at(
                    report: dict, plan: dict, index: int, cutoff: int = stop
                ) -> str | None:
                    if index == cutoff:
                        raise ValueError(f"bad gate {cutoff}")
                    return None

                with (
                    patch.object(verifier, "Recorder", FakeRecorder),
                    patch.object(verifier, "digest", return_value=cases.ORACLE_SHA256),
                    patch.object(verifier, "gate", side_effect=fail_at),
                ):
                    result = verifier.run_gated(
                        root / "plan.json",
                        root / "binary",
                        BASELINE,
                        root / f"stop-{stop}",
                    )
                self.assertEqual(result["status"], "failed")
                self.assertEqual(FakeRecorder.executed[-1], stop)
                self.assertTrue((root / f"stop-{stop}" / "report.json").exists())
                self.assertTrue((root / f"stop-{stop}" / "stage-gates.json").exists())


if __name__ == "__main__":
    unittest.main()
