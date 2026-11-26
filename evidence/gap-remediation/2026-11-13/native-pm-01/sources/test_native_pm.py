"""Offline requirements for the bounded native PM preparation packet."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_pm_cases as cases
from protocol_capture import validate_plan
from verify_native_pm import check_variant


class NativePMPlanTests(unittest.TestCase):
    """Tests of the private message plan builders."""
    @classmethod
    def setUpClass(cls) -> None:
        """Load the A7 baseline plan and its runtime record."""
        cls.baseline_raw = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json"
        ).read_bytes()
        cls.baseline = cases.load_baseline(cls.baseline_raw)
        cls.runtime = cls.baseline["environment"]

    def test_bounded_plan_and_baselines(self) -> None:
        """Check that the three plans are valid, bounded and tied to the baseline."""
        plans = cases.plans(self.runtime, self.baseline_raw)
        self.assertEqual(set(plans), {"preflight", "observe", "postflight"})
        for plan in plans.values():
            validate_plan(plan)
        self.assertEqual(plans["preflight"]["steps"], plans["postflight"]["steps"])
        self.assertEqual(plans["preflight"], self.baseline)
        self.assertEqual(len(plans["preflight"]["steps"]), 29)
        self.assertEqual(plans["preflight"]["endpoints"], self.baseline["endpoints"])
        observe = plans["observe"]
        self.assertEqual(
            observe["expectation"]["baseline_plan_sha256"], cases.BASELINE_SHA256
        )
        self.assertEqual(observe["expectation"]["pm_request_count"], 7)
        self.assertLessEqual(observe["expectation"]["pm_request_count"], 20)
        self.assertEqual(observe["expectation"]["cases"], list(cases.CASES))
        self.assertEqual(
            sum(
                s["op"] == "send" and int(s["hex"][4:8], 16) == 108
                for s in observe["steps"]
            ),
            7,
        )
        self.assertFalse(
            any(
                s["op"] == "send"
                and int(s["hex"][4:8], 16) in {350, 351, 353, 203, 204}
                for s in observe["steps"]
            )
        )
        self.assertEqual(observe["steps"][-2]["op"], "close")
        self.assertEqual(observe["steps"][-1]["op"], "close")

    def test_uid_substitutions_are_current_session_only(self) -> None:
        """Check that the observe plan takes user identifiers from the current session only."""
        observe = cases.plans(self.runtime, self.baseline_raw)["observe"]
        sent = "".join(s["hex"] for s in observe["steps"] if s["op"] == "send")
        self.assertIn("{main_uid}", sent)
        self.assertIn("{peer_uid}", sent)
        self.assertNotIn("00000067", sent)

    def test_unique_case_texts_and_negative_barriers(self) -> None:
        """Check that case texts are unique and that the plan has its quiet barriers."""
        texts = [case.text for case in cases.CASES.values() if case.text]
        self.assertEqual(len(texts), len(set(texts)))
        observe = cases.plans(self.runtime, self.baseline_raw)["observe"]
        self.assertGreaterEqual(
            sum(s["op"] == "expect_quiet" for s in observe["steps"]), 14
        )

    def test_variant_rejects_wrong_option_and_missing_quote(self) -> None:
        """Check that a wrong option or a missing quote is rejected."""
        fields = {
            103: b"\0\x02",
            102: cases.MAIN,
            113: b"\0\x01",
            101: b"hello",
            214: cases.QUOTE,
        }
        check_variant(fields, b"\0\x02", cases.MAIN, 1, b"hello", cases.QUOTE)
        with self.assertRaisesRegex(ValueError, "identity/option"):
            check_variant(fields, b"\0\x02", cases.MAIN, 2, b"hello", cases.QUOTE)
        with self.assertRaisesRegex(ValueError, "field set"):
            check_variant(
                {k: v for k, v in fields.items() if k != 214},
                b"\0\x02",
                cases.MAIN,
                1,
                b"hello",
                cases.QUOTE,
            )

    def test_variant_rejects_empty_generated_text(self) -> None:
        """Check that empty generated message text is rejected."""
        fields = {103: b"\0\x02", 102: cases.PEER, 113: b"\0\x02", 101: b""}
        with self.assertRaisesRegex(ValueError, "Generated PM text"):
            check_variant(fields, b"\0\x02", cases.PEER, 2, None)

    def test_baseline_rejects_mutation_or_short_readback(self) -> None:
        """Check that a changed, shortened or mismatched baseline or runtime is rejected."""
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            cases.load_baseline(self.baseline_raw + b" ")
        short = copy.deepcopy(self.baseline)
        short["steps"] = short["steps"][:18]
        with self.assertRaisesRegex(ValueError, "29-step"):
            cases.check_baseline_structure(short)
        short = copy.deepcopy(self.baseline)
        short["steps"][21]["size"] -= 1
        with self.assertRaisesRegex(ValueError, "download sequence"):
            cases.check_baseline_structure(short)
        wrong_runtime = dict(self.runtime, emulator_pid=-1)
        with self.assertRaisesRegex(ValueError, "Runtime identity"):
            cases.plans(wrong_runtime, self.baseline_raw)

    def test_export_preserves_full_baseline_bytes(self) -> None:
        """Check that exporting the plans keeps the baseline bytes unchanged."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = root / "runtime.json"
            record.write_text(json.dumps(self.runtime))
            output = root / "plans"
            with patch.object(
                sys,
                "argv",
                [
                    "native_pm_cases.py",
                    "--runtime-record",
                    str(record),
                    "--baseline-plan",
                    str(
                        Path(__file__).resolve().parents[2]
                        / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json"
                    ),
                    "--output",
                    str(output),
                ],
            ):
                cases.main()
            self.assertEqual(
                (output / "preflight.json").read_bytes(), self.baseline_raw
            )
            self.assertEqual(
                (output / "postflight.json").read_bytes(), self.baseline_raw
            )
            self.assertEqual(
                len(json.loads((output / "observe.json").read_text())["steps"]),
                len(cases.observe()),
            )


if __name__ == "__main__":
    unittest.main()
