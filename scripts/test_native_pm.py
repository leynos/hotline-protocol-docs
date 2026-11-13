"""Offline requirements for the bounded native PM preparation packet."""

import unittest

import native_pm_cases as cases
from protocol_capture import validate_plan
from verify_native_pm import check_variant


class NativePMPlanTests(unittest.TestCase):
    def test_bounded_plan_and_baselines(self) -> None:
        plans = cases.plans({"source": "offline-test"})
        self.assertEqual(set(plans), {"preflight", "observe", "postflight"})
        for plan in plans.values():
            validate_plan(plan)
        self.assertEqual(plans["preflight"]["steps"], plans["postflight"]["steps"])
        observe = plans["observe"]
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
        observe = cases.plans({"source": "offline-test"})["observe"]
        sent = "".join(s["hex"] for s in observe["steps"] if s["op"] == "send")
        self.assertIn("{main_uid}", sent)
        self.assertIn("{peer_uid}", sent)
        self.assertNotIn("00000067", sent)

    def test_unique_case_texts_and_negative_barriers(self) -> None:
        texts = [case.text for case in cases.CASES.values() if case.text]
        self.assertEqual(len(texts), len(set(texts)))
        observe = cases.plans({"source": "offline-test"})["observe"]
        self.assertGreaterEqual(
            sum(s["op"] == "expect_quiet" for s in observe["steps"]), 14
        )

    def test_variant_rejects_wrong_option_and_missing_quote(self) -> None:
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
        fields = {103: b"\0\x02", 102: cases.PEER, 113: b"\0\x02", 101: b""}
        with self.assertRaisesRegex(ValueError, "Generated PM text"):
            check_variant(fields, b"\0\x02", cases.PEER, 2, None)


if __name__ == "__main__":
    unittest.main()
