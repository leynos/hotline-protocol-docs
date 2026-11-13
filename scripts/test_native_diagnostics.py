"""Checks for bounded 303 diagnostic plan construction and semantic validation."""

import copy
import json
import unittest
from pathlib import Path

import native_diagnostic_cases as cases
from protocol_capture import decode_frame
from verify_native_diagnostics import semantic, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01"
)


class DiagnosticPlanTests(unittest.TestCase):
    def test_uid_substitution_is_two_bytes(self) -> None:
        step = cases.diagnostic_request("main", 11, "target_uid")
        frame = decode_frame(bytes.fromhex(step["hex"].replace("{target_uid}", "1234")))
        self.assertEqual(frame["data_size"], 8)
        self.assertEqual(frame["fields"], [{"id": 103, "hex": "1234"}])

    def test_unknown_uid_substitution_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cases.diagnostic_request("main", 11, "other")

    def test_self_case_saves_uid_from_current_roster(self) -> None:
        steps, _ = cases.suites()["self"]
        roster = next(
            step for step in steps if step.get("save", {}).get("name") == "admin_uid"
        )
        self.assertEqual(roster["save"], {"name": "admin_uid", "offset": 26, "size": 2})
        self.assertIn(
            "{admin_uid}",
            next(step["hex"] for step in steps if "{admin_uid}" in step.get("hex", "")),
        )

    def test_owned_account_is_unique_and_zero_privilege(self) -> None:
        self.assertEqual(cases.ACCESS, bytes(8))
        self.assertTrue(cases.KEY.startswith(b"m-diag31-"))
        self.assertLessEqual(len(cases.KEY), 31)


class DiagnosticEvidenceTests(unittest.TestCase):
    def reports(self) -> dict:
        return {
            name: json.loads((CORPUS / name / "report.json").read_text())
            for name in ("preflight", "seed", "observe", "self", "cleanup")
        }

    def test_complete_corpus(self) -> None:
        self.assertEqual(verify(CORPUS)["completed_reports"], 5)

    def test_wrong_field_is_rejected(self) -> None:
        reports = self.reports()
        reply = next(
            f for f in reports["observe"]["frames"] if f["id"] == 10 and f["is_reply"]
        )
        reply["fields"][0]["id"] = 100
        with self.assertRaises(ValueError):
            semantic(reports)

    def test_wrong_error_is_rejected(self) -> None:
        reports = self.reports()
        reply = next(
            f
            for f in reports["observe"]["frames"]
            if f["id"] == 11 and f["is_reply"] and f["connection"] == "zero"
        )
        reply["error"] = 0
        with self.assertRaises(ValueError):
            semantic(reports)

    def test_stale_uid_cannot_be_relabelled_self(self) -> None:
        reports = self.reports()
        send = next(
            e
            for e in reports["self"]["events"]
            if e["event"] == "send" and e["action"] == 9
        )
        send["hex"] = send["hex"][:-4] + "008d"
        with self.assertRaises(ValueError):
            semantic(reports)

    def test_multiple_self_roster_candidates_are_rejected(self) -> None:
        reports = self.reports()
        roster = next(
            f for f in reports["self"]["frames"] if f["id"] == 10 and f["is_reply"]
        )
        roster["fields"].append(copy.deepcopy(roster["fields"][0]))
        with self.assertRaises(ValueError):
            semantic(reports)

    def test_diagnostic_reply_reordering_is_rejected(self) -> None:
        reports = self.reports()
        frames = reports["observe"]["frames"]
        left = next(
            i
            for i, frame in enumerate(frames)
            if frame["id"] == 10 and frame["is_reply"]
        )
        right = next(
            i
            for i, frame in enumerate(frames)
            if frame["id"] == 12 and frame["is_reply"]
        )
        frames[left], frames[right] = frames[right], frames[left]
        with self.assertRaisesRegex(ValueError, "order"):
            semantic(reports)


if __name__ == "__main__":
    unittest.main()
