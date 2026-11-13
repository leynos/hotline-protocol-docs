"""Reject atomicity, permission-order, presence and comment-capacity overclaims."""

import json
import unittest
from pathlib import Path

from native_metadata_cases import specs
from verify_native_auth import reply
from verify_native_metadata import comment_boundaries, info, mutation, verify
from verify_native_mkdir import creation_quiet

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-metadata-01"
)


class MetadataTests(unittest.TestCase):
    def report(self, label: str) -> dict:
        return json.loads((BATCH / label / "report.json").read_text())

    def change_comment(self, frame: dict, value: bytes | None) -> None:
        frame["fields"] = [v for v in frame["fields"] if v["id"] != 210]
        if value is not None:
            frame["fields"].append({"id": 210, "hex": value.hex()})

    def check_case(self, label: str, report: dict) -> None:
        mutation(report, next(s for s in specs() if s["case"] == label))

    def test_complete_native_metadata_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(result["mutation_cases"], 36)
        self.assertEqual(result["boundary_writes"], 22)

    def test_conflict_error_does_not_roll_back_applied_comment(self) -> None:
        label = "file-comment-before-conflict"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), b"base-comment")
        with self.assertRaisesRegex(ValueError, "bytes"):
            self.check_case(label, report)

    def test_rename_denial_can_follow_comment_success(self) -> None:
        label = "dir-comment-only-privilege-combined"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), b"base-comment")
        with self.assertRaisesRegex(ValueError, "bytes"):
            self.check_case(label, report)

    def test_comment_denial_prevents_later_rename(self) -> None:
        label = "file-rename-only-privilege-combined"
        report = self.report("mutations/" + label)
        reply(report, 21)["error"] = 0
        with self.assertRaisesRegex(ValueError, "unexpectedly created"):
            self.check_case(label, report)

    def test_present_empty_comment_clears_and_omits_field(self) -> None:
        label = "file-empty-comment"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), b"")
        with self.assertRaisesRegex(ValueError, "presence"):
            self.check_case(label, report)

    def test_single_nul_comment_is_a_clear(self) -> None:
        label = "dir-nul-comment"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), b"\0")
        with self.assertRaisesRegex(ValueError, "presence"):
            self.check_case(label, report)

    def test_interior_nul_is_preserved(self) -> None:
        label = "file-comment-interior-nul"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), b"aa")
        with self.assertRaisesRegex(ValueError, "bytes"):
            self.check_case(label, report)

    def test_absent_comment_preserves_existing_value(self) -> None:
        label = "dir-empty-name"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, 20), None)
        with self.assertRaisesRegex(ValueError, "presence"):
            self.check_case(label, report)

    def test_200_byte_write_reads_back_199_not_200(self) -> None:
        report = self.report("boundaries/file")
        self.change_comment(reply(report, 109), b"x" * 200)
        with self.assertRaisesRegex(ValueError, "boundary"):
            comment_boundaries(report)

    def test_198_byte_value_is_not_truncated_to_197(self) -> None:
        report = self.report("boundaries/dir")
        self.change_comment(reply(report, 105), b"x" * 197)
        with self.assertRaisesRegex(ValueError, "boundary"):
            comment_boundaries(report)

    def test_noop_does_not_require_rename_or_comment_privileges(self) -> None:
        label = "file-neither-noop"
        report = self.report("mutations/" + label)
        reply(report, 12)["error"] = 1
        with self.assertRaisesRegex(ValueError, "ACK/error"):
            self.check_case(label, report)

    def test_post_mutation_silence_is_measured(self) -> None:
        label = "dir-both-new"
        report = self.report("mutations/" + label)
        plan = json.loads((BATCH / "mutations" / label / "plan.json").read_text())
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            900_000_000
        )
        with self.assertRaisesRegex(ValueError, "short"):
            creation_quiet(report, plan)

    def test_independent_admin_view_keeps_folder_size_absent(self) -> None:
        frame = reply(self.report("final"), 118)
        frame["fields"].append({"id": 207, "hex": "0000"})
        with self.assertRaisesRegex(ValueError, "presence"):
            info(frame, b"d00", True, b"base-comment")


if __name__ == "__main__":
    unittest.main()
