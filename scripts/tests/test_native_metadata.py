"""Reject atomicity, permission-order, presence and comment-capacity overclaims."""

import json
import typing as typ
from pathlib import Path

import pytest
from native_metadata_cases import specs
from verify_native_auth import reply
from verify_native_metadata import comment_boundaries, info, mutation, verify
from verify_native_mkdir import creation_quiet

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-metadata-01"
)
MUTATION_CASES = 36
BOUNDARY_WRITES = 22
COMMENT_FIELD = 210
FILE_SIZE_FIELD = 207
MUTATION_ACK = 12  # the reply to the account write
OLD_NAME_READ = 20  # the read of the name before the write
NEW_NAME_READ = 21  # the read of the name after the write
FILE_BOUNDARY_200_READBACK = 109  # the readback of the 200-byte file comment
DIR_BOUNDARY_198_READBACK = 105  # the readback of the 198-byte folder comment
FOLDER_FINAL_READ = 118  # the final read of a folder row
OVERSIZED_COMMENT_BYTES = 200
TRUNCATED_READBACK_BYTES = 197
QUIET_SHORTFALL_NS = 900_000_000  # elapsed time removed from the quiet window
ZERO_SIZE_HEX = "0000"


class MetadataTests:
    """Reject atomicity, permission-order, presence and comment-capacity overclaims."""

    def report(self, label: str) -> Report:
        """Load the report of one retained metadata case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / label / "report.json").read_text())

    def change_comment(self, frame: Report, value: bytes | None) -> None:
        """Set or remove the comment field of a reply."""
        frame["fields"] = [v for v in frame["fields"] if v["id"] != COMMENT_FIELD]
        if value is not None:
            frame["fields"].append({"id": COMMENT_FIELD, "hex": value.hex()})

    def check_case(self, label: str, report: Report) -> None:
        """Check one mutation case of the table against the report."""
        mutation(report, next(s for s in specs() if s["case"] == label))

    def test_complete_native_metadata_corpus(self) -> None:
        """The retained corpus verifies, with its mutation and boundary counts."""
        result = verify(BATCH)
        assert result["mutation_cases"] == MUTATION_CASES, "expected the 36 cases"
        assert result["boundary_writes"] == BOUNDARY_WRITES, "expected the 22 writes"

    def test_conflict_error_does_not_roll_back_applied_comment(self) -> None:
        """A conflict error does not undo the comment that was already applied."""
        label = "file-comment-before-conflict"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), b"base-comment")
        with pytest.raises(ValueError, match="bytes"):
            self.check_case(label, report)

    def test_rename_denial_can_follow_comment_success(self) -> None:
        """A denied rename may follow a comment write that succeeded."""
        label = "dir-comment-only-privilege-combined"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), b"base-comment")
        with pytest.raises(ValueError, match="bytes"):
            self.check_case(label, report)

    def test_comment_denial_prevents_later_rename(self) -> None:
        """A denied comment write is not followed by a rename to the new name."""
        label = "file-rename-only-privilege-combined"
        report = self.report("mutations/" + label)
        reply(report, NEW_NAME_READ)["error"] = 0
        with pytest.raises(ValueError, match="unexpectedly created"):
            self.check_case(label, report)

    def test_present_empty_comment_clears_and_omits_field(self) -> None:
        """An empty comment clears the entry and omits the comment field."""
        label = "file-empty-comment"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), b"")
        with pytest.raises(ValueError, match="presence"):
            self.check_case(label, report)

    def test_single_nul_comment_is_a_clear(self) -> None:
        """A single NUL comment is treated as a clear."""
        label = "dir-nul-comment"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), b"\0")
        with pytest.raises(ValueError, match="presence"):
            self.check_case(label, report)

    def test_interior_nul_is_preserved(self) -> None:
        """A comment with an interior NUL is kept as its bytes."""
        label = "file-comment-interior-nul"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), b"aa")
        with pytest.raises(ValueError, match="bytes"):
            self.check_case(label, report)

    def test_absent_comment_preserves_existing_value(self) -> None:
        """An absent comment field leaves the existing comment in place."""
        label = "dir-empty-name"
        report = self.report("mutations/" + label)
        self.change_comment(reply(report, OLD_NAME_READ), None)
        with pytest.raises(ValueError, match="presence"):
            self.check_case(label, report)

    def test_200_byte_write_reads_back_199_not_200(self) -> None:
        """A 200-byte comment reads back as 199 bytes, not 200."""
        report = self.report("boundaries/file")
        self.change_comment(
            reply(report, FILE_BOUNDARY_200_READBACK),
            b"x" * OVERSIZED_COMMENT_BYTES,
        )
        with pytest.raises(ValueError, match="boundary"):
            comment_boundaries(report)

    def test_198_byte_value_is_not_truncated_to_197(self) -> None:
        """A 198-byte folder comment is not truncated to 197 bytes."""
        report = self.report("boundaries/dir")
        self.change_comment(
            reply(report, DIR_BOUNDARY_198_READBACK),
            b"x" * TRUNCATED_READBACK_BYTES,
        )
        with pytest.raises(ValueError, match="boundary"):
            comment_boundaries(report)

    def test_noop_does_not_require_rename_or_comment_privileges(self) -> None:
        """A no-op write needs neither the rename nor the comment privilege."""
        label = "file-neither-noop"
        report = self.report("mutations/" + label)
        reply(report, MUTATION_ACK)["error"] = 1
        with pytest.raises(ValueError, match="ACK/error"):
            self.check_case(label, report)

    def test_post_mutation_silence_is_measured(self) -> None:
        """The silence after a mutation is measured, and a short one is refused."""
        label = "dir-both-new"
        report = self.report("mutations/" + label)
        plan = json.loads((BATCH / "mutations" / label / "plan.json").read_text())
        quiet = next(e for e in report["events"] if e["event"] == "quiet")
        quiet["elapsed_ns"] -= QUIET_SHORTFALL_NS
        with pytest.raises(ValueError, match="short"):
            creation_quiet(report, plan)

    def test_independent_admin_view_keeps_folder_size_absent(self) -> None:
        """A folder's size field stays absent in the administrator's view."""
        frame = reply(self.report("final"), FOLDER_FINAL_READ)
        frame["fields"].append({"id": FILE_SIZE_FIELD, "hex": ZERO_SIZE_HEX})
        with pytest.raises(ValueError, match="presence"):
            info(frame, b"d00", folder=True, comment=b"base-comment")
