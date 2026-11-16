"""Reject overwrite, recursive erase, alias absence and persistence overclaims."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_move_cases import deletion_specs, move_specs
from verify_native_auth import reply
from verify_native_mkdir import creation_quiet
from verify_native_moves import catalogue, deletion, move, verify

# scripts/tests sits two levels below the repository root that holds evidence/.
BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-move-01"
)
COMPLETED_REPORTS = 39  # the completed captures in the retained move corpus
PAIRED_CONNECTIONS = 75  # the paired connections in the retained move corpus
POSITIVE_CLEANUP = 70  # the positive cleanup observations in the retained corpus
ALIAS_SIZE_BYTES = 554  # the alias size that the retained corpus records
QUIET_SHORTFALL_NS = 900_000_000  # the amount taken off a measured quiet window


class MoveTests:
    """Reject overwrite, recursive erase, alias absence and persistence overclaims."""

    def report(self, group: str, case: str) -> dict[str, typ.Any]:
        """Load the report of one retained move or deletion capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / group / case / "report.json").read_text())

    def check_move(self, case: str, report: dict[str, typ.Any]) -> None:
        """Check one retained move case against a report.

        Parameters
        ----------
        case : str
            The name of the move case.
        report : dict[str, typing.Any]
            The report to check.
        """
        move(report, next(s for s in move_specs() if s["case"] == case))

    def check_delete(self, case: str, report: dict[str, typ.Any]) -> None:
        """Check one retained deletion case against a report.

        Parameters
        ----------
        case : str
            The name of the deletion case.
        report : dict[str, typing.Any]
            The report to check.
        """
        deletion(report, next(s for s in deletion_specs() if s["case"] == case))

    def test_complete_paired_native_move_and_delete_corpus(self) -> None:
        """The retained move and deletion corpus verifies with all of its captures."""
        result = verify(BATCH)
        assert (result["completed_reports"], result["paired_connections"]) == (
            COMPLETED_REPORTS,
            PAIRED_CONNECTIONS,
        ), "the completed capture or paired connection count differs"
        assert result["catalogue"]["positive_cleanup"] == POSITIVE_CLEANUP, (
            "the positive cleanup observation count differs"
        )

    def test_same_parent_move_is_a_successful_noop(self) -> None:
        """A move into its own parent must not report an error."""
        report = self.report("moves", "file-same-parent")
        reply(report, 13)["error"] = 1
        with pytest.raises(ValueError, match="ACK/error"):
            self.check_move("file-same-parent", report)

    def test_existing_file_collision_does_not_overwrite(self) -> None:
        """A move onto an existing file must report the collision error."""
        report = self.report("moves", "file-file-collision")
        reply(report, 13)["error"] = 0
        with pytest.raises(ValueError, match="ACK/error"):
            self.check_move("file-file-collision", report)

    def test_folder_cannot_move_into_its_descendant(self) -> None:
        """A folder moved into its own child must report the refusal."""
        report = self.report("moves", "dir-own-child")
        reply(report, 13)["fields"] = []
        with pytest.raises(ValueError, match="ACK/error"):
            self.check_move("dir-own-child", report)

    def test_successful_move_preserves_exposed_comment(self) -> None:
        """A successful move must keep the metadata that the listing exposes."""
        report = self.report("moves", "file-ordinary")
        next(f for f in reply(report, 23)["fields"] if f["id"] == 210)["hex"] = (
            b"changed".hex()
        )
        with pytest.raises(ValueError, match="exposed metadata"):
            self.check_move("file-ordinary", report)

    def test_alias_listing_size_is_resolved_not_physical(self) -> None:
        """An alias listing must keep the resolved size and not the physical one."""
        report = self.report("moves", "file-alias-source")
        name = bytes.fromhex(
            next(s for s in move_specs() if s["case"] == "file-alias-source")[
                "name_hex"
            ]
        )
        record = next(
            f
            for f in reply(report, 21)["fields"]
            if bytes.fromhex(f["hex"])[20:] == name
        )
        value = bytes.fromhex(record["hex"])
        record["hex"] = (
            value[:8] + ALIAS_SIZE_BYTES.to_bytes(4, "big") + value[12:]
        ).hex()
        with pytest.raises(ValueError, match="metadata/name"):
            self.check_move("file-alias-source", report)

    def test_permission_failure_does_not_remove_source_entry(self) -> None:
        """A move refused for permissions must leave the source listing unchanged."""
        report = self.report("moves", "dir-low-permission")
        reply(report, 20)["fields"].pop()
        with pytest.raises(ValueError, match="changed a listing"):
            self.check_move("dir-low-permission", report)

    def test_missing_delete_is_not_idempotent_success(self) -> None:
        """A deletion of a missing entry must not report success."""
        report = self.report("deletions", "missing-source")
        reply(report, 12)["error"] = 0
        with pytest.raises(ValueError, match="ACK/error"):
            self.check_delete("missing-source", report)

    def test_denied_delete_keeps_directory_view(self) -> None:
        """A refused directory deletion must keep the directory listing."""
        report = self.report("deletions", "denied-directory")
        reply(report, 20)["fields"].pop()
        with pytest.raises(ValueError, match="changed listing"):
            self.check_delete("denied-directory", report)

    def test_target_in_trash_does_not_make_alias_unattached(self) -> None:
        """An alias whose target is in Trash must still resolve to that target."""
        report = self.report("deletions", "alias-target-to-trash")
        next(f for f in reply(report, 30)["fields"] if f["id"] == 205)["hex"] = (
            b"Unattached Alias".hex()
        )
        with pytest.raises(ValueError, match="no longer resolves"):
            self.check_delete("alias-target-to-trash", report)

    def test_quiet_window_is_measured(self) -> None:
        """A quiet window shorter than the planned one must be rejected."""
        report = self.report("moves", "dir-ordinary")
        plan = json.loads((BATCH / "moves/dir-ordinary/plan.json").read_text())
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            QUIET_SHORTFALL_NS
        )
        with pytest.raises(ValueError, match="short"):
            creation_quiet(report, plan)

    def test_nonempty_folder_move_preserves_child_data_fork(
        self, tmp_path: Path
    ) -> None:
        """A move of a non-empty folder must keep the data fork of its child."""
        target = tmp_path
        for name in ["native-seeded", "native-final", "native-cleanup"]:
            shutil.copytree(BATCH / name, target / name)
        extraction = json.loads((target / "native-final/extraction.json").read_text())
        child = next(
            r
            for r in extraction["records"]
            if r["path"].endswith("/D/m-mv22-d00/child/leaf")
        )
        (target / "native-final" / (child["key"] + ".data")).write_bytes(b"lost-child")
        with pytest.raises(ValueError, match="physical data/resource"):
            catalogue(target)

    def test_partial_cleanup_snapshot_cannot_drop_positive_observations(
        self, tmp_path: Path
    ) -> None:
        """A cleanup snapshot with a record removed must fail the inventory check."""
        target = tmp_path
        for name in ["native-seeded", "native-final", "native-cleanup"]:
            shutil.copytree(BATCH / name, target / name)
        path = target / "native-cleanup/extraction.json"
        extraction = json.loads(path.read_text())
        extraction["records"].pop()
        path.write_text(json.dumps(extraction))
        with pytest.raises(ValueError, match="inventory"):
            catalogue(target)
