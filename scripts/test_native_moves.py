"""Reject overwrite, recursive erase, alias absence and persistence overclaims."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_move_cases import deletion_specs, move_specs
from verify_native_auth import reply
from verify_native_mkdir import creation_quiet
from verify_native_moves import catalogue, deletion, move, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-move-01"
)


class MoveTests(unittest.TestCase):
    def report(self, group: str, case: str) -> dict:
        return json.loads((BATCH / group / case / "report.json").read_text())

    def check_move(self, case: str, report: dict) -> None:
        move(report, next(s for s in move_specs() if s["case"] == case))

    def check_delete(self, case: str, report: dict) -> None:
        deletion(report, next(s for s in deletion_specs() if s["case"] == case))

    def test_complete_paired_native_move_and_delete_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["completed_reports"], result["paired_connections"]), (39, 75)
        )
        self.assertEqual(result["catalogue"]["positive_cleanup"], 70)

    def test_same_parent_move_is_a_successful_noop(self) -> None:
        report = self.report("moves", "file-same-parent")
        reply(report, 13)["error"] = 1
        with self.assertRaisesRegex(ValueError, "ACK/error"):
            self.check_move("file-same-parent", report)

    def test_existing_file_collision_does_not_overwrite(self) -> None:
        report = self.report("moves", "file-file-collision")
        reply(report, 13)["error"] = 0
        with self.assertRaisesRegex(ValueError, "ACK/error"):
            self.check_move("file-file-collision", report)

    def test_folder_cannot_move_into_its_descendant(self) -> None:
        report = self.report("moves", "dir-own-child")
        reply(report, 13)["fields"] = []
        with self.assertRaisesRegex(ValueError, "ACK/error"):
            self.check_move("dir-own-child", report)

    def test_successful_move_preserves_exposed_comment(self) -> None:
        report = self.report("moves", "file-ordinary")
        next(f for f in reply(report, 23)["fields"] if f["id"] == 210)["hex"] = (
            b"changed".hex()
        )
        with self.assertRaisesRegex(ValueError, "exposed metadata"):
            self.check_move("file-ordinary", report)

    def test_alias_listing_size_is_resolved_not_physical(self) -> None:
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
        record["hex"] = (value[:8] + (554).to_bytes(4, "big") + value[12:]).hex()
        with self.assertRaisesRegex(ValueError, "metadata/name"):
            self.check_move("file-alias-source", report)

    def test_permission_failure_does_not_remove_source_entry(self) -> None:
        report = self.report("moves", "dir-low-permission")
        reply(report, 20)["fields"].pop()
        with self.assertRaisesRegex(ValueError, "changed a listing"):
            self.check_move("dir-low-permission", report)

    def test_missing_delete_is_not_idempotent_success(self) -> None:
        report = self.report("deletions", "missing-source")
        reply(report, 12)["error"] = 0
        with self.assertRaisesRegex(ValueError, "ACK/error"):
            self.check_delete("missing-source", report)

    def test_denied_delete_keeps_directory_view(self) -> None:
        report = self.report("deletions", "denied-directory")
        reply(report, 20)["fields"].pop()
        with self.assertRaisesRegex(ValueError, "changed listing"):
            self.check_delete("denied-directory", report)

    def test_target_in_trash_does_not_make_alias_unattached(self) -> None:
        report = self.report("deletions", "alias-target-to-trash")
        next(f for f in reply(report, 30)["fields"] if f["id"] == 205)["hex"] = (
            b"Unattached Alias".hex()
        )
        with self.assertRaisesRegex(ValueError, "no longer resolves"):
            self.check_delete("alias-target-to-trash", report)

    def test_quiet_window_is_measured(self) -> None:
        report = self.report("moves", "dir-ordinary")
        plan = json.loads((BATCH / "moves/dir-ordinary/plan.json").read_text())
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            900_000_000
        )
        with self.assertRaisesRegex(ValueError, "short"):
            creation_quiet(report, plan)

    def test_nonempty_folder_move_preserves_child_data_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ["native-seeded", "native-final", "native-cleanup"]:
                shutil.copytree(BATCH / name, target / name)
            extraction = json.loads(
                (target / "native-final/extraction.json").read_text()
            )
            child = next(
                r
                for r in extraction["records"]
                if r["path"].endswith("/D/m-mv22-d00/child/leaf")
            )
            (target / "native-final" / (child["key"] + ".data")).write_bytes(
                b"lost-child"
            )
            with self.assertRaisesRegex(ValueError, "physical data/resource"):
                catalogue(target)

    def test_partial_cleanup_snapshot_cannot_drop_positive_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ["native-seeded", "native-final", "native-cleanup"]:
                shutil.copytree(BATCH / name, target / name)
            path = target / "native-cleanup/extraction.json"
            extraction = json.loads(path.read_text())
            extraction["records"].pop()
            path.write_text(json.dumps(extraction))
            with self.assertRaisesRegex(ValueError, "inventory"):
                catalogue(target)


if __name__ == "__main__":
    unittest.main()
