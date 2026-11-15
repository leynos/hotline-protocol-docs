"""Reject directory-name, path, permission and cleanup overclaims."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_mkdir_cases import specs
from verify_native_mkdir import (
    catalogue,
    check_creation,
    check_root_empty,
    creation_quiet,
    listing,
    verify,
)

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-mkdir-01"
)


class MkdirTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    def check(self, name: str, report: dict) -> None:
        expected = next(c for c in specs() if c["case"] == name)
        agreement = (
            (BATCH.parent / "native-agreement-01/original-agreement.data")
            .read_bytes()
            .replace(b"\r\n", b"\r")
        )
        check_creation(report, expected, agreement)

    def frame(self, report: dict, identifier: int) -> dict:
        return next(
            f for f in report["frames"] if f["is_reply"] and f["id"] == identifier
        )

    def rename_added(self, report: dict, old: bytes, new: bytes) -> None:
        record = next(
            f
            for f in self.frame(report, 12)["fields"]
            if bytes.fromhex(f["hex"])[20:] == old
        )
        value = bytes.fromhex(record["hex"])
        record["hex"] = (value[:16] + len(new).to_bytes(4, "big") + new).hex()

    def test_complete_native_creation_matrix(self) -> None:
        result = verify(BATCH)
        self.assertEqual((result["cases"], result["paired_connections"]), (47, 53))

    def test_one_nul_byte_is_not_an_empty_name(self) -> None:
        report = self.report("name-nul-only")
        self.rename_added(report, b"\0", b"")
        with self.assertRaisesRegex(ValueError, "target or name bytes differ"):
            self.check("name-nul-only", report)

    def test_colon_normalization_must_match_native_name_bytes(self) -> None:
        report = self.report("name-colon")
        self.rename_added(report, b"co-lon", b"co:lon")
        with self.assertRaisesRegex(ValueError, "target or name bytes differ"):
            self.check("name-colon", report)

    def test_long_name_does_not_discard_the_recorded_extension(self) -> None:
        report = self.report("long-extension")
        expected = next(c for c in specs() if c["case"] == "long-extension")
        self.rename_added(
            report,
            b"ext-" + b"x" * 23 + b".txt",
            bytes.fromhex(expected["name_hex"])[:31],
        )
        with self.assertRaisesRegex(ValueError, "target or name bytes differ"):
            self.check("long-extension", report)

    def test_failed_collision_cannot_hide_listing_changes(self) -> None:
        report = self.report("existing-directory")
        self.frame(report, 12)["fields"].pop()
        with self.assertRaisesRegex(ValueError, "Failed creation changed"):
            self.check("existing-directory", report)

    def test_permission_error_precedes_existing_target_disclosure(self) -> None:
        report = self.report("low-permission-conflict")
        self.frame(report, 11)["fields"] = copy.deepcopy(
            self.frame(self.report("existing-directory"), 11)["fields"]
        )
        with self.assertRaisesRegex(ValueError, "Creation error outcome differs"):
            self.check("low-permission-conflict", report)

    def test_short_path_cannot_be_relabelled_as_strict_rejection(self) -> None:
        report = self.report("path-one-byte")
        frame = self.frame(report, 11)
        frame["error"], frame["fields"] = 1, [{"id": 100, "hex": b"bad path".hex()}]
        with self.assertRaisesRegex(ValueError, "Successful create ACK differs"):
            self.check("path-one-byte", report)

    def test_dot_component_must_address_the_literal_child_directory(self) -> None:
        report = self.report("path-dot-component")
        record = copy.deepcopy(self.frame(self.report("ascii"), 10)["fields"][0])
        self.frame(report, 10)["fields"].append(record)
        self.frame(report, 12)["fields"].append(copy.deepcopy(record))
        with self.assertRaisesRegex(ValueError, "literal empty directory"):
            self.check("path-dot-component", report)

    def test_trash_move_must_preserve_the_ordinary_child_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for group in ["native-before-cleanup", "native-after-cleanup"]:
                shutil.copytree(BATCH / group, directory / group)
            root = directory / "native-after-cleanup"
            extraction = json.loads((root / "extraction.json").read_text())
            ordinary = next(
                r
                for r in extraction["records"]
                if r["path"] == "/Trash/mothra-fs19/ordinary"
            )
            (root / (ordinary["key"] + ".data")).write_bytes(b"")
            with self.assertRaisesRegex(
                ValueError, "Trash move lost ordinary file bytes"
            ):
                catalogue(directory)

    def test_quiet_claim_requires_the_full_measured_second(self) -> None:
        report = self.report("ascii")
        plan = json.loads((BATCH / "captures/ascii/plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        previous = [e for e in report["events"] if e["action"] < event["action"]][-1]
        event["elapsed_ns"] = previous["elapsed_ns"] + 500_000_000
        with self.assertRaisesRegex(ValueError, "short creation quiet"):
            creation_quiet(report, plan)

    def test_absent_empty_root_inputs_cannot_be_called_idempotent_success(self) -> None:
        report = json.loads((BATCH / "root-empty/report.json").read_text())
        initial = listing(self.frame(report, 10))
        frame = self.frame(report, 20)
        frame["error"], frame["fields"] = 0, []
        with self.assertRaisesRegex(ValueError, "Empty-root creation outcome differs"):
            check_root_empty(report, initial)

    def test_permission_cases_cannot_be_dropped_from_the_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = json.loads((BATCH / "manifest.json").read_text())
            manifest["cases"].remove("low-permission-new")
            (directory / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(
                ValueError, "Creation matrix inventory differs"
            ):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
