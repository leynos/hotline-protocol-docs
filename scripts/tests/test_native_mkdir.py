"""Reject directory-name, path, permission and cleanup overclaims."""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
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
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-mkdir-01"
)
CASES = 47
PAIRED_CONNECTIONS = 53
HALF_SECOND_NS = 500_000_000  # half of the one-second quiet interval


class MkdirTests:
    """Reject directory-name, path, permission and cleanup overclaims."""

    @staticmethod
    def report(name: str) -> dict[str, typ.Any]:
        """Load the report of one retained creation case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    @staticmethod
    def check(name: str, report: dict[str, typ.Any]) -> None:
        """Check one creation report against the planned case called ``name``."""
        expected = next(c for c in specs() if c["case"] == name)
        agreement = (
            (BATCH.parent / "native-agreement-01/original-agreement.data")
            .read_bytes()
            .replace(b"\r\n", b"\r")
        )
        check_creation(report, expected, agreement)

    @staticmethod
    def frame(report: dict[str, typ.Any], identifier: int) -> dict[str, typ.Any]:
        """Find the one reply frame with ``identifier`` in a report.

        Returns
        -------
        dict[str, typing.Any]
            The reply frame.
        """
        return next(
            f for f in report["frames"] if f["is_reply"] and f["id"] == identifier
        )

    def rename_added(self, report: dict[str, typ.Any], old: bytes, new: bytes) -> None:
        """Rename the added folder record of a report from ``old`` to ``new``."""
        record = next(
            f
            for f in self.frame(report, 12)["fields"]
            if bytes.fromhex(f["hex"])[20:] == old
        )
        value = bytes.fromhex(record["hex"])
        record["hex"] = (value[:16] + len(new).to_bytes(4, "big") + new).hex()

    def test_complete_native_creation_matrix(self) -> None:
        """The retained creation matrix verifies with all of its connections."""
        result = verify(BATCH)
        assert (result["cases"], result["paired_connections"]) == (
            CASES,
            PAIRED_CONNECTIONS,
        ), "the creation matrix or its paired connections differ"

    def test_one_nul_byte_is_not_an_empty_name(self) -> None:
        """A name of one NUL byte is not treated as an empty name."""
        report = self.report("name-nul-only")
        self.rename_added(report, b"\0", b"")
        with pytest.raises(ValueError, match="target or name bytes differ"):
            self.check("name-nul-only", report)

    def test_colon_normalization_must_match_native_name_bytes(self) -> None:
        """Colon normalisation must match the bytes the native listing holds."""
        report = self.report("name-colon")
        self.rename_added(report, b"co-lon", b"co:lon")
        with pytest.raises(ValueError, match="target or name bytes differ"):
            self.check("name-colon", report)

    def test_long_name_does_not_discard_the_recorded_extension(self) -> None:
        """A long name keeps the extension that the native listing recorded."""
        report = self.report("long-extension")
        expected = next(c for c in specs() if c["case"] == "long-extension")
        self.rename_added(
            report,
            b"ext-" + b"x" * 23 + b".txt",
            bytes.fromhex(expected["name_hex"])[:31],
        )
        with pytest.raises(ValueError, match="target or name bytes differ"):
            self.check("long-extension", report)

    def test_failed_collision_cannot_hide_listing_changes(self) -> None:
        """A refused creation that changed the listing is refused."""
        report = self.report("existing-directory")
        self.frame(report, 12)["fields"].pop()
        with pytest.raises(ValueError, match="Failed creation changed"):
            self.check("existing-directory", report)

    def test_permission_error_precedes_existing_target_disclosure(self) -> None:
        """A low-permission refusal is not replaced by a disclosure of the target."""
        report = self.report("low-permission-conflict")
        self.frame(report, 11)["fields"] = copy.deepcopy(
            self.frame(self.report("existing-directory"), 11)["fields"]
        )
        with pytest.raises(ValueError, match="Creation error outcome differs"):
            self.check("low-permission-conflict", report)

    def test_short_path_cannot_be_relabelled_as_strict_rejection(self) -> None:
        """A short path that the server accepted cannot be reported as refused."""
        report = self.report("path-one-byte")
        frame = self.frame(report, 11)
        frame["error"], frame["fields"] = 1, [{"id": 100, "hex": b"bad path".hex()}]
        with pytest.raises(ValueError, match="Successful create ACK differs"):
            self.check("path-one-byte", report)

    def test_dot_component_must_address_the_literal_child_directory(self) -> None:
        """A dot component must address the literal child, not the parent."""
        report = self.report("path-dot-component")
        record = copy.deepcopy(self.frame(self.report("ascii"), 10)["fields"][0])
        self.frame(report, 10)["fields"].append(record)
        self.frame(report, 12)["fields"].append(copy.deepcopy(record))
        with pytest.raises(ValueError, match="literal empty directory"):
            self.check("path-dot-component", report)

    def test_trash_move_must_preserve_the_ordinary_child_payload(
        self, tmp_path: Path
    ) -> None:
        """Moving the owned tree to Trash must keep the ordinary file's bytes."""
        directory = tmp_path
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
        with pytest.raises(ValueError, match="Trash move lost ordinary file bytes"):
            catalogue(directory)

    def test_quiet_claim_requires_the_full_measured_second(self) -> None:
        """A quiet interval shorter than one second is refused."""
        report = self.report("ascii")
        plan = json.loads((BATCH / "captures/ascii/plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        previous = [e for e in report["events"] if e["action"] < event["action"]][-1]
        event["elapsed_ns"] = previous["elapsed_ns"] + HALF_SECOND_NS
        with pytest.raises(ValueError, match="short creation quiet"):
            creation_quiet(report, plan)

    def test_absent_empty_root_inputs_cannot_be_called_idempotent_success(
        self,
    ) -> None:
        """A creation that succeeds in the empty root is refused as an overclaim."""
        report = json.loads((BATCH / "root-empty/report.json").read_text())
        initial = listing(self.frame(report, 10))
        frame = self.frame(report, 20)
        frame["error"], frame["fields"] = 0, []
        with pytest.raises(ValueError, match="Empty-root creation outcome differs"):
            check_root_empty(report, initial)

    def test_permission_cases_cannot_be_dropped_from_the_manifest(
        self, tmp_path: Path
    ) -> None:
        """A manifest that omits a permission case is refused."""
        manifest = json.loads((BATCH / "manifest.json").read_text())
        manifest["cases"].remove("low-permission-new")
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="Creation matrix inventory differs"):
            verify(tmp_path)
