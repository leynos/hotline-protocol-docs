"""Fault controls for the portable C7/C9 direct-reply acceptance corpus."""

import json
import shutil
import typing as typ

import pytest
from verify_mxd_direct_ack import DEFAULT, PREFIX, sha256, verify

if typ.TYPE_CHECKING:
    from pathlib import Path


class FaultControls:
    """Show that plausible forged acceptance records are rejected."""

    @pytest.fixture(autouse=True)
    def _copy(self, tmp_path: Path) -> None:
        """Copy the small corpus for an isolated mutation."""
        self.evidence = tmp_path / "mxd-direct-ack-02"
        shutil.copytree(DEFAULT, self.evidence)
        shutil.copytree(
            DEFAULT.parent / "mxd-direct-ack-01",
            self.evidence.parent / "mxd-direct-ack-01",
        )

    def rewrite_sums(self) -> None:
        """Keep checksums valid so tests reach semantic checks."""
        root = self.evidence
        files = sorted(
            p for p in root.rglob("*") if p.is_file() and p != root / "SHA256SUMS"
        )
        (root / "SHA256SUMS").write_text(
            "".join(f"{sha256(p)}  {PREFIX}{p.relative_to(root)}\n" for p in files)
        )

    def test_corpus_passes_offline(self) -> None:
        """Verify the unchanged exported corpus."""
        verify(self.evidence)

    def test_forged_unit_exit_is_rejected(self) -> None:
        """Reject a falsely reported successful managed unit."""
        path = self.evidence / "unit-final-props.txt"
        path.write_text(
            path.read_text().replace("ExecMainStatus=0", "ExecMainStatus=2")
        )
        self.rewrite_sums()
        with pytest.raises(ValueError, match="retained unit"):
            verify(self.evidence)

    def test_missing_suite_is_rejected(self) -> None:
        """Reject a manifest with an omitted nextest profile."""
        path = self.evidence / "full.log"
        lines = path.read_text().splitlines()
        path.write_text("\n".join(x for x in lines if "561 tests run:" not in x) + "\n")
        manifest_path = self.evidence / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["execution"]["full_log_sha256"] = sha256(path)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        self.rewrite_sums()
        with pytest.raises(ValueError, match="suite or doctest"):
            verify(self.evidence)

    def test_source_hash_mismatch_is_rejected(self) -> None:
        """Reject a candidate hash that differs from the frozen source."""
        path = self.evidence / "manifest.json"
        manifest = json.loads(path.read_text())
        name = next(iter(manifest["candidate_source_hashes"]))
        manifest["candidate_source_hashes"][name] = "0" * 64
        path.write_text(json.dumps(manifest) + "\n")
        self.rewrite_sums()
        with pytest.raises(ValueError, match="frozen candidate"):
            verify(self.evidence)
