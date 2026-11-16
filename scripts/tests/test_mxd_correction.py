"""Fault controls for the portable mxd correction acceptance package."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from verify_mxd_correction import PREFIX, verify

# scripts/tests sits two levels below the repository root that holds evidence/.
EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/mxd-correction-01"
)


def refresh_checksum(evidence: Path, name: str) -> None:
    """Keep corpus checksums valid so semantic controls do the rejecting."""
    target = PREFIX + name
    checksum = evidence / "SHA256SUMS"
    lines = checksum.read_text().splitlines()
    replacement = (
        f"{hashlib.sha256((evidence / name).read_bytes()).hexdigest()}  {target}"
    )
    checksum.write_text(
        "\n".join(
            replacement if line.endswith(f"  {target}") else line for line in lines
        )
        + "\n"
    )


class MxdCorrectionEvidenceTests:
    """Reject a forged success or changed source in a copied offline corpus."""

    def test_offline_baseline(self) -> None:
        """The default verifier needs only the two-repository export."""
        assert verify(EVIDENCE) == (7, 2), "the offline package must verify (7, 2)"

    def test_forged_exit(self, tmp_path: Path) -> None:
        """A checksum-consistent exit file cannot override retained unit facts."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        (altered / "full-test.exit").write_text("2\n")
        refresh_checksum(altered, "full-test.exit")
        with pytest.raises(ValueError, match="unit-derived exit differs"):
            verify(altered)

    def test_missing_profile(self, tmp_path: Path) -> None:
        """An omitted fuzz summary fails even when the file checksum is updated."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        path = altered / "full-gate-summary.txt"
        path.write_text(
            "\n".join(
                line
                for line in path.read_text().splitlines()
                if "8 tests run:" not in line
            )
            + "\n"
        )
        refresh_checksum(altered, "full-gate-summary.txt")
        with pytest.raises(ValueError, match="nextest profile summaries differ"):
            verify(altered)

    def test_changed_test_source(self, tmp_path: Path) -> None:
        """A rehashed source and edited manifest cannot change the pinned test."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        name = "inputs/final/src/db/migrations_tests.rs.txt"
        path = altered / name
        path.write_bytes(path.read_bytes() + b"\nchanged\n")
        manifest_path = altered / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest["source_snapshots"][name] = digest
        manifest["candidate_source_hashes"]["src/db/migrations_tests.rs"] = digest
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        refresh_checksum(altered, name)
        refresh_checksum(altered, "manifest.json")
        with pytest.raises(ValueError, match="changed-source digest"):
            verify(altered)
