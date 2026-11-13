"""Fault controls for the portable mxd correction acceptance package."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_mxd_correction import PREFIX, verify

EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/mxd-correction-01"
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


class MxdCorrectionEvidenceTests(unittest.TestCase):
    """Reject a forged success or changed source in a copied offline corpus."""

    def test_offline_baseline(self) -> None:
        """The default verifier needs only the two-repository export."""
        self.assertEqual(verify(EVIDENCE), (7, 2))

    def test_forged_exit(self) -> None:
        """A checksum-consistent exit file cannot override retained unit facts."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "evidence"
            shutil.copytree(EVIDENCE, altered)
            (altered / "full-test.exit").write_text("2\n")
            refresh_checksum(altered, "full-test.exit")
            with self.assertRaisesRegex(ValueError, "unit-derived exit differs"):
                verify(altered)

    def test_missing_profile(self) -> None:
        """An omitted fuzz summary fails even when the file checksum is updated."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "evidence"
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
            with self.assertRaisesRegex(ValueError, "nextest profile summaries differ"):
                verify(altered)

    def test_changed_test_source(self) -> None:
        """A rehashed source and edited manifest cannot change the pinned test."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "evidence"
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
            with self.assertRaisesRegex(ValueError, "changed-source digest"):
                verify(altered)


if __name__ == "__main__":
    unittest.main()
