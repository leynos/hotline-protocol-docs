"""Mutation tests for portable mxd framing-limit evidence."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_mxd_limits import verify

EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/mxd-limits-01"
)


class MxdLimitEvidenceTests(unittest.TestCase):
    """Detect changed assertions in a copied evidence directory."""

    def test_red_and_green_results(self) -> None:
        """Retain the red failure and reject a changed green boundary count."""
        self.assertEqual(verify(EVIDENCE), 44)
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "altered"
            shutil.copytree(EVIDENCE, altered)
            log = altered / "green-framed-final.log"
            log.write_text(log.read_text().replace("17 passed", "16 passed"))
            with self.assertRaisesRegex(ValueError, "focused test count differs"):
                verify(altered)

    def test_frozen_source_mutation(self) -> None:
        """Reject altered production bytes without an adjacent mxd checkout."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "altered"
            shutil.copytree(EVIDENCE, altered)
            manifest = json.loads((altered / "manifest.json").read_text())
            source = altered / manifest["sources"][0]["snapshot"]
            source.write_bytes(source.read_bytes() + b"\nmutation\n")
            with self.assertRaisesRegex(ValueError, "source snapshot hash mismatch"):
                verify(altered)

    def test_linker_failure_cannot_be_labelled_green(self) -> None:
        """Reject a changed full-gate exit without rerun evidence."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "altered"
            shutil.copytree(EVIDENCE, altered)
            (altered / "make-test-serialized.exit").write_text("0\n")
            with self.assertRaisesRegex(ValueError, "full gate exit differs"):
                verify(altered)


if __name__ == "__main__":
    unittest.main()
