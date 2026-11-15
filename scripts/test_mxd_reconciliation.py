"""Mutation checks for the portable mxd evidence verifier."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_mxd_reconciliation import verify

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/delegated-mxd-01"
)


class MxdReconciliationTests(unittest.TestCase):
    """Reject changed source and result claims in an exported evidence copy."""

    def test_verified_run_and_mutated_log(self) -> None:
        """Accept 55 recorded passes and reject a forged pass count."""
        self.assertEqual(verify(EVIDENCE), 55)
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "altered"
            shutil.copytree(EVIDENCE, altered)
            log = altered / "compat-tests.log"
            log.write_text(log.read_text().replace("31 passed", "30 passed"))
            with self.assertRaisesRegex(ValueError, "test counts differ"):
                verify(altered)

    def test_mutated_source_snapshot_is_rejected(self) -> None:
        """Reject a changed frozen source without an mxd checkout present."""
        with tempfile.TemporaryDirectory() as temp:
            altered = Path(temp) / "altered"
            shutil.copytree(EVIDENCE, altered)
            manifest = json.loads((altered / "manifest.json").read_text())
            snapshot = altered / manifest["inputs"][0]["snapshot"]
            snapshot.write_bytes(snapshot.read_bytes() + b"\nmutation\n")
            with self.assertRaisesRegex(ValueError, "source snapshot hash mismatch"):
                verify(altered)


if __name__ == "__main__":
    unittest.main()
