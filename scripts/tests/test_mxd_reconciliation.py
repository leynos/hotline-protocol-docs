"""Mutation checks for the portable mxd evidence verifier."""

import json
import shutil
from pathlib import Path

import pytest
from verify_mxd_reconciliation import verify

# scripts/tests sits two levels below the repository root that holds evidence/.
EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/delegated-mxd-01"
)


class MxdReconciliationTests:
    """Reject changed source and result claims in an exported evidence copy."""

    def test_verified_run_and_mutated_log(self, tmp_path: Path) -> None:
        """Accept 55 recorded passes and reject a forged pass count."""
        assert verify(EVIDENCE) == 55, "the recorded run no longer passes 55 tests"
        altered = tmp_path / "altered"
        shutil.copytree(EVIDENCE, altered)
        log = altered / "compat-tests.log"
        log.write_text(log.read_text().replace("31 passed", "30 passed"))
        with pytest.raises(ValueError, match="test counts differ"):
            verify(altered)

    def test_mutated_source_snapshot_is_rejected(self, tmp_path: Path) -> None:
        """Reject a changed frozen source without an mxd checkout present."""
        altered = tmp_path / "altered"
        shutil.copytree(EVIDENCE, altered)
        manifest = json.loads((altered / "manifest.json").read_text())
        snapshot = altered / manifest["inputs"][0]["snapshot"]
        snapshot.write_bytes(snapshot.read_bytes() + b"\nmutation\n")
        with pytest.raises(ValueError, match="source snapshot hash mismatch"):
            verify(altered)
