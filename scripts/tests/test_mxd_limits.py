"""Mutation tests for portable mxd framing-limit evidence."""

import json
import shutil
from pathlib import Path

import pytest
from verify_mxd_limits import verify

# scripts/tests sits two levels below the repository root that holds evidence/.
EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/mxd-limits-01"
)


class MxdLimitEvidenceTests:
    """Detect changed assertions in a copied evidence directory."""

    def test_red_and_green_results(self, tmp_path: Path) -> None:
        """Retain the red failure and reject a changed green boundary count."""
        assert verify(EVIDENCE) == 44, "the retained focused run must count 44 tests"
        altered = tmp_path / "altered"
        shutil.copytree(EVIDENCE, altered)
        log = altered / "green-framed-final.log"
        log.write_text(log.read_text().replace("17 passed", "16 passed"))
        with pytest.raises(ValueError, match="focused test count differs"):
            verify(altered)

    def test_frozen_source_mutation(self, tmp_path: Path) -> None:
        """Reject altered production bytes without an adjacent mxd checkout."""
        altered = tmp_path / "altered"
        shutil.copytree(EVIDENCE, altered)
        manifest = json.loads((altered / "manifest.json").read_text())
        source = altered / manifest["sources"][0]["snapshot"]
        source.write_bytes(source.read_bytes() + b"\nmutation\n")
        with pytest.raises(ValueError, match="source snapshot hash mismatch"):
            verify(altered)

    def test_linker_failure_cannot_be_labelled_green(self, tmp_path: Path) -> None:
        """Reject a changed full-gate exit without rerun evidence."""
        altered = tmp_path / "altered"
        shutil.copytree(EVIDENCE, altered)
        (altered / "make-test-serialized.exit").write_text("0\n")
        with pytest.raises(ValueError, match="full gate exit differs"):
            verify(altered)
