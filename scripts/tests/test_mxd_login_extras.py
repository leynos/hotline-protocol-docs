"""Fault controls for the portable C11 login-extras acceptance corpus."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from verify_mxd_login_extras import CORPUS, verify

# scripts/tests sits two levels below the repository root that holds evidence/.
EVIDENCE = Path(__file__).resolve().parents[2] / CORPUS


def refresh_checksum(evidence: Path, name: str) -> None:
    """Rehash a deliberately forged file so semantic checks see it."""
    path = evidence / name
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    sums = evidence / "SHA256SUMS"
    rows = sums.read_text().splitlines()
    needle = f"  {name}"
    assert sum(row.endswith(needle) for row in rows) == 1, (
        f"the checksum row for {name} is not unique"
    )
    sums.write_text(
        "\n".join(f"{digest}{needle}" if row.endswith(needle) else row for row in rows)
        + "\n"
    )


class LoginExtrasEvidenceTests:
    """Require source, execution, and results to agree in an offline export."""

    def test_offline_baseline(self) -> None:
        """The acceptance package works without a live mxd checkout."""
        assert verify(EVIDENCE) == (7, 2), "the offline baseline counts differ"

    def test_rehashed_field_161_source_change(self, tmp_path: Path) -> None:
        """A checksum-consistent altered implementation is not the tested source."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        name = "snapshots/src/wireframe/compat_policy/mod.rs"
        path = altered / name
        source = path.read_text()
        assert "const OPAQUE_LOGIN_FIELD_161: [u8; 2] = [0, 0];" in source, (
            "the two-byte field 161 contract is missing from the source"
        )
        path.write_text(source.replace("= [0, 0];", "= [0, 1];", 1))
        manifest_path = altered / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for item in manifest["source_snapshots"]:
            if item["path"] == "src/wireframe/compat_policy/mod.rs":
                item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        refresh_checksum(altered, name)
        refresh_checksum(altered, "manifest.json")
        with pytest.raises(ValueError, match="source snapshot digest differs"):
            verify(altered)

    def test_rehashed_unit_exit_failure(self, tmp_path: Path) -> None:
        """A forged zero script exit cannot hide a failed retained unit."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        name = "full/unit-final-props.txt"
        path = altered / name
        path.write_text(
            path.read_text().replace("ExecMainStatus=0", "ExecMainStatus=2")
        )
        refresh_checksum(altered, name)
        with pytest.raises(ValueError, match="unit-derived exit differs"):
            verify(altered)

    def test_rehashed_missing_profile_count(self, tmp_path: Path) -> None:
        """A passing exit cannot replace the seven required suite summaries."""
        altered = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, altered)
        name = "full/full.log"
        path = altered / name
        text = path.read_text()
        assert "565 tests run: 565 passed, 0 skipped" in text, (
            "the first nextest profile summary is missing"
        )
        path.write_text(
            text.replace(
                "565 tests run: 565 passed, 0 skipped",
                "564 tests run: 564 passed, 0 skipped",
                1,
            )
        )
        refresh_checksum(altered, name)
        with pytest.raises(ValueError, match="seven nextest profile summaries differ"):
            verify(altered)
