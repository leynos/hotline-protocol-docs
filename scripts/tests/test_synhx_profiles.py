"""Reject source lineage and configured-executable identity conflation."""

import json
import runpy
import shutil
from pathlib import Path

import pytest

# scripts/tests sits two levels below the repository root that holds evidence/.
ROOT = Path(__file__).resolve().parents[2]
API = runpy.run_path(str(ROOT / "scripts/verify-synhx-profiles.py"))
DIRECTORY = ROOT / "evidence/gap-remediation/2026-11-13/synhx-profile-01"


class SynhxProfileTests:
    """Exercise the declared versions, lineage and applicability of the profile."""

    def test_declared_versions_and_effective_profile_are_verified(self) -> None:
        """The verified profile reports the declared server and client versions."""
        result = API["verify"]()
        assert result["declared_server_source_version"] == "0.1.48.1", (
            "the declared server version differs"
        )
        assert result["client_source_version"] == "0.1.48", (
            "the client source version differs"
        )

    def test_nonempty_vendor_delta_cannot_be_called_identical(self) -> None:
        """A nonempty vendor delta is refused rather than called identical."""
        raw = (DIRECTORY / "archives/version.c.rcs").read_bytes()
        position = raw.rfind(b"text\n@@")
        assert position > 0, "the vendor delta marker is absent"
        changed = raw[:position] + raw[position:].replace(
            b"text\n@@", b"text\n@a1 1\nextra\n@", 1
        )
        with pytest.raises(ValueError, match="Vendor delta is not empty"):
            API["check_archive"](
                changed, (DIRECTORY / "selected/version.c.txt").read_bytes()
            )

    def test_other_default_branch_is_not_accepted_as_the_saved_vendor_branch(
        self,
    ) -> None:
        """A default branch other than the saved vendor branch is refused."""
        raw = (
            (DIRECTORY / "archives/version.c.rcs")
            .read_bytes()
            .replace(b"branch   1.1.1;", b"branch   1.2.1;")
        )
        with pytest.raises(ValueError, match="selected/default relationship"):
            API["check_archive"](
                raw, (DIRECTORY / "selected/version.c.txt").read_bytes()
            )

    def test_trunk_source_cannot_be_replaced_without_archive_evidence(self) -> None:
        """Trunk source that differs from the archive is refused."""
        with pytest.raises(ValueError, match="Selected trunk content differs"):
            API["check_archive"](
                (DIRECTORY / "archives/version.c.rcs").read_bytes(),
                b'const char *hxd_version = "1.9";\n',
            )

    def test_client_version_cannot_replace_the_server_declared_version(
        self, tmp_path: Path
    ) -> None:
        """A client version cannot replace the declared server source version."""
        directory = tmp_path / "profiles"
        shutil.copytree(DIRECTORY, directory)
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["declared_server_version"] = "0.1.48"
        path.write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="Declared server source version differs"):
            API["verify"](directory)

    def test_static_server_and_tested_client_scopes_cannot_be_collapsed(
        self, tmp_path: Path
    ) -> None:
        """The static server scope and the tested client scope stay separate."""
        directory = tmp_path / "profiles"
        shutil.copytree(DIRECTORY, directory)
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["applicability"] = manifest["applicability"][-1:]
        path.write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="Applicability scopes differ"):
            API["verify"](directory)
