"""Reject source lineage and configured-executable identity conflation."""

import json
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = runpy.run_path(str(ROOT / "scripts/verify-synhx-profiles.py"))
DIRECTORY = ROOT / "evidence/gap-remediation/2026-11-13/synhx-profile-01"


class SynhxProfileTests(unittest.TestCase):
    def test_declared_versions_and_effective_profile_are_verified(self) -> None:
        result = API["verify"]()
        self.assertEqual(result["declared_server_source_version"], "0.1.48.1")
        self.assertEqual(result["client_source_version"], "0.1.48")

    def test_nonempty_vendor_delta_cannot_be_called_identical(self) -> None:
        raw = (DIRECTORY / "archives/version.c.rcs").read_bytes()
        position = raw.rfind(b"text\n@@")
        self.assertGreater(position, 0)
        changed = raw[:position] + raw[position:].replace(
            b"text\n@@", b"text\n@a1 1\nextra\n@", 1
        )
        with self.assertRaisesRegex(ValueError, "Vendor delta is not empty"):
            API["check_archive"](
                changed, (DIRECTORY / "selected/version.c.txt").read_bytes()
            )

    def test_other_default_branch_is_not_accepted_as_the_saved_vendor_branch(
        self,
    ) -> None:
        raw = (
            (DIRECTORY / "archives/version.c.rcs")
            .read_bytes()
            .replace(b"branch   1.1.1;", b"branch   1.2.1;")
        )
        with self.assertRaisesRegex(ValueError, "selected/default relationship"):
            API["check_archive"](
                raw, (DIRECTORY / "selected/version.c.txt").read_bytes()
            )

    def test_trunk_source_cannot_be_replaced_without_archive_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "Selected trunk content differs"):
            API["check_archive"](
                (DIRECTORY / "archives/version.c.rcs").read_bytes(),
                b'const char *hxd_version = "1.9";\n',
            )

    def test_client_version_cannot_replace_the_server_declared_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "profiles"
            shutil.copytree(DIRECTORY, directory)
            path = directory / "manifest.json"
            manifest = json.loads(path.read_text())
            manifest["declared_server_version"] = "0.1.48"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(
                ValueError, "Declared server source version differs"
            ):
                API["verify"](directory)

    def test_static_server_and_tested_client_scopes_cannot_be_collapsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "profiles"
            shutil.copytree(DIRECTORY, directory)
            path = directory / "manifest.json"
            manifest = json.loads(path.read_text())
            manifest["applicability"] = manifest["applicability"][-1:]
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Applicability scopes differ"):
                API["verify"](directory)


if __name__ == "__main__":
    unittest.main()
