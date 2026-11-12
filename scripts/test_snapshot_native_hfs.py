"""Keep failed native catalogue/fork probes distinct from successful reads."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from snapshot_native_hfs import snapshot


class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = self.root / "synthetic-image"
        self.image.write_bytes(b"synthetic tool test, not native evidence")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        for name in ["istat", "icat"]:
            (self.tools / name).write_bytes(b"synthetic executable identity")

    def test_failed_fork_and_catalogue_reads_keep_nonzero_status(self) -> None:
        stat = b"File Path: /Hotline19/Files/example\nType:\tFile\nResource fork size:\t0\n"
        results = [
            subprocess.CompletedProcess([], 0, stat, b""),
            subprocess.CompletedProcess([], 0, b"abc", b""),
            subprocess.CompletedProcess([], 1, b"", b"Attribute 4353-1 not found"),
            subprocess.CompletedProcess([], 1, b"", b"catalogue lookup failed"),
        ]
        with patch("snapshot_native_hfs.subprocess.run", side_effect=results):
            result = snapshot(
                self.image,
                self.tools,
                100,
                101,
                ["/Hotline19/Files/example"],
                self.root / "output",
            )
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["attributes"]["rsrc"]["exit_code"], 1)
        self.assertEqual(result["probes"][-1]["exit_code"], 1)
        self.assertIn("absence", result["method"])

    def test_probe_bound_and_existing_output_are_checked_before_tool_execution(
        self,
    ) -> None:
        with patch("snapshot_native_hfs.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "at most4096"):
                snapshot(
                    self.image,
                    self.tools,
                    2,
                    4098,
                    ["/example"],
                    self.root / "too-many",
                )
            self.assertFalse((self.root / "too-many").exists())
            output = self.root / "existing"
            output.mkdir()
            marker = output / "keep.txt"
            marker.write_text("retain existing evidence")
            with self.assertRaises(FileExistsError):
                snapshot(self.image, self.tools, 2, 3, ["/example"], output)
            self.assertEqual(marker.read_text(), "retain existing evidence")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
