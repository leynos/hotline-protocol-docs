"""Semantic fault controls for the failed 304 first-pair corpus."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_rate304_partial import CORPUS, verify


class PartialCorpusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / CORPUS.name
        shutil.copytree(CORPUS, self.corpus)

    def refresh(self) -> None:
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"] = dict(sorted(files.items()))
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
        )

    def change_report(self, edit) -> None:
        path = self.corpus / "raw/coordinator/report.json"
        report = json.loads(path.read_text())
        edit(report)
        path.write_text(json.dumps(report, indent=2) + "\n")
        self.refresh()
        with self.assertRaises(ValueError):
            verify(self.corpus)

    def test_frozen_failure_replays(self) -> None:
        verify(self.corpus)

    def test_zero_304_is_rejected(self) -> None:
        self.change_report(lambda report: report["actions"].pop(4))

    def test_missing_late_barrier_ack_is_rejected(self) -> None:
        self.change_report(
            lambda report: report["frames"].__setitem__(
                slice(None), [f for f in report["frames"] if f["id"] != 2000]
            )
        )

    def test_wrong_icon_is_rejected(self) -> None:
        def edit(report):
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "paced" and f["type"] == 301
            )
            next(field for field in frame["fields"] if field["id"] == 104)["hex"] = (
                "0001"
            )

        self.change_report(edit)

    def test_false_observer_update_is_rejected(self) -> None:
        def edit(report):
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "observer" and f["type"] == 301
            )
            next(field for field in frame["fields"] if field["id"] == 104)["hex"] = (
                "0002"
            )

        self.change_report(edit)

    def test_early_response_timing_is_rejected(self) -> None:
        def edit(report):
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "paced" and f["type"] == 301
            )
            frame["arrival_elapsed_ns"] = 900_000_000

        self.change_report(edit)

    def test_packet_byte_mutation_is_rejected(self) -> None:
        path = self.corpus / "raw/lab-namespace.pcap"
        data = bytearray(path.read_bytes())
        needle = bytes.fromhex("00000130000003e8")
        index = data.index(needle)
        data[index + 7] ^= 1
        path.write_bytes(data)
        self.refresh()
        with self.assertRaises(ValueError):
            verify(self.corpus)

    def test_missing_flow_is_rejected(self) -> None:
        path = self.corpus / "raw/lab-namespace.pcap"
        path.write_bytes(path.read_bytes()[:24])
        self.refresh()
        with self.assertRaises(ValueError):
            verify(self.corpus)

    def test_false_terminal_success_is_rejected(self) -> None:
        self.change_report(lambda report: report.__setitem__("status", "completed"))

    def test_false_capture_drop_status_is_rejected(self) -> None:
        path = self.corpus / "raw/capture-journal-terminal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel", 1
            )
        )
        self.refresh()
        with self.assertRaises(ValueError):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
