"""Semantic fault controls for the frozen native liveness corpus."""

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_control_readiness
import verify_native_liveness as witness


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LivenessCorpus(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / witness.SCHEMA
        shutil.copytree(witness.CORPUS, self.corpus)

    def refresh(self) -> None:
        files = {
            str(path.relative_to(self.corpus)): digest(path)
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"] = files
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{value}  {name}\n" for name, value in sorted(files.items()))
        )

    def change_json(self, name: str, change) -> None:
        path = self.corpus / name
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh()

    def rejected(self, reason: str) -> None:
        with self.assertRaisesRegex(ValueError, reason):
            witness.verify(self.corpus)

    def test_baseline(self) -> None:
        witness.verify(self.corpus)

    def test_frozen_imports_restore_after_success_and_semantic_failure(self) -> None:
        original = sys.modules["native_control_readiness"]
        original_path = sys.path.copy()
        original_bytecode = sys.dont_write_bytecode
        witness.verify(self.corpus)
        self.assertIs(sys.modules["native_control_readiness"], original)
        self.assertIs(original, native_control_readiness)
        with patch("native_control_readiness.login_gate") as mocked:
            self.assertIs(original.login_gate, mocked)
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report.__setitem__("status", "failed"),
        )
        self.rejected("Complete custom case identity")
        self.assertIs(sys.modules["native_control_readiness"], original)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(sys.dont_write_bytecode, original_bytecode)
        with patch("native_control_readiness.login_gate") as mocked:
            self.assertIs(original.login_gate, mocked)

    def test_observer_uid_change(self) -> None:
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: next(
                frame
                for frame in report["frames"]
                if frame["connection"] == "o" and frame["type"] == 302
            )["fields"][0].update(hex="ffff"),
        )
        self.rejected("302 UID|Decoded|frame")

    def test_eof_label_change(self) -> None:
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report["window_status"].update(a="bounded_no_eof"),
        )
        self.rejected("Window socket outcome")

    def test_operation_timing_change(self) -> None:
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report["operations"][10].update(
                actual_elapsed_ns=report["operations"][10]["actual_elapsed_ns"]
                + 10_000_000_000
            ),
        )
        self.rejected("Scheduled time")

    def test_packet_byte_change(self) -> None:
        path = self.corpus / "raw/lab-guest.pcap"
        value = bytearray(path.read_bytes())
        index = value.find(bytes.fromhex("54525450484f544c"))
        self.assertGreater(index, 0)
        value[index + 5] ^= 1
        path.write_bytes(value)
        self.refresh()
        self.rejected("packet/report bytes|Conflicting TCP retransmission|TRTP")

    def test_missing_flow(self) -> None:
        self.change_json(
            "raw/parent-paired-stream-review.json",
            lambda review: review["flows"].pop(),
        )
        self.rejected("paired-stream review")

    def test_wrong_capture_namespace(self) -> None:
        self.change_json(
            "raw/capture-ready.json",
            lambda receipt: receipt.update(emulator_netns="net:[1]"),
        )
        self.rejected("runtime or fixed deadline")

    def test_deadline_change(self) -> None:
        self.change_json(
            "raw/host-ready.json",
            lambda ready: ready.update(deadline_utc="2026-11-14T08:18:11+00:00"),
        )
        self.rejected("host managed recorder")

    def test_stopped_fork_change(self) -> None:
        self.change_json(
            "raw/stopped-forks.json",
            lambda proof: next(iter(proof["files"].values())).update(sha256="0" * 64),
        )
        self.rejected("Stopped named fork")

    def test_primary_syn_added(self) -> None:
        primary = self.corpus / "raw/primary-syn.pcap"
        namespace = (self.corpus / "raw/lab-namespace.pcap").read_bytes()
        first_length = int.from_bytes(namespace[24 + 8 : 24 + 12], "little")
        primary.write_bytes(
            primary.read_bytes() + namespace[24 : 24 + 16 + first_length]
        )
        self.refresh()
        self.rejected("Primary-port SYN capture")

    def test_recorder_drop(self) -> None:
        path = self.corpus / "raw/c92-recorder-terminal-journal.log"
        value = path.read_text().replace(
            "0 packets dropped by kernel", "1 packets dropped by kernel", 1
        )
        path.write_text(value)
        self.refresh()
        self.rejected("Recorder drops")

    def test_frozen_source_change(self) -> None:
        path = self.corpus / "sources/protocol/native_liveness_cases.py"
        path.write_text(path.read_text() + "\n# altered snapshot\n")
        self.refresh()
        self.rejected("Frozen dependency")


if __name__ == "__main__":
    unittest.main()
