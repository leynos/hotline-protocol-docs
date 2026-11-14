"""Semantic fault controls for the portable native board witness."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_control_readiness
from verify_native_board import CORPUS, verify


class BoardCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="native-board-corpus-")
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / CORPUS.name
        shutil.copytree(CORPUS, self.corpus)

    def refresh(self) -> None:
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest["files"] = files
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
        )

    def change_json(self, name: str, mutate) -> None:
        path = self.corpus / name
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh()

    def rejected(self, pattern: str) -> None:
        with self.assertRaisesRegex(ValueError, pattern):
            verify(self.corpus)

    def test_baseline(self) -> None:
        result = verify(self.corpus)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["board_bytes"], 65629)
        self.assertEqual(len(result["flows"]), 6)

    def test_frozen_imports_restore_after_success_and_semantic_failure(self) -> None:
        original = sys.modules["native_control_readiness"]
        original_path = sys.path.copy()
        original_bytecode = sys.dont_write_bytecode
        verify(self.corpus)
        self.assertIs(sys.modules["native_control_readiness"], original)
        self.assertIs(original, native_control_readiness)
        with patch("native_control_readiness.login_gate") as mocked:
            self.assertIs(original.login_gate, mocked)
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report.__setitem__("status", "failed"),
        )
        self.rejected("Finite custom board case")
        self.assertIs(sys.modules["native_control_readiness"], original)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(sys.dont_write_bytecode, original_bytecode)
        with patch("native_control_readiness.login_gate") as mocked:
            self.assertIs(original.login_gate, mocked)

    def test_board_byte_after_65535_rejected(self) -> None:
        path = self.corpus / "raw/stopped/MessageBoard.data"
        data = bytearray(path.read_bytes())
        data[65536] ^= 1
        path.write_bytes(data)
        self.refresh()
        self.rejected("Stopped board DATA")

    def test_wrong_report_segment_rejected(self) -> None:
        def mutate(report):
            value = report["segments_hex"][4]
            report["segments_hex"][4] = value[:-2] + (
                "00" if value[-2:] != "00" else "ff"
            )

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board segment|Whole board")

    def test_wrong_recipient_rejected(self) -> None:
        def mutate(report):
            frame = next(
                frame
                for frame in report["frames"]
                if frame["connection"] == "eligible" and frame["type"] == 102
            )
            frame["connection"] = "denied"

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Eligible|Denied|Missing|Raw|frame|102|duplicate")

    def test_post_filler_rejected(self) -> None:
        def mutate(report):
            raw = report["post_data_hex"][10]
            report["post_data_hex"][10] = raw[:-2] + (
                "00" if raw[-2:] != "00" else "ff"
            )

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board segment|Post|filler|request")

    def test_rejected_8193_claim_rejected(self) -> None:
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report["post_data_hex"].__setitem__(12, "00" * 8192),
        )
        self.rejected("Post boundary")

    def test_read_prefix_rejected(self) -> None:
        def mutate(report):
            raw = report["reads"]["12"]
            report["reads"]["12"] = ("00" if raw[:2] != "00" else "ff") + raw[2:]

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board read/prefix")

    def test_recorded_tail_rejected(self) -> None:
        def mutate(report):
            report["streams"]["sender"]["received_hex"] += "00"

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Raw stream/event|Received bytes/frame")

    def test_resource_fork_claim_rejected(self) -> None:
        path = self.corpus / "raw/stopped/board-istat.txt"
        path.write_text(
            path.read_text().replace("Resource fork size:\t0", "Resource fork size:\t1")
        )
        self.refresh()
        self.rejected("HFS path, Finder metadata")

    def test_pcap_payload_byte_rejected(self) -> None:
        path = self.corpus / "raw/lab-namespace.pcap"
        raw = path.read_bytes()
        self.assertIn(b"TRTPHOTL", raw)
        path.write_bytes(raw.replace(b"TRTPHOTL", b"TRTPH0TL", 1))
        self.refresh()
        self.rejected("PCAP/report bytes|packet/report bytes|tail")

    def test_missing_flow_rejected(self) -> None:
        path = self.corpus / "raw/lab-guest.pcap"
        path.write_bytes(path.read_bytes()[:24])
        self.refresh()
        self.rejected("packet count|SYN lifetimes")

    def test_primary_syn_rejected(self) -> None:
        path = self.corpus / "raw/primary-syn.pcap"
        path.write_bytes((self.corpus / "raw/lab-namespace.pcap").read_bytes())
        self.refresh()
        self.rejected("primary capture|Primary-port SYN")

    def test_drop_claim_rejected(self) -> None:
        path = self.corpus / "raw/capture-journal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel", 1
            )
        )
        self.refresh()
        self.rejected("Recorder zero-drop")

    def test_stopped_fork_changed_rejected(self) -> None:
        path = self.corpus / "raw/stopped/fork-sha256.txt"
        path.write_text(path.read_text().replace("26612ad4", "36612ad4", 1))
        self.refresh()
        self.rejected("Unchanged stopped named fork")

    def test_wrong_catalog_rejected(self) -> None:
        path = self.corpus / "raw/stopped/board-istat.txt"
        path.write_text(path.read_text().replace("TEXT", "BINA", 1))
        self.refresh()
        self.rejected("HFS path, Finder metadata")

    def test_deadline_rejected(self) -> None:
        self.change_json(
            "raw/capture-ready.json",
            lambda receipt: receipt.__setitem__(
                "deadline_utc", "2026-11-14T09:23:28+00:00"
            ),
        )
        self.rejected("Actual emulator, capture receipt|fixed deadline")

    def test_source_change_rejected(self) -> None:
        path = self.corpus / "sources/protocol/native_board_control.py"
        path.write_bytes(path.read_bytes() + b"\n# forged\n")
        self.refresh()
        self.rejected("Frozen source differs")

    def test_incomplete_case_rejected(self) -> None:
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report.__setitem__("status", "failed"),
        )
        self.rejected("Finite custom board case")


if __name__ == "__main__":
    unittest.main()
