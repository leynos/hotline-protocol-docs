"""Fault controls for the portable failed rate304 sequence witness."""

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
from verify_native_rate304_sequence import CORPUS, verify


class Rate304SequenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="rate304-sequence-")
        self.addCleanup(temporary.cleanup)
        self.corpus = Path(temporary.name) / CORPUS.name
        shutil.copytree(CORPUS, self.corpus)

    def refresh(self) -> None:
        manifest_path = self.corpus / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest["files"] = files
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        prefix = "evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/"
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{digest}  {prefix}{name}\n" for name, digest in sorted(files.items())
            )
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
        self.assertEqual(result["case_status"], "failed")
        self.assertEqual(len(result["flows"]), 5)
        self.assertGreaterEqual(
            result["host_timing_ns"]["subject_quiet_ns"], 70_000_000_000
        )

    def test_frozen_imports_restore_on_pass_and_failure(self) -> None:
        original = sys.modules["native_control_readiness"]
        path, bytecode = sys.path.copy(), sys.dont_write_bytecode
        verify(self.corpus)
        self.assertIs(sys.modules["native_control_readiness"], original)
        with patch("native_control_readiness.login_gate") as mocked:
            self.assertIs(original.login_gate, mocked)
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: d.__setitem__("status", "completed"),
        )
        self.rejected("Failed case status")
        self.assertIs(sys.modules["native_control_readiness"], original)
        self.assertIs(original, native_control_readiness)
        self.assertEqual(sys.path, path)
        self.assertEqual(sys.dont_write_bytecode, bytecode)

    def test_missing_update_rejected(self) -> None:
        def mutate(d):
            index = next(
                i
                for i, f in enumerate(d["frames"])
                if f["connection"] == "paced" and f["type"] == 301
            )
            del d["frames"][index]

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw event/action/frame boundary|Received frame/tail|update301")

    def test_barrier_ack_rejected(self) -> None:
        def mutate(d):
            frame = next(
                f for f in d["frames"] if f["connection"] == "burst" and f["id"] == 4000
            )
            frame["error"] = 1

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|direct success")

    def test_quiet_bracket_rejected(self) -> None:
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: next(
                a for a in d["actions"] if a["label"] == "paced-304-after-quiet"
            ).__setitem__("elapsed_ns", 10_000_000_000),
        )
        self.rejected("Action causal timestamp|host quiet bracket")

    def test_shifted_postquiet_action_times_rejected(self) -> None:
        def mutate(report):
            for action in report["actions"]:
                if action["label"] in {
                    "paced-304-after-quiet",
                    "paced-500-after-quiet",
                }:
                    action["elapsed_ns"] += 1_000_000_000

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Action causal timestamp differs")

    def test_shifted_icon27_frame_arrival_rejected(self) -> None:
        def mutate(report):
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "observer"
                and f["type"] == 301
                and {item["id"]: item["hex"] for item in f["fields"]}.get(103) == "0003"
                and {item["id"]: item["hex"] for item in f["fields"]}.get(104) == "001b"
            )
            frame["arrival_elapsed_ns"] -= 500_000_000

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Frame causal timestamp differs")

    def test_terminal_label_rejected(self) -> None:
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: d["terminals"].__setitem__("burst", "rst"),
        )
        self.rejected("Failed case status|Socket terminal")

    def test_probe_text_rejected(self) -> None:
        def mutate(d):
            frame = next(f for f in d["frames"] if f["connection"] == "probe")
            frame["fields"][0]["hex"] = (
                b"You are permanently banned on this server.".hex()
            )

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|temporary-ban")

    def test_final_303_target_rejected(self) -> None:
        def mutate(d):
            action = next(a for a in d["actions"] if a["label"] == "observer-303")
            action["hex"] = action["hex"][:-4] + "0001"

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("request schedule|Action/send|fieldless")

    def test_final_error_rejected(self) -> None:
        def mutate(d):
            frame = next(
                f
                for f in d["frames"]
                if f["connection"] == "observer" and f["id"] == 6004
            )
            frame["error"] = 0

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|Final303")

    def test_approved_closure_source_rejected(self) -> None:
        path = self.corpus / "raw/epoch/sources/native_rate304_control.py"
        path.write_bytes(path.read_bytes() + b"\n# forged\n")
        self.refresh()
        self.rejected("Frozen module|Approved source")

    def test_pcap_payload_rejected(self) -> None:
        path = self.corpus / "raw/epoch/lab-guest.pcap"
        value = path.read_bytes()
        self.assertIn(b"TRTPHOTL", value)
        path.write_bytes(value.replace(b"TRTPHOTL", b"TRTPH0TL", 1))
        self.refresh()
        self.rejected("PCAP/Recorder|Conflicting TCP retransmission")

    def test_missing_guest_flow_rejected(self) -> None:
        path = self.corpus / "raw/epoch/lab-guest.pcap"
        path.write_bytes(path.read_bytes()[:24])
        self.refresh()
        self.rejected("Capture packet inventory|Five SYN lifetimes")

    def test_primary_syn_rejected(self) -> None:
        path = self.corpus / "raw/epoch/primary-syn.pcap"
        path.write_bytes((self.corpus / "raw/epoch/lab-namespace.pcap").read_bytes())
        self.refresh()
        self.rejected("Capture packet inventory|Primary-port")

    def test_drop_counter_rejected(self) -> None:
        path = self.corpus / "raw/epoch/capture-journal-terminal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packet dropped by kernel", 1
            )
        )
        self.refresh()
        self.rejected("Capture drops/counts")

    def test_stopped_fixture_byte_rejected(self) -> None:
        path = self.corpus / "raw/epoch/stopped-icat-admin.stdout"
        data = bytearray(path.read_bytes())
        data[100] ^= 1
        path.write_bytes(data)
        self.refresh()
        self.rejected("Stopped admin fork")

    def test_forced_retirement_label_rejected(self) -> None:
        self.change_json(
            "raw/epoch/owned-pid-term.json",
            lambda d: d.__setitem__("action", "orderly OS shutdown"),
        )
        self.rejected("Forced retirement")

    def test_source_pin_extra_entry_rejected(self) -> None:
        path = self.corpus / "raw/preparation/approved-source-closure.sha256"
        path.write_text(path.read_text() + "0" * 64 + "  scripts/forged.py\n")
        self.refresh()
        self.rejected("Approved 35-module closure")


if __name__ == "__main__":
    unittest.main()
