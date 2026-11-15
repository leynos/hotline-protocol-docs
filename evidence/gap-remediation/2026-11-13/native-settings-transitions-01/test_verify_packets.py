"""Fault controls for the portable A33 corpus replay."""

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_packets as corpus
from protocol_capture import verify_capture
from verify_native_settings_transition import semantic

ROOT = Path(__file__).resolve().parent


class NativeSettingsCorpusTests(unittest.TestCase):
    def test_portable_replay(self) -> None:
        result = corpus.verify(ROOT)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["stages"]), 8)
        self.assertEqual(result["tcp_connections"], 6)
        self.assertFalse(result["raw_snapshots_replayed"])

    def test_missing_default_104_is_not_a_pass(self) -> None:
        report = copy.deepcopy(verify_capture(ROOT / "observe"))
        plan = json.loads((ROOT / "observe/plan.json").read_text())
        omitted = plan["expectation"]["windows"][1]
        report["frames"] = [
            frame
            for frame in report["frames"]
            if not (
                omitted["first"] <= frame["action"] <= omitted["last"]
                and frame["type"] == 104
                and frame["connection"] == "main"
            )
        ]
        with self.assertRaisesRegex(ValueError, "104 delivery/feedback"):
            semantic(report, plan)

    def test_modified_tcp_stream_and_tail_identity_fail(self) -> None:
        reports = {
            name: verify_capture(ROOT / name)
            for name in ("preflight", "observe", "postflight")
        }
        wrong = copy.deepcopy(reports)
        sent = wrong["preflight"]["streams"]["a"]["sent_hex"]
        wrong["preflight"]["streams"]["a"]["sent_hex"] = "00" + sent[2:]
        with self.assertRaisesRegex(ValueError, "TCP input differs"):
            corpus.packet_views(ROOT, wrong, b"\0\x32")
        with self.assertRaisesRegex(ValueError, "Subject departure tail differs"):
            corpus.packet_views(ROOT, reports, b"\0\x33")

    def test_corrupt_inventory_rejected(self) -> None:
        actual = corpus.digest
        with (
            patch.object(
                corpus,
                "digest",
                side_effect=lambda path: (
                    "0" * 64 if path.name == "host-six-flows.pcap" else actual(path)
                ),
            ),
            self.assertRaisesRegex(ValueError, "Corpus hash differs"),
        ):
            corpus.inventory(ROOT)


if __name__ == "__main__":
    unittest.main()
