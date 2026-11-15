"""Fault controls for the portable A37 delayed-121 corpus replay."""

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import verify_packets as corpus
from protocol_capture import verify_capture
from verify_native_121_default import semantic

ROOT = Path(__file__).resolve().parent


class Native121CorpusTests(unittest.TestCase):
    def test_portable_replay(self) -> None:
        result = corpus.verify(ROOT)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(len(result["gates"]), 27)
        self.assertEqual(result["tcp_connections"], 7)
        self.assertEqual(result["subjects"]["absent"]["uid_hex"], "0040")
        self.assertEqual(result["subjects"]["empty"]["uid_hex"], "0041")
        self.assertFalse(result["raw_snapshots_replayed"])

    def test_missing_default_104_is_not_a_pass(self) -> None:
        report = copy.deepcopy(verify_capture(ROOT / "observe"))
        plan = json.loads((ROOT / "observe/plan.json").read_text())
        case = plan["expectation"]["cases"][0]
        auto = next(
            frame for frame in report["frames"] if frame["action"] == case["first"] + 18
        )
        next(field for field in auto["fields"] if field["id"] == 101)["hex"] = (
            b"stale-default".hex()
        )
        with self.assertRaisesRegex(ValueError, "default text"):
            semantic(report, plan)

    def test_modified_tcp_stream_and_prefix_fail(self) -> None:
        reports = {
            name: verify_capture(ROOT / name)
            for name in ("preflight", "observe", "postflight")
        }
        wrong = copy.deepcopy(reports)
        sent = wrong["preflight"]["streams"]["a"]["sent_hex"]
        wrong["preflight"]["streams"]["a"]["sent_hex"] = "00" + sent[2:]
        with self.assertRaisesRegex(ValueError, "TCP input differs"):
            corpus.packet_views(ROOT, wrong)
        wrong = copy.deepcopy(reports)
        received = wrong["observe"]["streams"]["main"]["received_hex"]
        wrong["observe"]["streams"]["main"]["received_hex"] = "00" + received[2:]
        with self.assertRaisesRegex(ValueError, "TCP output prefix differs"):
            corpus.packet_views(ROOT, wrong)

    def test_corrupt_inventory_rejected(self) -> None:
        actual = corpus.digest
        with (
            patch.object(
                corpus,
                "digest",
                side_effect=lambda path: (
                    "0" * 64 if path.name == "host-seven-flows.pcap" else actual(path)
                ),
            ),
            self.assertRaisesRegex(ValueError, "Corpus hash differs"),
        ):
            corpus.inventory(ROOT)


if __name__ == "__main__":
    unittest.main()
