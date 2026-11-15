"""Check complete fork bytes and reject evidence that omits native outcomes."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_filp import decode, metadata
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from verify_native_forks import verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-forks-01"
)


class ForkTests(unittest.TestCase):
    def test_native_transfers_and_filesystem_forks(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 10)
        self.assertEqual(len(result["initial_eof_hypotheses"]), 8)
        raw = next(c for c in result["cases"] if c["case"] == "download-raw")
        self.assertEqual(raw["advertised_bytes"], 510)
        self.assertEqual(raw["metadata"]["flags"], "00000000")

    def test_truncated_resource_and_trailing_data_are_rejected(self) -> None:
        report = json.loads(
            (BATCH / "transcripts/download-raw/report.json").read_text()
        )
        data = bytes.fromhex(report["streams"]["download"]["received_hex"])
        for value in [data[:-1], data + b"extra"]:
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                decode(value)
        info = decode(data)["INFO"]
        with self.assertRaisesRegex(ValueError, "comment length"):
            metadata(info[:-1])

    def test_socket_prefix_cannot_silently_discard_unread_native_output(self) -> None:
        report = json.loads(
            (BATCH / "transcripts/download-empty/report.json").read_text()
        )
        with self.assertRaisesRegex(ValueError, "host output differs"):
            reconcile(
                report,
                read_packets(BATCH / "host.pcap"),
                read_packets(BATCH / "guest.pcap"),
            )

    def test_network_success_does_not_substitute_for_native_fork_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            resource = directory / "native-files/mothra-fork-fixture.rsrc"
            raw = bytearray(resource.read_bytes())
            raw[260] ^= 1
            resource.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "Native resource fork differs"):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
