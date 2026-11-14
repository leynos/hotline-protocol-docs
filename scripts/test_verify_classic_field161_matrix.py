"""Fault controls for the portable Classic field-161 corpus."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_classic_field161_matrix import check_case, check_readiness, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/classic-field161-01"
)


class ClassicField161MatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "classic-field161-01"
        shutil.copytree(CORPUS, self.base)
        self.manifest = json.loads((self.base / "manifest.json").read_text())

    def packets(self) -> dict:
        return {
            "pcaps/" + p.name: read_packets(p)
            for p in (self.base / "pcaps").glob("*.pcap")
        }

    def case(self, name: str = "one-byte-161") -> dict:
        return check_case(self.base, name, self.manifest["cases"][name], self.packets())

    def test_original_corpus_replays(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(
            set(result["cases"]), {"omit-161", "one-byte-161", "four-byte-161"}
        )
        self.assertTrue(result["capture"]["journals_zero_drops"])

    def test_wrong_forwarded_ack_guest_byte_rejected(self) -> None:
        p = self.base / "pcaps/client-guest-post.pcap"
        data = bytearray(p.read_bytes())
        report = json.loads((self.base / "one-byte-161/proxy/report.json").read_text())
        ack = bytes.fromhex(report["entries"][3]["forwarded_hex"])
        offset = data.find(ack)
        self.assertGreater(offset, 0)
        data[offset + len(ack) - 1] ^= 1
        p.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "downstream parity"):
            self.case()

    def test_missing_guest_record_rejected(self) -> None:
        p = self.base / "pcaps/client-guest-post.pcap"
        p.write_bytes(p.read_bytes()[:-5])
        with self.assertRaisesRegex(ValueError, "Truncated"):
            self.packets()

    def test_wrong_expected_161_ack_rejected(self) -> None:
        self.manifest["cases"]["one-byte-161"]["expected_ack_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source/forwarded ACK"):
            self.case()

    def test_kernel_drop_claim_rejected(self) -> None:
        p = self.base / "ns-recorder-journal.txt"
        p.write_text(
            p.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel"
            )
        )
        with self.assertRaisesRegex(ValueError, "capture drops"):
            check_readiness(self.base, self.manifest)

    def test_late_cutoff_rejected(self) -> None:
        p = self.base / "one-byte-161/proxy/report.json"
        report = json.loads(p.read_text())
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        p.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "cutoff timing"):
            self.case()

    def test_live_unit_claim_after_cleanup_rejected(self) -> None:
        p = self.base / "units-terminal.txt"
        p.write_text(p.read_text().replace("MainPID=0", "MainPID=42", 1))
        with self.assertRaisesRegex(ValueError, "unit cleanup"):
            check_readiness(self.base, self.manifest)


if __name__ == "__main__":
    unittest.main()
