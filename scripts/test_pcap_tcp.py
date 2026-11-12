"""Check TCP observation analysis against an existing native packet corpus."""

import json
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets, stream

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-core-01"
)


class PacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packets = read_packets(BATCH / "loopback.pcap")
        syn = self.packets[0]
        self.client = (syn["src_ip"], syn["src_port"])
        self.server = (syn["dst_ip"], syn["dst_port"])

    def test_first_native_flow_matches_both_recorded_streams(self) -> None:
        report = json.loads((BATCH / "early-login-and-errors/report.json").read_text())
        expected = report["streams"]["main"]
        self.assertEqual(
            stream(self.packets, self.client, self.server).hex(), expected["sent_hex"]
        )
        self.assertEqual(
            stream(self.packets, self.server, self.client).hex(),
            expected["received_hex"],
        )

    def test_sequence_gap_is_rejected(self) -> None:
        packets = [dict(p) for p in self.packets]
        first = next(p for p in packets if p["payload_hex"])
        first["sequence"] += 1
        with self.assertRaisesRegex(ValueError, "sequence gap"):
            stream(packets, self.client, self.server)

    def test_conflicting_retransmission_is_rejected(self) -> None:
        duplicate = dict(next(p for p in self.packets if p["payload_hex"]))
        duplicate["payload_hex"] = "00" + duplicate["payload_hex"][2:]
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            stream(self.packets + [duplicate], self.client, self.server)

    def test_reset_diagnostics_do_not_become_application_bytes(self) -> None:
        original = stream(self.packets, self.server, self.client)
        reset = dict(next(p for p in self.packets if p["src_port"] == self.server[1]))
        reset.update(flags=4, payload_hex=b"tcp_disconnect".hex())
        self.assertEqual(
            stream(self.packets + [reset], self.server, self.client), original
        )
        self.assertEqual(bytes.fromhex(reset["payload_hex"]), b"tcp_disconnect")

    def test_truncated_packet_is_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cut.pcap"
            path.write_bytes((BATCH / "loopback.pcap").read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "Truncated"):
                read_packets(path)


if __name__ == "__main__":
    unittest.main()
