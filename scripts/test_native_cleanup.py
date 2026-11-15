"""Require real native prefix, close, buffering and ownership observations."""

import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import direction, read_packets
from verify_native_cleanup import bytes_after, check_download, flow, reply, verify
from verify_native_queues import frame_time

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-cleanup-01"
)


class CleanupTests(unittest.TestCase):
    def test_native_cleanup_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 10)
        self.assertEqual(result["baseline_stream_bytes"], 1049073)
        partial = next(c for c in result["cases"] if c["case"] == "cleanup-partial-1")
        self.assertGreater(partial["application_bytes_read_after_owner_ack"], 1024)
        self.assertGreater(partial["guest_bytes_first_observed_after_owner_request"], 0)
        self.assertEqual(partial["guest_bytes_first_observed_after_owner_ack"], 0)

    def test_cancelled_bytes_must_match_baseline_prefix(self) -> None:
        case = BATCH / "transcripts/cleanup-partial-1"
        report = json.loads((case / "report.json").read_text())
        baseline = json.loads(
            (BATCH / "transcripts/cleanup-baseline/report.json").read_text()
        )
        raw = bytearray.fromhex(report["streams"]["reference"]["received_hex"])
        raw[200] ^= 1
        report["streams"]["reference"]["received_hex"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "not a baseline prefix"):
            check_download(
                report,
                {"variant": "partial-1", "prefix_size": 1024},
                bytes.fromhex(baseline["streams"]["reference"]["received_hex"]),
                {},
                [],
            )

    def test_retransmission_does_not_turn_old_bytes_into_late_delivery(self) -> None:
        report = json.loads(
            (BATCH / "transcripts/cleanup-partial-1/report.json").read_text()
        )
        guest = read_packets(BATCH / "guest.pcap")
        packets, client, server = flow(report, "reference", guest)
        ack = frame_time(report, reply(report, "a", 21), guest)
        packet = next(
            p
            for p in direction(packets, server, client)
            if p["payload_hex"] and not p["flags"] & 4
        )
        retransmission = {**packet, "timestamp_us": ack + 1000}
        count = len(bytes.fromhex(report["streams"]["reference"]["received_hex"]))
        self.assertEqual(
            bytes_after(packets + [retransmission], server, client, count, ack), 0
        )

    def test_successful_captures_do_not_replace_native_file_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            file = directory / "native-files/mothra-race-fixture.data"
            raw = bytearray(file.read_bytes())
            raw[0] ^= 1
            file.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "Native cleanup DATA differs"):
                verify(directory)

    def test_socket_eof_requires_native_close_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            report = json.loads(
                (directory / "transcripts/cleanup-partial-1/report.json").read_text()
            )
            port = next(
                e["local_address"][1]
                for e in report["events"]
                if e["event"] == "connect" and e["connection"] == "reference"
            )
            path = directory / "guest.pcap"
            raw = path.read_bytes()
            order = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
            result, position = bytearray(raw[:24]), 24
            while position < len(raw):
                size = struct.unpack_from(order + "I", raw, position + 8)[0]
                frame = raw[position + 16 : position + 16 + size]
                omit = False
                if len(frame) >= 54 and frame[12:14] == b"\x08\x00" and frame[23] == 6:
                    tcp = 14 + (frame[14] & 15) * 4
                    omit = (
                        int.from_bytes(frame[tcp : tcp + 2], "big") == 5501
                        and int.from_bytes(frame[tcp + 2 : tcp + 4], "big") == port
                        and bool(frame[tcp + 13] & 5)
                    )
                if not omit:
                    result.extend(raw[position : position + 16 + size])
                position += 16 + size
            path.write_bytes(result)
            with self.assertRaisesRegex(ValueError, "Missing native cleanup close"):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
