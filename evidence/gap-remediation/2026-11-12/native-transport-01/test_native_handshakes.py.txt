"""Require observed guest close packets and adequate quiet windows in fixtures."""

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from verify_native_handshakes import verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-transport-01"
)


class HandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "fixtures"
        shutil.copytree(BATCH, self.directory)

    def test_native_packets_and_socket_streams_agree(self) -> None:
        result = verify(self.directory)
        self.assertEqual(len(result["cases"]), 14)
        magic = next(c for c in result["cases"] if c["case"] == "wrong-magic")
        self.assertEqual(magic["guest_server_close_kind"], "RST")
        self.assertEqual(magic["received_bytes"], 0)

    def test_shortened_quiet_window_is_rejected(self) -> None:
        case = self.directory / "transcripts/segmented-11"
        plan = json.loads((case / "plan.json").read_text())
        next(s for s in plan["steps"] if s["op"] == "expect_quiet")["timeout"] = 0.01
        (case / "plan.json").write_text(json.dumps(plan))
        report = json.loads((case / "report.json").read_text())
        report["plan_sha256"] = hashlib.sha256(
            (case / "plan.json").read_bytes()
        ).hexdigest()
        (case / "report.json").write_text(json.dumps(report))
        (case / "checksums.sha256").write_text(
            "".join(
                f"{hashlib.sha256((case / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ["plan.json", "report.json"]
            )
        )
        with self.assertRaisesRegex(ValueError, "quiet observation too short"):
            verify(self.directory)

    def test_socket_eof_without_guest_close_evidence_is_rejected(self) -> None:
        report = json.loads(
            (self.directory / "transcripts/wrong-magic/report.json").read_text()
        )
        port = report["events"][0]["local_address"][1]
        path = self.directory / "guest.pcap"
        original = path.read_bytes()
        order = "<" if original[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        result, position = bytearray(original[:24]), 24
        while position < len(original):
            size = struct.unpack_from(order + "I", original, position + 8)[0]
            frame = original[position + 16 : position + 16 + size]
            omit = False
            if len(frame) >= 54 and frame[12:14] == b"\x08\x00" and frame[23] == 6:
                tcp = 14 + (frame[14] & 15) * 4
                omit = (
                    int.from_bytes(frame[tcp : tcp + 2], "big") == 5500
                    and int.from_bytes(frame[tcp + 2 : tcp + 4], "big") == port
                    and bool(frame[tcp + 13] & 5)
                )
            if not omit:
                result.extend(original[position : position + 16 + size])
            position += 16 + size
        path.write_bytes(result)
        with self.assertRaisesRegex(ValueError, "incomplete guest close"):
            verify(self.directory)


if __name__ == "__main__":
    unittest.main()
