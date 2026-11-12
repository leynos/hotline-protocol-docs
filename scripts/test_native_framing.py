"""Reject incomplete independent observations in the real native corpus."""

import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from verify_native_framing import check_quiet, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-framing-01"
)


class FramingTests(unittest.TestCase):
    def test_native_framing_matrix(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 62)
        icon = next(c for c in result["cases"] if c["case"] == "tlv-icon-8000")
        self.assertEqual(icon["emitted_icon_hex"], "ffff8000")

    def test_nominal_window_without_measured_silence_is_rejected(self) -> None:
        case = BATCH / "transcripts/fragment-basic"
        report = json.loads((case / "report.json").read_text())
        quiet = next(e for e in report["events"] if e["event"] == "quiet")
        previous = [e for e in report["events"] if e["action"] < quiet["action"]][-1]
        quiet["elapsed_ns"] = previous["elapsed_ns"] + 1
        plan = json.loads((case / "plan.json").read_text())
        with self.assertRaisesRegex(ValueError, "shorter than its plan"):
            check_quiet(report, plan)

    def test_socket_eof_requires_native_close_packets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            report = json.loads(
                (directory / "transcripts/data-zero/report.json").read_text()
            )
            port = report["events"][0]["local_address"][1]
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
                        int.from_bytes(frame[tcp : tcp + 2], "big") == 5500
                        and int.from_bytes(frame[tcp + 2 : tcp + 4], "big") == port
                        and bool(frame[tcp + 13] & 5)
                    )
                if not omit:
                    result.extend(raw[position : position + 16 + size])
                position += 16 + size
            path.write_bytes(result)
            with self.assertRaisesRegex(ValueError, "Guest did not initiate close"):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
