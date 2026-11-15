"""Require native packet, offset-range and independent filesystem evidence."""

import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from verify_native_resume import check_download, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-resume-01"
)


class ResumeTests(unittest.TestCase):
    def test_native_resume_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 23)
        repeated = next(
            c
            for c in result["cases"]
            if c["case"] == "resume-download-duplicate-data-3-4"
        )
        self.assertEqual(repeated["data_bytes"], 6)
        inconsistent = next(
            c
            for c in result["cases"]
            if c["case"] == "resume-upload-inconsistent-complete"
        )
        self.assertEqual(
            (inconsistent["data_bytes"], inconsistent["resource_bytes"]), (26, 322)
        )

    def test_shortened_invalid_rflt_window_is_rejected(self) -> None:
        case = BATCH / "transcripts/resume-download-short-41"
        report = json.loads((case / "report.json").read_text())
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + 1
        with self.assertRaisesRegex(ValueError, "Short invalid-input window"):
            check_download(case.name, report, {"kind": "resume-no-reply"}, {})

    def test_inconsistent_client_requires_actual_appended_native_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            file = directory / "native-files/after/mothra-resume-inconsistent.data"
            file.write_bytes(file.read_bytes()[:13])
            with self.assertRaisesRegex(ValueError, "Native resumed DATA differs"):
                verify(directory)

    def test_max_offset_close_requires_native_packet_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            report = json.loads(
                (
                    directory
                    / "transcripts/resume-download-both-uint32-max/report.json"
                ).read_text()
            )
            port = next(
                e["local_address"][1]
                for e in report["events"]
                if e["event"] == "connect" and e["connection"] == "download"
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
            with self.assertRaisesRegex(
                ValueError, "Missing native offset-error close"
            ):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
