"""Check folder direction/state distinctions and independent native fork state."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_folder_clock_checks import upload_clock
from native_folder_stream import Cursor, descriptor, download
from pcap_tcp import read_packets
from verify_native_folders import check_upload, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-folder-01"
)


class FolderTests(unittest.TestCase):
    def test_native_folder_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 17)
        full = next(c for c in result["cases"] if c["case"] == "folder-download-full")
        self.assertEqual(
            (full["aggregate_bytes"], full["file_stream_bytes"], full["item_count"]),
            (652, 1148, 5),
        )
        self.assertTrue(all(i["path"] for i in full["items"]))
        self.assertEqual(result["native_files"]["before"]["partial_resource_bytes"], 5)
        self.assertEqual(result["native_files"]["after"]["partial_resource_bytes"], 317)

    def test_final_file_does_not_inherit_directory_final_control(self) -> None:
        report = json.loads(
            (BATCH / "transcripts/folder-upload-fresh/report.json").read_text()
        )
        report["streams"]["folder"]["received_hex"] += "0003"
        with self.assertRaisesRegex(ValueError, "File-ending next-control differs"):
            check_upload(
                "folder-upload-fresh",
                report,
                {"folder": {"guest_server_initiated_close": True}},
            )

    def test_truncated_descriptor_and_file_body_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Truncated folder stream"):
            descriptor(Cursor(bytes.fromhex("ffff00000001000005616c706861")))
        report = json.loads(
            (BATCH / "transcripts/folder-download-full/report.json").read_text()
        )
        sent = bytes.fromhex(report["streams"]["folder"]["sent_hex"])
        received = bytes.fromhex(report["streams"]["folder"]["received_hex"])
        with self.assertRaisesRegex(ValueError, "Truncated folder stream"):
            download(sent, received[:-1])

    def test_resume_wire_success_requires_original_partial_native_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "fixtures"
            shutil.copytree(BATCH, directory)
            file = directory / "native-files/before/mothra-folder-partial__part.rsrc"
            file.write_bytes(file.read_bytes()[:-1])
            with self.assertRaisesRegex(ValueError, "Native folder MACR differs"):
                verify(directory)

    def test_declared_folder_delay_requires_measured_pause_evidence(self) -> None:
        case = BATCH / "transcripts/folder-upload-late-attachment"
        report = json.loads((case / "report.json").read_text())
        plan = json.loads((case / "plan.json").read_text())
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + 1
        with self.assertRaisesRegex(ValueError, "Shortened folder timing pause"):
            upload_clock(
                case.name, report, plan, read_packets(BATCH / "timers-guest.pcap")
            )


if __name__ == "__main__":
    unittest.main()
